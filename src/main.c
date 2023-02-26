#include "ft_nmap.h"
/*
Todo:

-afficher temps ecoule pendant le scan
-parser 
*/
t_nmap          nmap;
pthread_mutex_t mutex_global;

int     expected_port(uint16_t port)
{
    uint16_t index;

    index = 0;
    while (nmap.t_ports[index].dst_port != 0 && index < MAX_PORT)
    {
        if (nmap.t_ports[index].dst_port == port)
            return (E_OK);
        index++;
    }
    return (E_ERR);
}

void    packet_handler(u_char *user_data, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
    struct iphdr        *ip_h;
    struct tcphdr       *tcp_h;
    struct icmphdr      *icmp_h;
    struct udphdr       *udp_h;
    uint16_t            port;
    uint16_t            index;

    (void)user_data;
    (void)pkt_header;
    (void)pkt_data;
    udp_h = NULL;
    index = 0;
    port = 0;
    ip_h = (struct iphdr*)(pkt_data + 14); // skip 14 bytes for ethernet header
    if (ip_h && ip_h->protocol == IPPROTO_TCP)
    {
        tcp_h = (struct tcphdr*)((u_int8_t *)ip_h + (5 * sizeof(u_int32_t)));
        // check if src ip match with our target ip, and check if src port is < 42000 (then, we may be sure that is not our own packet)
        if (swap_uint16(tcp_h->source) < START_SRC_PORT && memcmp(&ip_h->saddr, &nmap.targets->sockaddr.sin_addr, 4) == 0)
            update_ports_list(tcp_h);
    }
    else if (ip_h && ip_h->protocol == IPPROTO_ICMP)
    {
        icmp_h = (struct icmphdr*)((u_int8_t *)ip_h + 20);
        if (icmp_h->type == 3 && icmp_h->code == 3)
           update_ports_list_udp(icmp_h);
    }
    else if (ip_h && ip_h->protocol == IPPROTO_UDP)
    {
        udp_h = (struct udphdr*)((u_int8_t *)ip_h + sizeof(struct iphdr));
        if (udp_h) // j'ai jamais eu l'occasion de tomber sur ce cas
        {
            port = swap_uint16(udp_h->source);
            if (expected_port(port) == E_OK)
            {
                while (nmap.t_ports[index].dst_port != port && index < MAX_PORT)
                    index++;
                nmap.t_ports[index].state_res.udp_res |= OPEN;
            }
            
        }
    }
}

void *capture_thread(void *arg)
{
    pcap_t *handle;
    
    handle = (pcap_t *)arg;
    while (1)
    {
        pcap_dispatch(handle, -1, packet_handler, NULL);
        if (nmap.stop_capture)
            break;
    }
    return (NULL);
}

void    *scan_thread(void *arg)
{
    struct iphdr    *ip_h;
    struct tcphdr   *tcp_h;
    struct udphdr   *udp_h;
    uint16_t        port_index;
    
    (void)arg;
    while (1)
    {
        pthread_mutex_lock(&mutex_global);
        if (nmap.remain_ports <= 0)
        {
            pthread_mutex_unlock(&mutex_global);
            return (NULL);
        }
        wait_microseconds(6000);
        port_index = get_available_port();
        pthread_mutex_unlock(&mutex_global);
        ip_h = (struct iphdr*)nmap.datagram;
        fill_ip_header(ip_h);
        if (nmap.current_scan_type == SCAN_UDP)
        {
            udp_h = (struct udphdr*)((u_int8_t *)ip_h + (5 * sizeof(u_int32_t)));
            fill_udp_header(udp_h, port_index, nmap.t_ports[port_index].dst_port);
        }
        else
        {
            tcp_h = (struct tcphdr*)((u_int8_t *)ip_h + (5 * sizeof(u_int32_t)));
            fill_tcp_header(tcp_h, ip_h, port_index, nmap.t_ports[port_index].dst_port);
        }
        send_packet(ip_h);
        nmap.t_ports[port_index].src_port = START_SRC_PORT + nmap.t_ports[port_index].dst_port;
        if (nmap.current_scan_type == SCAN_UDP)
            wait_seconds(1);
    }
    return (NULL);
}

void    apply_filters(pcap_t *handle, pcap_t *handle_localhost)
{
    char     errbuf[PCAP_ERRBUF_SIZE];

    if (nmap.current_scan_type != SCAN_UDP)
    {
        if (nmap.pcap_filter == NULL)
            nmap_to_pcap(nmap.string_ports, nmap.string_src_ip);
        if (pcap_compile(handle, &nmap.filter_tcp, nmap.pcap_filter, 0, PCAP_NETMASK_UNKNOWN) == -1)
            ft_exerror(errbuf, errno);
        if (pcap_setfilter(handle, &nmap.filter_tcp) == -1)
            ft_exerror(errbuf, errno);
        if (handle_localhost != NULL)
            if (pcap_setfilter(handle_localhost, &nmap.filter_tcp) == -1) // apply same filters than with the "main" interface
                ft_exerror(errbuf, errno);
    }
    else // voir si peut faire un truc plus propre ? 
    {
        if (pcap_compile(handle, &nmap.filter_udp, "host 192.168.1.30 and (udp or icmp)", 0, PCAP_NETMASK_UNKNOWN) == -1)
            ft_exerror(errbuf, errno);
        if (pcap_setfilter(handle, &nmap.filter_udp) == -1)
            ft_exerror(errbuf, errno);
        if (handle_localhost != NULL)
            if (pcap_setfilter(handle_localhost, &nmap.filter_udp) == -1) // apply same filters than with the "main" interface
                ft_exerror(errbuf, errno);
    }
}

void    run_scan(void)
{
    int             index;
    struct timeval  current_start_timestamp;

    index = 0;
    pthread_mutex_init(&mutex_global, NULL);
    for (index = 0; index < nmap.speedup; index++)
        pthread_create(&nmap.main_threads[index], NULL, scan_thread, NULL);
    for (index = 0; index < nmap.speedup; index++)
        pthread_join(nmap.main_threads[index], NULL);
    if (nmap.speedup == 0)
        scan_thread(NULL);
    save_current_time(&current_start_timestamp);
    wait_seconds(2);
    pthread_mutex_destroy(&mutex_global);
    check_responseless_ports();
    print_result();
}

int     main(int argc, char **argv)
{
    uint8_t                 tmp_scans;
    pcap_t                  *handle;
    pcap_t                  *handle_localhost;
    uint8_t                 localhost[4] = {127, 0, 0, 1};
    char                    errbuf[PCAP_ERRBUF_SIZE];

    handle = NULL;
    handle_localhost = NULL;
    tmp_scans = 0;
    if (getuid() != 0)
        return (ft_reterror("you must be root to use ft_nmap", 1));
    if (argc < 2 || parse_parameters(argv) != 0)
        return (ft_reterror(USAGE, 2));
    if (nmap.flags & FLAG_HELP)
        return (ft_reterror(HELP, 0));
    if (create_tcp_socket() < 0 || create_udp_socket() < 0)
        return (ft_reterror(strerror(errno), errno));
    if (get_network_interface() != 0)
        return (ft_reterror("no available interface found", 3));
    if (!nmap.targets)
        return (ft_reterror("no target. please check --help", 4));
    tmp_scans = nmap.scans;
    if (!(handle = pcap_open_live(nmap.interface, BUFSIZ, 1, 1000, errbuf)))
        ft_exerror(errbuf, errno);
    pthread_create(&nmap.capture_thread, NULL, capture_thread, handle);
    while (nmap.targets)
    {
        save_current_time(&nmap.starting_time);
        if (memcmp(&nmap.targets->sockaddr.sin_addr, &localhost, 4) == 0) // je retrouve pas mon ft_memcmp
        {
            if (!(handle_localhost = pcap_open_live(nmap.interface_localhost, BUFSIZ, 1, 1000, errbuf))) // pour l'instant "lo" est en dur mais je vais utiliser pcap_findalldevs() apres
                ft_exerror(errbuf, errno);
            pthread_create(&nmap.capture_thread, NULL, capture_thread, handle_localhost);
        }
        display_scan_config();
        while (nmap.scans)
        {
            set_correct_flags();
            apply_filters(handle, handle_localhost);
            run_scan();
            nmap.remain_ports = get_total_ports();
            reset_ports();
        }
        save_current_time(&nmap.ending_time);
        display_total_time();
        nmap.scans = tmp_scans;
        // get the next target and free the current one
        t_target *next_target = nmap.targets->next;
        free(nmap.targets->string_ip);
        free(nmap.targets);
        nmap.targets = next_target;
        if (handle_localhost)
            pcap_close(handle_localhost); // peut-etre remettre a NULL ensuite ? 
    }
    nmap.stop_capture = 1;
    pcap_close(handle);
    return (0);
}
