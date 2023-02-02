#include "../inc/ft_nmap.h"

t_nmap          nmap;
pthread_mutex_t mutex_global;

void    packet_handler(u_char *user_data, const struct pcap_pkthdr *pkt_header, const u_char *pkt_data)
{
    struct ip           *ip_h;
    struct tcphdr       *tcp_h;

    if (user_data && pkt_data && pkt_header)
        puts("");
    ip_h = (struct ip*)(pkt_data + 14); // skip 14 bytes for ethernet header
    tcp_h = (struct tcphdr*)((u_int8_t *)ip_h + (5 * sizeof(u_int32_t)));
    if (ip_h && tcp_h)
    {
        if (memcmp(&ip_h->ip_src.s_addr, &nmap.targets->sockaddr.sin_addr, 4) == 0)
        {
            update_ports_list(tcp_h);
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

pcap_t      *manage_filter(pcap_t *handle)
{
    char                errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program  filter;
    
    if (nmap.pcap_filter == NULL)
        nmap_to_pcap(nmap.string_ports, nmap.string_src_ip);
    if (pcap_compile(handle, &filter, nmap.pcap_filter, 0, PCAP_NETMASK_UNKNOWN) == -1)
        ft_exerror(errbuf, errno);
    if (pcap_setfilter(handle, &filter) == -1)
        ft_exerror(errbuf, errno);
    return (handle);
}

void    *scan_thread(void *arg)
{
    struct ip       *ip_h;
    struct tcphdr   *tcp_h;
    uint16_t        port_index;
    struct timeval  current_start_timestamp;
    
    if (arg)
        arg = arg;
    while (1)
    {
        pthread_mutex_lock(&mutex_global);
        if (nmap.remain_ports <= 0)
        {
            pthread_mutex_unlock(&mutex_global);
            return (NULL);
        }
        usleep(5000);
        port_index = get_available_port();
        pthread_mutex_unlock(&mutex_global);
        save_current_time(&current_start_timestamp);
        ip_h = (struct ip*)nmap.datagram;
        tcp_h = (struct tcphdr*)((u_int8_t *)ip_h + (5 * sizeof(u_int32_t)));
        fill_ip_header(ip_h);
        fill_tcp_header(tcp_h, port_index, nmap.t_ports[port_index].dst_port);
        send_packet(ip_h);
        nmap.t_ports[port_index].src_port = START_SRC_PORT + nmap.t_ports[port_index].dst_port;
        usleep(20000 * ((nmap.speedup / 2) + 1)); // arbitraire. a changer
        //wait_interval(current_start_timestamp, 1);
    }
    return (NULL);
}

void    run_tcp_scan(void)
{
    pcap_t                  *handle;
    char                    errbuf[PCAP_ERRBUF_SIZE];
    int                     index;
    struct timeval          begin;
    //struct timeval          end;

    index = 0;
    if (!(handle = pcap_open_live(nmap.interface, BUFSIZ, 1, 1000, errbuf)))
        ft_exerror(errbuf, errno);
    manage_filter(handle);
    pthread_mutex_init(&mutex_global, NULL);
    save_current_time(&begin);
    pthread_create(&nmap.capture_thread, NULL, capture_thread, handle);
    for (index = 0; index < nmap.speedup; index++)
        pthread_create(&nmap.main_threads[index], NULL, scan_thread, NULL);
    for (index = 0; index < nmap.speedup; index++)
        pthread_join(nmap.main_threads[index], NULL);
    if (nmap.speedup == 0)
        scan_thread(NULL);
    sleep(1);
    nmap.stop_capture = 1;  //ask capture thread to stop capturing
    //save_current_time(&end);
    pthread_mutex_destroy(&mutex_global);
    check_responseless_ports();
    pcap_close(handle);
    print_result();
    //display_request_time(begin, end);
}

int     main(int argc, char **argv)
{
    if (getuid() != 0)
        return (ft_reterror("you must be root to use ft_nmap", 1));
    else if (argc < 2 || parse_parameters(argv) != 0)
        return (ft_reterror(USAGE, 2));
    else if (nmap.flags & FLAG_HELP)
        return (ft_reterror(HELP, 0));
    if (create_socket() != 0)
        return (ft_reterror(strerror(errno), errno));
    if (get_network_interface() != 0)
        return (ft_reterror("no available interface found", 3));
    display_scan_config();
    while (nmap.targets)
    {
        while (nmap.scans)
        {
            set_correct_flags();
            run_tcp_scan();
            nmap.remain_ports = get_total_ports();
            reset_ports();
            nmap.targets = nmap.targets->next;
        }
    }
    return (0);
}