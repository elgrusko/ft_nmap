#include "ft_nmap.h"

void    update_ports_list_udp(struct icmphdr *icmp_h)
{
    uint16_t        port;
    uint16_t        index;
    struct udphdr   *udp_h;

    index = 0;
    udp_h = (struct udphdr*)((u_int8_t *)icmp_h + sizeof(struct icmphdr) + sizeof(struct iphdr));
    if (udp_h)
    {
        //print_memory(udp_h, sizeof(struct udphdr));
        port = swap_uint16(udp_h->dest);
        while (nmap.t_ports[index].dst_port != port && index < MAX_PORT)
            index++;
        if (icmp_h->type == 3 && icmp_h->code == 3)
            nmap.t_ports[index].state_res.udp_res |= CLOSE;
        else if (icmp_h->type == 3 && (icmp_h->code == 1 || icmp_h->code == 2 || icmp_h->code == 9 || icmp_h->code == 10 || icmp_h->code == 13))
            nmap.t_ports[index].state_res.udp_res |= FILTERED; // jamais eu l'occasion de tomber sur ce cas... (https://nmap.org/book/scan-methods-udp-scan.html)
    }

}

void    update_ports_list(struct tcphdr *tcp_h)
{
    uint16_t    port;
    uint16_t    index;

    index = 0;
    port = swap_uint16(tcp_h->source);
    while (nmap.t_ports[index].dst_port != port)
        index++;
    if (nmap.current_scan_type == SCAN_SYN)
    {
        if (tcp_h->syn && tcp_h->ack)
            nmap.t_ports[index].state_res.syn_res |= OPEN;
        else if (tcp_h->rst)
            nmap.t_ports[index].state_res.syn_res |= CLOSE;
    }
    else if (nmap.current_scan_type == SCAN_NULL || nmap.current_scan_type == SCAN_FIN || nmap.current_scan_type == SCAN_XMAS)
    {
        if (tcp_h->rst)
            nmap.t_ports[index].state_res.null_res |= CLOSE;
    }
    else if (nmap.current_scan_type == SCAN_ACK)
    {
        if (tcp_h->rst)
            nmap.t_ports[index].state_res.ack_res |= UNFILTERED;
    }
}

// check which ports doesnt get a response (in case of timeout, filtered etc.)
void    check_responseless_ports(void)
{
    uint16_t index;

    index = 0;
    while (nmap.t_ports[index].dst_port != 0)
    {
        if (nmap.current_scan_type == SCAN_SYN && nmap.t_ports[index].state_res.syn_res == NO_RESPONSE)
            nmap.t_ports[index].state_res.syn_res |= FILTERED;
        if (nmap.current_scan_type == SCAN_NULL && nmap.t_ports[index].state_res.null_res == NO_RESPONSE)
            nmap.t_ports[index].state_res.null_res |= OPENFILTERED;
        if (nmap.current_scan_type == SCAN_FIN && nmap.t_ports[index].state_res.fin_res == NO_RESPONSE)
            nmap.t_ports[index].state_res.fin_res |= OPENFILTERED;  
        if (nmap.current_scan_type == SCAN_XMAS && nmap.t_ports[index].state_res.xmas_res == NO_RESPONSE)
            nmap.t_ports[index].state_res.xmas_res |= OPENFILTERED;
        if (nmap.current_scan_type == SCAN_ACK && nmap.t_ports[index].state_res.ack_res == NO_RESPONSE)
            nmap.t_ports[index].state_res.ack_res |= FILTERED;
        if (nmap.current_scan_type == SCAN_UDP && nmap.t_ports[index].state_res.udp_res == NO_RESPONSE)
            nmap.t_ports[index].state_res.udp_res |= OPENFILTERED;    
        index++;
    }
}

// when many scans are given in param, then we have to "reset" ports states in our tab before new scan type starts
void    reset_ports(void)
{
    uint16_t index;

    index = 0;
    while (nmap.t_ports[index].dst_port != 0 && index < MAX_PORT)
    {
        nmap.t_ports[index].src_port = 0;
        nmap.t_ports[index].scanned = 0;
        ft_memset(&nmap.t_ports[index].state_res, 0, sizeof(t_state));
        index++;
    }
}

// to sync thread. each thread looks for a port which has not been already scanned
uint16_t    get_available_port(void)
{
    uint16_t index;

    index = 0;
    while (nmap.t_ports[index].dst_port != 0)
    {
        if (nmap.t_ports[index].scanned == E_NOT_SCANNED)
        {
            break;
        }
        index++;
    }
    nmap.t_ports[index].scanned = E_SCANNED;
    nmap.remain_ports--;
    return (index);
}