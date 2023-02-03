#include "../inc/ft_nmap.h"

extern t_nmap nmap;

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
            nmap.t_ports[index].state |= OPEN;
        else if (tcp_h->rst)
            nmap.t_ports[index].state |= CLOSE;
    }
    if (nmap.current_scan_type == SCAN_NULL || nmap.current_scan_type == SCAN_FIN)
    {
        if (tcp_h->rst)
            nmap.t_ports[index].state |= CLOSE;
    }
}

// check which ports doesnt get a response (in case of timeout, filtered etc.)
void    check_responseless_ports(void)
{
    uint16_t index;

    index = 0;
    while (nmap.t_ports[index].dst_port != 0)
    {
        if (nmap.t_ports[index].state == NO_RESPONSE)
        {
            if (nmap.current_scan_type == SCAN_SYN)
                nmap.t_ports[index].state |= FILTERED;
            else if (nmap.current_scan_type == SCAN_NULL || nmap.current_scan_type == SCAN_FIN || nmap.current_scan_type == SCAN_XMAS)
                nmap.t_ports[index].state |= OPENFILTERED;
        }
        index++;
    }
}

// when many scans are given in param, then we have to "reset" ports state before new scan type starts
void    reset_ports(void)
{
    uint16_t index;

    index = 0;
    while (nmap.t_ports[index].dst_port != 0)
    {
        nmap.t_ports[index].src_port = 0;
        nmap.t_ports[index].scanned = 0;
        nmap.t_ports[index].state = 0;
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