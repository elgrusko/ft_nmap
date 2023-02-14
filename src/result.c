#include "ft_nmap.h"

uint16_t    get_total_ports(void)
{
    uint16_t total = 0;
    while (nmap.t_ports[total].dst_port != 0 && total < MAX_PORT)
        total++;
    return (total);
}