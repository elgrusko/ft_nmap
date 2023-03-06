#include "ft_nmap.h"

// 0-1,3-7,6 => portrange 0-1 or portrange 3-7 or port 6
void    nmap_to_pcap(char *nmap_ports, const char *host, uint8_t current_scan_type)
{
    nmap.pcap_filter = ft_strdup("host ");
    ft_add_str(&nmap.pcap_filter, host);
    if (current_scan_type != SCAN_UDP)
        ft_add_str(&nmap.pcap_filter, " and (tcp ");
    else
        ft_add_str(&nmap.pcap_filter, " and icmp or (udp ");
    while (*nmap_ports) {
        char *end = ft_find(nmap_ports, ',');

        if (*end) {
            *end = '\0';
            end++;
        }

        if (*ft_find(nmap_ports, '-'))
            ft_add_str(&nmap.pcap_filter, "portrange ");
        else
            ft_add_str(&nmap.pcap_filter, "port ");
        ft_add_str(&nmap.pcap_filter, nmap_ports);
        if (*end)
            ft_add_str(&nmap.pcap_filter, " or ");

        nmap_ports = end;
    }
    ft_add_str(&nmap.pcap_filter, ")");
}

// parsing ports given in param
void   store_ports(char **ports_list)
{
    uint16_t    index;
    uint16_t    tmp;
    uint16_t    index_ports_tab;

    index_ports_tab = 0;
    index = 0;
    if (ports_list)
    {
        while (ports_list[index])
        {
            if (*ft_find(ports_list[index], '-')) // if it's a range
                parse_range_ports(ports_list[index]);
            else
            {   
                while (nmap.t_ports[index_ports_tab].dst_port != 0) // skip slots already use
                    index_ports_tab++;
                tmp = ft_atoi(ports_list[index]);
                if (tmp >= MIN_PORT && tmp <= MAX_PORT)
                {
                    if (!is_in_array(tmp))
                    {
                        nmap.t_ports[index_ports_tab].dst_port = tmp;
                        index_ports_tab++;
                    }
                }
            }
            index++;
        }
    }
}

// parsing ports given in param
void   parse_range_ports(char *range)
{
    uint16_t    low_range = 0;
    uint16_t    high_range = 0;
    uint16_t    index_ports_tab;
    char        **split;

    index_ports_tab = 0;
    split = ft_split(range, '-');
    if (split[0] && split[1])
    {
        low_range = ft_atoi(split[0]);
        high_range = ft_atoi(split[1]);
    }
    if (low_range >= MIN_PORT && low_range <= MAX_PORT && low_range < high_range && high_range >= MIN_PORT && high_range <= MAX_PORT)
    {
        while (nmap.t_ports[index_ports_tab].dst_port != 0) // skip slots already use
            index_ports_tab++;
        while (low_range <= high_range)
        {
            if (!is_in_array(low_range))
            {
                nmap.t_ports[index_ports_tab].dst_port = low_range;
                index_ports_tab++;
            }
            low_range++;
        }
    }
    ft_split_free(split);
}