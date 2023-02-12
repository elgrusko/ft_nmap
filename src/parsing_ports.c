#include "ft_nmap.h"

// arbitrary code given by chatgpt (dangerous code)
// lol
void    nmap_to_pcap(char *nmap_ports, const char *host)
{
    int     offset;
    char    temp[1000]; // a changer aussi
    char    *token;

    offset = 0;
    // TODO remove strtok (forbidden function)
    token = strtok(nmap_ports, ",");
    sprintf(temp, "host %s and (tcp ", host);
    offset = strlen(temp);
    while (token != NULL)
    {
        char *range = strchr(token, '-');
        if (range)
        {
            *range = '\0';
            sprintf(temp + offset,"portrange %s-%s or ", token, range + 1);
        }
        else
            sprintf(temp + offset,"port %s or ", token);
        offset = ft_strlen(temp);
        token = strtok(NULL, ",");
    }
    if (offset)
    {
        sprintf(temp + offset - 4,")");
        temp[offset - 3] = '\0';
    }
    nmap.pcap_filter = malloc(sizeof(char) * (ft_strlen(temp) + 1));
    strncpy(nmap.pcap_filter, temp, ft_strlen(temp) + 1);
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
            if (strchr(ports_list[index], '-')) // if it's a range
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