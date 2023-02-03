#include "../inc/ft_nmap.h"

extern t_nmap nmap;

void    nmap_to_pcap(char *nmap_ports, const char *host)
{
    int     offset;
    char    temp[1000]; // a changer aussi
    char    *token;

    offset = 0;
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
        offset = strlen(temp);
        token = strtok(NULL, ",");
    }
    if (offset)
    {
        sprintf(temp + offset - 4,")");
        temp[offset - 3] = '\0';
    }
    nmap.pcap_filter = malloc(sizeof(char) * (strlen(temp) + 1));
    strncpy(nmap.pcap_filter, temp, strlen(temp) + 1);
}

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

void   parse_range_ports(char *range)
{
    uint16_t    low_range;
    uint16_t    high_range;
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

int    parse_ports(char **argv, uint8_t index)
{
    char        **ports_list;
    uint16_t    tmp;

    ports_list = NULL;
    if (argv[index] != NULL)
    {
        nmap.string_ports = argv[index];
        if (strchr(argv[index], ','))       // if it's ports separared by comma
        {
            if ((ports_list = ft_split(argv[index], ',')))
                store_ports(ports_list);
        }
        else if (strchr(argv[index], '-'))
            parse_range_ports(argv[index]);
        else                               // only one port
        {
            tmp = (uint16_t)ft_atoi((const char *)argv[index]);
            if (tmp < MIN_PORT || tmp > MAX_PORT)
                ft_reterror("ports to scan must be somewhere between 1-1024", 1);
            else
                nmap.t_ports[0].dst_port = tmp;
        }
    nmap.remain_ports = get_total_ports();
    }
    return (0);
}