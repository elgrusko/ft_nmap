#include "ft_nmap.h"

int     file_to_targets(char *filename)
{
    FILE    *fd;
    char    buffer[256];

    fd = NULL;
    if (filename)
    {
        if (!(fd = fopen(filename, "r+")))
            return (ft_reterror(strerror(errno), E_ERR));
        while (fgets(buffer, sizeof(buffer), fd) != NULL)
        {
            buffer[strlen(buffer) - 1] = '\0'; // eat the newline fgets() stores
            if (interpret_addr(buffer) != E_OK)
                return (E_ERR);
        }
        fclose(fd);
    }
    return (E_OK);
}

int     parse_parameters(char **argv)
{
    uint16_t    index;

    index = 1;
    ft_memset(nmap.t_ports, 0, sizeof(nmap.t_ports));
    while (argv[index])
    {
        if (ft_strcmp("--help", argv[index]) == 0)
        {
            nmap.flags |= FLAG_HELP;
            return (E_OK);
        }
        else if (ft_strcmp("--ports", argv[index]) == 0)
        {
            if (!argv[index + 1] || parse_ports(argv, index + 1) != E_OK)
                return (E_ERR);
            index++;                            // skip values, just seek for keys
        }
        else if (ft_strcmp("--ip", argv[index]) == 0)
        {
            if (argv[index + 1] != NULL)
                if (interpret_addr(argv[index + 1]) != E_OK)
                    return (E_ERR);
            index++;
        }
        else if (ft_strcmp("--file", argv[index]) == 0)
        {
            if (argv[index + 1] != NULL)
                if (file_to_targets(argv[index + 1]) != E_OK)
                    return (E_ERR);
            index++;
        }
        else if (ft_strcmp("--scan", argv[index]) == 0)
        {
            if (argv[index + 1] == NULL || scan_to_flag(argv, index + 1) != E_OK)
                return ft_reterror("you have to select a correct scan, see --help", E_ERR);
            index++;
        }
        else if (ft_strcmp("--speedup", argv[index]) == 0)
        {
            if (argv[index + 1] != NULL)
                nmap.speedup = ft_atoi(argv[index + 1]);
            if (nmap.speedup < MIN_THREAD || nmap.speedup > MAX_THREAD)
                return ft_reterror("scan must be >= 0 and <= 250", E_ERR);
            index++;
        }
        else
            return (ft_reterror("bad option!", E_ERR));
        index++; 
    }
    if (nmap.t_ports[0].dst_port == 0)        // if no port has been specified by the user, then we scan 1-1024 ports
    {
        index = 0;
        while (index < MAX_PORT)
        {
            nmap.t_ports[index].dst_port = index + 1;
            index++;
        }
        nmap.string_ports = ft_strdup("1-1024"); // dont forget to free it
        nmap.remain_ports = get_total_ports();
    }
    if (nmap.scans == 0)                // if no scan has been specified by the user, then we'll use all scan types
        nmap.scans |= (SCAN_SYN | SCAN_NULL | SCAN_FIN | SCAN_XMAS | SCAN_ACK | SCAN_UDP);
    return (0);
}

// parsing ports given in param
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