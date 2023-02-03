#include "../inc/ft_nmap.h"

extern t_nmap nmap;

void    set_correct_flags(void)
{
    //print_bits(nmap.scans);
    nmap.flags = 0b00000000;

    if (nmap.scans & SCAN_SYN)
    {
        nmap.flags |= FLAG_SYN;
        nmap.scans ^= SCAN_SYN;
        nmap.current_scan_type = SCAN_SYN;
    }
    else if (nmap.scans & SCAN_NULL)
    {
        nmap.flags |= 0b00000000;
        nmap.scans ^= SCAN_NULL;
        nmap.current_scan_type = SCAN_NULL; // nmap.current_scan_type is for display result function
    }
    else if (nmap.scans & SCAN_FIN)
    {
        nmap.flags |= FLAG_FIN;
        nmap.scans ^= SCAN_FIN;
        nmap.current_scan_type = SCAN_FIN;
    }
    else if (nmap.scans & SCAN_XMAS)
    {
        nmap.flags |= (FLAG_FIN | FLAG_PSH | FLAG_URG);
        nmap.scans ^= SCAN_XMAS;
        nmap.current_scan_type = SCAN_XMAS;
    }
    else if (nmap.scans & SCAN_ACK)
    {
        nmap.flags |= FLAG_ACK;
        nmap.scans ^= SCAN_ACK;
        nmap.current_scan_type = SCAN_XMAS;
    }
    else if (nmap.scans & SCAN_UDP)
    {
        nmap.flags |= 0b00000000;
        nmap.scans ^= SCAN_UDP;
        nmap.current_scan_type = SCAN_UDP;
    }
    //print_bits(nmap.scans);
}

int    scan_to_flag(char **argv, uint8_t index)
{
    char        **split;
    uint8_t     i;

    split = NULL;
    i = 0;
    if (argv[index] != NULL)
    {
        if (!(split = ft_split(argv[index], '/')))
            return (E_ERR);
        while (split[i])
        {
            if (ft_strcmp("SYN", split[i]) == 0)
                nmap.scans |= SCAN_SYN;
            else if (ft_strcmp("NULL", split[i]) == 0)
                nmap.scans |= SCAN_NULL;
            else if (ft_strcmp("FIN", split[i]) == 0)
                nmap.scans |= SCAN_FIN;
            else if (ft_strcmp("XMAS", split[i]) == 0)
                nmap.scans |= SCAN_XMAS;
            else if (ft_strcmp("ACK", split[i]) == 0)
                nmap.scans |= SCAN_ACK;
            else if (ft_strcmp("UDP", split[i]) == 0)
                nmap.scans |= SCAN_UDP;
            else
            {
                ft_split_free(split);
                return (E_ERR);
            }
            i++;
        }
        ft_split_free(split);
        if (nmap.scans == 0)
            return (E_ERR);
        return (E_OK);
    }
    return (E_ERR);
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
                if (interpret_addr(argv[index + 1]) != 0)
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