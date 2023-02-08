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
        nmap.current_scan_type = SCAN_ACK;
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