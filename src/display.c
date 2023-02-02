#include "../inc/ft_nmap.h"

extern t_nmap nmap;

char   *state_to_string(u_int8_t state)
{
    if (state & OPEN)
        return("open");
    if (state & CLOSE)
        return("close");
    if (state & FILTERED)
        return("filtered");
    if (state & UNFILTERED)
        return("unfiltered");
    if (state & OPENFILTERED)
        return("open|filtered");
    return (NULL);
}

void    print_result(void)
{
    uint16_t    index = 0;
    t_ports_result  result;

    get_total_state_ports(&result);
    printf("\nScan result:\n");
    if (nmap.current_scan_type == SCAN_SYN)
        printf("open : %d / close : %d / filtered : %d\n", result.open_ports, result.close_ports, result.filtered_ports);
    else if (nmap.current_scan_type == SCAN_NULL || nmap.current_scan_type == SCAN_FIN || nmap.current_scan_type == SCAN_XMAS)
        printf("filtered : %d / close : %d / open|filtered : %d\n", result.open_ports, result.close_ports, result.openfiltered_ports);
    if (result.open_ports || result.close_ports || result.filtered_ports || result.openfiltered_ports || result.unfiltered_ports)
    {
        printf("\nPORT\t STATE\n");
        while (nmap.t_ports[index].dst_port != 0 && index < MAX_PORT)
        {
            if ((nmap.t_ports[index].state == CLOSE && result.close_ports > 30) || (nmap.t_ports[index].state == OPENFILTERED && result.openfiltered_ports > 30))
                ;
            else
                printf("%d\t%s\n", nmap.t_ports[index].dst_port, state_to_string(nmap.t_ports[index].state));
            index++;
        }
    }
}

void    display_scan_config(void)
{
    printf("Scan configuration: \n");
    printf("  Target    : %s\n", nmap.targets->string_ip);
    printf("  Ports     : %s\n", nmap.string_ports);
    printf("  Interface : %s (%s)\n", nmap.interface, nmap.string_src_ip);
    printf("  Speed     : %d (threads)\n", nmap.speedup);
    printf("  Scans     : ");
    if (nmap.scans & SCAN_SYN)
        printf("SYN ");
    if (nmap.scans & SCAN_NULL)
        printf("NULL ");
    if (nmap.scans & SCAN_FIN)
        printf("FIN ");
    if (nmap.scans & SCAN_XMAS)
        printf("XMAS ");
    if (nmap.scans & SCAN_ACK)
        printf("ACK ");
    if (nmap.scans & SCAN_UDP)
        printf("SYN ");
    printf("\n");
}