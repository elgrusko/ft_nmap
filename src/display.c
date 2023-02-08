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

void    print_scans_type_res(uint16_t index)
{
    printf("%d\t", nmap.t_ports[index].dst_port);
    if (nmap.t_ports[index].state_res.syn_res)
        printf("SYN(%s) ", state_to_string(nmap.t_ports[index].state_res.syn_res));
    if (nmap.t_ports[index].state_res.null_res)
        printf("NULL(%s) ", state_to_string(nmap.t_ports[index].state_res.null_res));
    printf("\n");
}

void    print_result(void)
{
    uint16_t        index = 0;

    //get_total_state_ports(&nmap.result); // fonction to be updated since we use t_state struct
    printf("\nScan result:\n");
    printf("open: %d / close: %d / filtered: %d / open|filtered: %d / unfiltered %d\n", nmap.result.open_ports, nmap.result.close_ports, nmap.result.filtered_ports, nmap.result.openfiltered_ports, nmap.result.unfiltered_ports);
    //if (nmap.result.open_ports || nmap.result.close_ports || nmap.result.filtered_ports || nmap.result.openfiltered_ports || nmap.result.unfiltered_ports)
    //{
    printf("\nPORT\t STATE\n");
    while (nmap.t_ports[index].dst_port != 0 && index < MAX_PORT)
    {
        print_scans_type_res(index);
        index++;
    }
    //}
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