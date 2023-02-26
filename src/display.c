#include "ft_nmap.h"

char *get_service_name(int port, const char *protocol)
{
	struct servent *service = getservbyport(port, protocol);

	if (!service)
		return "Unassigned";
	return service->s_name;
}

char   *state_to_string(u_int8_t state)
{
    if (state & OPEN)
        return("\x1b[1;92mopen\x1b[0m");
    if (state & CLOSE)
        return("\x1b[1;91mclose\x1b[0m");
    if (state & FILTERED)
        return("\x1b[1;90mfiltered\x1b[0m");
    if (state & UNFILTERED)
        return("\x1b[1;90munfiltered\x1b[0m");
    if (state & OPENFILTERED)
        return("\x1b[1;90mopen|filtered\x1b[0m");
    return (NULL);
}

void    print_scans_type_res(t_ports *port)
{
    int    res = (port->state_res.syn_res | port->state_res.null_res | port->state_res.fin_res | port->state_res.xmas_res | port->state_res.ack_res | port->state_res.udp_res);

    if (!(res & ~(CLOSE)) || res & CLOSE)
        return ;

    printf("%d\t", port->dst_port);
    if (port->state_res.syn_res)
        printf("SYN(%s) ", state_to_string(port->state_res.syn_res));
    if (port->state_res.null_res)
        printf("NULL(%s) ", state_to_string(port->state_res.null_res));
    if (port->state_res.fin_res)
        printf("FIN(%s) ", state_to_string(port->state_res.fin_res));
    if (port->state_res.xmas_res)
        printf("XMAS(%s) ", state_to_string(port->state_res.xmas_res));
    if (port->state_res.ack_res)
        printf("ACK(%s) ", state_to_string(port->state_res.ack_res));
    if (port->state_res.udp_res)
        printf("UDP(%s) ", state_to_string(port->state_res.udp_res));

    if (nmap.current_scan_type == SCAN_UDP)
        printf("\t%s", get_service_name(port->dst_port, "udp"));
    else
        printf("\t%s", get_service_name(port->dst_port, "tcp"));

    printf("\n");
}

void    print_result(void)
{
    uint16_t        index = 0;

    printf("\nScan result for %s:\n", nmap.targets->string_ip);
    printf("\nPORT\t STATE\n");
    while (nmap.t_ports[index].dst_port != 0 && index < MAX_PORT)
    {
        print_scans_type_res(&nmap.t_ports[index]);
        index++;
    }
    printf("\n");
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
        printf("UDP ");
    printf("\n");
}