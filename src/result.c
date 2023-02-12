#include "ft_nmap.h"

uint16_t    get_total_ports(void)
{
    uint16_t total = 0;
    while (nmap.t_ports[total].dst_port != 0 && total < MAX_PORT)
        total++;
    return (total);
}

/*void     get_total_state_ports(t_ports_result *result)
{
    for (uint16_t index = 0; nmap.t_ports[index].dst_port != 0 && index < MAX_PORT; index++)
    {
        if (nmap.t_ports[index].scanned == E_SCANNED)
        {
            switch (nmap.t_ports[index].state)
            {
                case OPEN:
                    (result->open_ports)++;
                    break;
                case CLOSE:
                    (result->close_ports)++;
                    break;
                case FILTERED:
                    (result->filtered_ports)++;
                    break;
                case OPENFILTERED:
                    (result->openfiltered_ports)++;
                    break;
                case UNFILTERED:
                    (result->unfiltered_ports)++;
                    break;
            }
        }
    }
}*/