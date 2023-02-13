#include "ft_nmap.h"

int	create_tcp_socket(void)
{
	int socket_fd;

	if ((socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) == -1)
		return (-1);
	nmap.socket_tcp = socket_fd;
	return (0);
}

int	create_udp_socket(void)
{
	int socket_fd;

	if ((socket_fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP)) == -1)
		return (-1);
	nmap.socket_udp = socket_fd;
	return (0);
}

void    send_packet(struct iphdr *ip_h)
{
    // a IP_HDRINCL call, to make sure that the kernel knows the header is included in the data, and doesn't insert its own header into the packet before our data 
    int         tmp;
    const int   *val;
	int			socket;

    tmp = 1;
    val = &tmp;
	if (nmap.current_scan_type == SCAN_UDP)
		socket = nmap.socket_udp;
	else
		socket = nmap.socket_tcp;
    setsockopt(socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (tmp));
    if (sendto(socket, nmap.datagram, ip_h->tot_len, 0, (struct sockaddr *)&nmap.targets->sockaddr, sizeof(nmap.targets->sockaddr)) < 0)
        fprintf(stderr, "%s", strerror(errno));
}

int		interpret_addr(char *input)
{
	char				*string_ip;
	struct addrinfo		*res;
	struct addrinfo		hints;
	struct sockaddr_in	sockaddr;	

	res = NULL;
	ft_memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	if (getaddrinfo(input, NULL, &hints, &res) != 0)
		return (ft_reterror("failure in name resolution", E_ERR));
	else
	{
		ft_memcpy(&sockaddr, res->ai_addr, sizeof(struct sockaddr_in));
		string_ip = inet_ntoa(sockaddr.sin_addr);
		ft_list_push_back(string_ip, res);
	}
	if (res)
		freeaddrinfo(res);
	return (E_OK);
}

int    get_network_interface(void)
{
    pcap_if_t       *interfaces;
    pcap_if_t       *tmp;
	pcap_addr_t 	*a;
    char            error[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */

    tmp = NULL;
	a = NULL;
    if (pcap_findalldevs(&interfaces, error) == -1)
        ft_reterror(error, E_ERR);
    if (interfaces)
    {
        tmp = interfaces;
        while (tmp)
        {
            if (tmp->flags & PCAP_IF_UP && tmp->flags & PCAP_IF_RUNNING && tmp->flags & PCAP_IF_CONNECTION_STATUS_CONNECTED)
            {
				a = tmp->addresses;
				while (a)
				{
					if (a->addr->sa_family == AF_INET)
					{
                    	nmap.string_src_ip = inet_ntoa(((struct sockaddr_in*)a->addr)->sin_addr);
						nmap.interface = ft_strdup(tmp->name);
						pcap_freealldevs(interfaces);
						return (E_OK);
					}
					a = a->next;
				}
            }
            tmp = tmp->next;
        }
        pcap_freealldevs(interfaces);
        return (E_OK);
    }
    return (E_ERR);
}