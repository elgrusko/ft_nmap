#include "../inc/ft_nmap.h"

extern t_nmap nmap;

unsigned short checksum(const char *buf, unsigned int size)
{
	unsigned sum = 0, i;
	for (i = 0; i < size - 1; i += 2)
	{
		unsigned short word16 = *(unsigned short *) &buf[i];
		sum += word16;
	}
	if (size & 1)
	{
		unsigned short word16 = (unsigned char) buf[i];
		sum += word16;
	}
	while (sum >> 16) sum = (sum & 0xFFFF)+(sum >> 16);
	return ~sum;
}

unsigned short tcp_checksum(struct iphdr *ip, struct tcphdr *tcp)
{
	struct pseudo_header
	{
		u_int32_t source_address;
		u_int32_t dest_address;
		u_int8_t placeholder;
		u_int8_t protocol;
		u_int16_t tcp_length;
	} psh;

	char ppacket[sizeof(struct pseudo_header) + sizeof(struct tcphdr)];

	psh.source_address = ip->saddr;
	psh.dest_address = ip->daddr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr));

	ft_memcpy(ppacket, (char*)&psh, sizeof(struct pseudo_header));
	ft_memcpy(ppacket+sizeof(struct pseudo_header),
		tcp, sizeof(struct tcphdr));

	return checksum(ppacket, sizeof(ppacket));
}

void	fill_ip_header(struct iphdr *ip_h)
{
    ip_h->version = 4;
	ip_h->ihl = sizeof(*ip_h) >> 2; // 5*4 = 20 bytes. This field is only 4 bits (half-byte)
	ip_h->tos = 0;
	ip_h->tot_len = sizeof(struct ip) + sizeof(struct tcphdr); // 20+20 = 40 bytes
	ip_h->id = htons(0); // we don't except to defragment/refragment packet
	ip_h->frag_off = 0;
	ip_h->ttl = 64;
	if (nmap.current_scan_type == SCAN_UDP)
		ip_h->protocol = IPPROTO_UDP;
	else
		ip_h->protocol = IPPROTO_TCP;
	ip_h->check = 0;
	inet_pton(AF_INET, nmap.string_src_ip, &ip_h->saddr);
	ft_memcpy(&ip_h->daddr, &nmap.targets->sockaddr.sin_addr, sizeof(ip_h->daddr));
}

void	fill_udp_header(struct udphdr *udp_h, u_int16_t src_port, u_int16_t dst_port)
{
	udp_h->source = htons(START_SRC_PORT + src_port);
	udp_h->dest = htons(dst_port);
	udp_h->len = htons(sizeof(struct udphdr));
	udp_h->check = 0;
}

void	fill_tcp_header(struct tcphdr *tcp_h, struct iphdr *ip_h, u_int16_t src_port, u_int16_t dst_port)
{
	tcp_h->source = htons(START_SRC_PORT + src_port);
	tcp_h->dest = htons(dst_port);
	tcp_h->seq = htonl(305414945); //0x1234
	tcp_h->ack_seq = htonl(0);
	tcp_h->doff = (sizeof(struct tcphdr) >> 2);
	tcp_h->fin = (nmap.flags & FLAG_FIN) ? 1 : 0;
	tcp_h->syn = (nmap.flags & FLAG_SYN) ? 1 : 0;
	tcp_h->rst = (nmap.flags & FLAG_RST) ? 1 : 0;
	tcp_h->psh = (nmap.flags & FLAG_PSH) ? 1 : 0;
	tcp_h->ack = (nmap.flags & FLAG_ACK) ? 1 : 0;
	tcp_h->urg = (nmap.flags & FLAG_URG) ? 1 : 0;
	tcp_h->window = htons(1024);
	tcp_h->check = 0;
	tcp_h->urg_ptr = 0;
	tcp_h->check = tcp_checksum(ip_h, tcp_h);
}