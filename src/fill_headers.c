#include "../inc/ft_nmap.h"

extern t_nmap nmap;

unsigned short csum(unsigned short *buf, int nwords)
{
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--)
        sum += *buf++;
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

void	fill_ip_header(struct ip *ip_h)
{
    ip_h->ip_v = 4;
	ip_h->ip_hl = 5; // 5*4 = 20 bytes. This field is only 4 bits (half-byte)
	ip_h->ip_tos = 0;
	ip_h->ip_len = sizeof(struct ip) + sizeof(struct tcphdr); // 20+20 = 40 bytes
	ip_h->ip_id = htons(0); // we don't except to defragment/refragment packet
	ip_h->ip_off = 0;
	ip_h->ip_ttl = 64;
	ip_h->ip_p = IPPROTO_TCP;
	ip_h->ip_sum = 0;
	ip_h->ip_src.s_addr = inet_addr(nmap.string_src_ip);
	ip_h->ip_dst = nmap.targets->sockaddr.sin_addr;
	ip_h->ip_sum = csum((u_short *)&nmap.ip_h, nmap.ip_h.ip_len >> 1);
}

void	fill_tcp_header(struct tcphdr *tcp_h, u_int16_t src_port, u_int16_t dst_port)
{
	tcp_h->source = htons(START_SRC_PORT + src_port);
	tcp_h->dest = htons(dst_port);
	tcp_h->seq = htonl(0);
	tcp_h->ack_seq = htonl(3980504321);
	tcp_h->doff = sizeof(struct tcphdr) / 4;
	tcp_h->fin = (nmap.flags & FLAG_FIN) ? 1 : 0;
	tcp_h->syn = (nmap.flags & FLAG_SYN) ? 1 : 0;
	tcp_h->rst = (nmap.flags & FLAG_RST) ? 1 : 0;
	tcp_h->psh = (nmap.flags & FLAG_PSH) ? 1 : 0;
	tcp_h->ack = (nmap.flags & FLAG_ACK) ? 1 : 0;
	tcp_h->urg = (nmap.flags & FLAG_URG) ? 1 : 0;
	tcp_h->window = htons(4096);
	tcp_h->check = csum((u_short *)&nmap.tcp_h, nmap.ip_h.ip_len >> 1);
	tcp_h->urg_ptr = 0;
}