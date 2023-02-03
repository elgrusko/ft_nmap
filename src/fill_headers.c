#include "../inc/ft_nmap.h"

extern t_nmap nmap;

unsigned short checksum(unsigned short *ptr,int nbytes) // chatGPT xd
{
    register long sum;
    unsigned short oddbyte;
    register short answer;
 
    sum = 0;
    while (nbytes > 1)
	{
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1)
	{
        oddbyte = 0;
        *((u_char*)&oddbyte) = *(u_char*)ptr;
        sum += oddbyte;
    }
    sum = (sum>>16) + (sum & 0xffff);
    sum = sum + (sum >> 16);
    answer = (short)~sum;
    return (answer);
}

void	fill_ip_header(struct ip *ip_h)
{
    ip_h->ip_v = 4;
	ip_h->ip_hl = sizeof(*ip_h) >> 2; // 5*4 = 20 bytes. This field is only 4 bits (half-byte)
	ip_h->ip_tos = 0;
	ip_h->ip_len = sizeof(struct ip) + sizeof(struct tcphdr); // 20+20 = 40 bytes
	ip_h->ip_id = htons(0); // we don't except to defragment/refragment packet
	ip_h->ip_off = 0;
	ip_h->ip_ttl = 64;
	ip_h->ip_p = IPPROTO_TCP;
	ip_h->ip_sum = 0;
	ip_h->ip_src.s_addr = inet_addr(nmap.string_src_ip);
	ip_h->ip_dst = nmap.targets->sockaddr.sin_addr;
	ip_h->ip_sum = checksum((unsigned short *)ip_h, sizeof(ip_h));
}

void	fill_tcp_header(struct tcphdr *tcp_h, u_int16_t src_port, u_int16_t dst_port)
{
	tcp_h->source = htons(START_SRC_PORT + src_port);
	tcp_h->dest = htons(dst_port);
	tcp_h->seq = htonl(1);
	tcp_h->ack_seq = htonl(1);
	tcp_h->doff = (sizeof(struct tcphdr) >> 2);
	tcp_h->fin = (nmap.flags & FLAG_FIN) ? 1 : 0;
	tcp_h->syn = (nmap.flags & FLAG_SYN) ? 1 : 0;
	tcp_h->rst = (nmap.flags & FLAG_RST) ? 1 : 0;
	tcp_h->psh = (nmap.flags & FLAG_PSH) ? 1 : 0;
	tcp_h->ack = (nmap.flags & FLAG_ACK) ? 1 : 0;
	tcp_h->urg = (nmap.flags & FLAG_URG) ? 1 : 0;
	tcp_h->window = htons(1024);
	tcp_h->check = checksum((unsigned short *)tcp_h, sizeof(tcp_h));
	tcp_h->urg_ptr = 0;
}