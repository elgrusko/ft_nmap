# ifndef FT_NMAP
# define FT_NMAP

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <pcap.h>
#include <poll.h>
#include <errno.h>

#define USAGE "./ft_nmap [--help] [--ports [NUMBER/RANGED]] --file FILE [--speedup [NUMBER]] [--scan [TYPE]]"
#define MAX_PACKET_SIZE 4096

#define HELP    "Help Screen \n\
ft_nmap [OPTIONS] \n\
 --help Print this help screen \n\
 --ports ports to scan (eg: 1-10 or 1,2,3 or 1,5-15) \n\
 --ip ip addresses to scan in dot format \n\
 --file File name containing IP addresses to scan, \n\
 --speedup [250 max] number of parallel threads to use\n\
 --scan SYN/NULL/FIN/XMAS/ACK/UDP"

#define SCAN_SYN  0b00000001
#define SCAN_NULL 0b00000010
#define SCAN_FIN  0b00000100
#define SCAN_XMAS 0b00001000
#define SCAN_ACK  0b00010000
#define SCAN_UDP  0b00100000

#define FLAG_FIN  0b00000001
#define FLAG_SYN  0b00000010
#define FLAG_RST  0b00000100
#define FLAG_PSH  0b00001000
#define FLAG_ACK  0b00010000
#define FLAG_URG  0b00100000
#define FLAG_HELP 0b10000000

#define NO_RESPONSE     0b00000000
#define OPEN            0b00000001
#define CLOSE           0b00000010
#define FILTERED        0b00000100
#define UNFILTERED      0b00001000
#define OPENFILTERED    0b00010000

#define MIN_PORT        1
#define MAX_PORT        1024
#define MIN_THREAD      0
#define MAX_THREAD      250
#define MAX_PACKET_SIZE 4096
#define START_SRC_PORT  42000

enum errors {E_OK, E_ERR};
enum scanned {E_NOT_SCANNED, E_SCANNED};
enum scan_types {SYN, NUL, ACK, FIN, XMAS, UDP};

// each scan result for each port
typedef struct              s_state
{
    uint8_t                 syn_res;
    uint8_t                 null_res;
    uint8_t                 fin_res;
    uint8_t                 xmas_res;
    uint8_t                 ack_res;
    uint8_t                 udp_res;
}                           t_state;

typedef struct              s_ports
{
    uint16_t                src_port;
    uint16_t                dst_port;
    uint8_t                 scanned; // is the port already been scanned ? (to sync threads)
    t_state                 state_res;
}                           t_ports;

typedef struct              s_target
{
    char                    *string_ip;
    struct sockaddr_in      sockaddr;
    struct s_target         *next;
}                           t_target;

typedef struct              s_nmap
{
    int                     speedup;        // 0 to 250 (threads)
    uint8_t                 flags;
    int                     socket_tcp;
    int                     socket_udp;
    uint8_t                 current_scan_type;
    t_ports                 t_ports[MAX_PORT];
    uint16_t                remain_ports;
    pthread_t               main_threads[MAX_THREAD];
    t_target                *targets;
    pthread_t               capture_thread;
    uint8_t                 stop_capture;
    char                    *string_src_ip;
    char                    *string_ports;  // to display them properly in display_scan_config()
    char                    *pcap_filter;
    uint8_t                 scans;
    uint8_t                 datagram[MAX_PACKET_SIZE];
    struct ip               ip_h;
    struct tcphdr           tcp_h;
    char                    *interface;
    char                    *interface_localhost;
    struct timeval			starting_time;
	struct timeval			ending_time;
    struct bpf_program		filter;
}                           t_nmap;

extern t_nmap nmap;

//time
void	    wait_interval(struct timeval start, long interval);
double	    calcul_request_time(struct timeval start, struct timeval end);
void        save_current_time(struct timeval *destination);
void	    display_request_time(struct timeval start, struct timeval end);

//configure networking
int         create_tcp_socket(void);
int         create_udp_socket(void);
void	    fill_udp_header(struct udphdr *udp_h, u_int16_t src_port, u_int16_t dst_port);
void	    fill_ip_header(struct iphdr *ip_h);
void	    fill_tcp_header(struct tcphdr *tcp_h, struct iphdr *ip_h, u_int16_t src_port, u_int16_t dst_port);
int         interpret_addr(char *input);
int         get_network_interface(void);
void        send_packet(struct iphdr *ip_h);

//display
void        print_result(void);
void        display_ports(void);
void        display_scan_config(void);
void        print_memory(void *memory, int size);

// parameters parsing
void        nmap_to_pcap(char *nmap_ports, const char *host);
int         scan_to_flag(char **argv, uint8_t index);
void        store_ports(char **ports_list);
void        parse_range_ports(char *range);
int         parse_parameters(char **argv);
int         parse_ports(char **argv, uint8_t index);
void        reset_ports(void);
void        check_responseless_ports(void);
uint16_t    get_available_port(void);
void        update_ports_list(struct tcphdr *tcp_h);
void        set_correct_flags(void);
void        run_tcp_scan(void);

// tools
uint16_t    get_total_ports(void);
uint16_t    swap_uint16(uint16_t val);

// libft functions
void        ft_list_push_back(char *ip, struct addrinfo *res);
t_target    *ft_create_elem(char *ip, struct addrinfo *res);
void        print_list(void);
int		    is_in_array(int value);
void	    ft_exerror(char *str, int value);
int         ft_reterror(char *str, int value);
int		    ft_strcmp(const char *s1, const char *s2);
void	    *ft_memset(void *ptr, int value, size_t len);
char	    *ft_strdup(const char *s);
size_t	    ft_strlen(const char *str);
void	    *ft_memcpy(void *dest, const void *src, size_t n);
int		    ft_atoi(const char *str);
char	    **ft_split(char const *s, char c);
void	    ft_split_free(char **split);
void	    ft_add_bytes(char **src, const char *bytes, size_t nb_bytes);
void    	ft_add_str(char **src, const char *str);
char        *ft_find(char *s, char c);

# endif