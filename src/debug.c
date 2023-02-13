#include "ft_nmap.h"

//debug function
void    display_ports(void)
{
    int index;

    index = 0;
    printf("ports: ");
    while (nmap.t_ports[index].dst_port != 0)
    {
        printf("%d ", nmap.t_ports[index].dst_port);
        index++;
    }
    printf("\n");
}

//debug function
/*void    print_bits(uint8_t octet)
{
    int z = 128, oct = octet;

    while (z > 0)
    {
        if (oct & z)
            write(1, "1", 1);
        else
            write(1, "0", 1);
        z >>= 1;
    }
    puts("\n");
}
*/

//debug function
void        print_list(void)
{
    t_target *tmp;

    tmp = nmap.targets;
    if (tmp)
    {
        while (tmp)
        {
            printf("->%s\n", tmp->string_ip);
            print_memory(&tmp->sockaddr, sizeof(struct sockaddr_in));
            tmp = tmp->next;
        }
    }
}

//debug function
void    print_memory(void *memory, int size)
{
    unsigned char   *p;
    int             i;

    p = memory;
    if (p)
    {
        for (i = 0; i < size; i++)
            printf("%02hhX ", p[i]);
        printf("\n");
    }
}
