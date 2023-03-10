#include "ft_nmap.h"

t_target    *ft_create_elem(char *ip, struct addrinfo *res)
{
	t_target	*elem;

	if (!(elem = (t_target*)malloc(sizeof(t_target))))
		return (NULL);
	elem->string_ip = ft_strdup(ip);
    ft_memcpy(&(elem->sockaddr), res->ai_addr, sizeof(struct sockaddr_in));
	elem->next = NULL;
	return (elem);
}

void        ft_list_push_back(char *ip, struct addrinfo *res)
{
    t_target **tmp;

    tmp = &nmap.targets;
    while (*tmp)
        tmp = &(*tmp)->next;
    *tmp = ft_create_elem(ip, res);
}