#include "ft_nmap.h"

uint16_t swap_uint16(uint16_t val) 
{
    return (val << 8) | (val >> 8 );
}

int		is_in_array(int value)
{
	int index;

	index = 0;
	while (index < MAX_PORT)
	{
		if (nmap.t_ports[index].dst_port == value)
			return (1);
		index++;
	}
	return (0);
}

void	ft_exerror(char *str, int value)
{
	if (str)
		fprintf(stderr, "%s\n", str);
	exit(value); // penser a free les trucs alloues dynamiquement
}

int     ft_reterror(char *str, int value)
{
    if (str)
        fprintf(stderr, "%s\n", str);
    return (value);
}

int		ft_strcmp(const char *s1, const char *s2)
{
	int i;

	i = 0;
	while (s1[i] == s2[i] && s1[i])
		i++;
	return (((unsigned char*)s1)[i] - ((unsigned char*)s2)[i]);
}

void	*ft_memset(void *ptr, int value, size_t len)
{
	unsigned char	*str;
	size_t			i;

	str = (unsigned char *)ptr;
	i = 0;
	while (i < len)
	{
		str[i] = (unsigned char)value;
		i++;
	}
	return (ptr);
}

char	*ft_strdup(const char *s)
{
	size_t	i;
	char	*mal;
	int		j;

	i = ft_strlen(s);
	if (!(mal = (char*)malloc(sizeof(*mal) * (i + 1))))
		return (NULL);
	j = 0;
	while (s[j])
	{
		mal[j] = s[j];
		j++;
	}
	mal[j] = '\0';
	return (mal);
}

size_t		ft_strlen(const char *str)
{
	int i;

	i = 0;
	while (str[i])
		i++;
	return (i);
}

void	*ft_memcpy(void *dest, const void *src, size_t n)
{
	size_t i;

	i = 0;
	while (i < n)
	{
		((char*)dest)[i] = ((char*)src)[i];
		i++;
	}
	return (dest);
}

int		ft_atoi(const char *str)
{
	int i;
	int res;
	int neg;

	i = 0;
	neg = 1;
	res = 0;
	while (str[i] == 32 || (str[i] >= 9 && str[i] <= 13))
		i++;
	if (str[i] == 45)
		neg = -1;
	if (str[i] == 43 || str[i] == 45)
		i++;
	while (str[i] >= 48 && str[i] <= 57)
	{
		res = (res * 10) + str[i] - 48;
		i++;
		if (i > 20)
			return (neg == -1 ? 0 : -1);
	}
	return (res * neg);
}

void		ft_split_free(char **split)
{
	int i = -1;
	while (split[++i])
		free(split[i]);
	free(split);
}

static int	count_words(const char *str, char c)
{
	int i;
	int trigger;

	i = 0;
	trigger = 0;
	while (*str)
	{
		if (*str != c && trigger == 0)
		{
			trigger = 1;
			i++;
		}
		else if (*str == c)
			trigger = 0;
		str++;
	}
	return (i);
}

static char	*word_dup(const char *str, int start, int finish)
{
	char	*word;
	int		i;

	i = 0;
	word = malloc((finish - start + 1) * sizeof(char));
	while (start < finish)
		word[i++] = str[start++];
	word[i] = '\0';
	return (word);
}

char		**ft_split(char const *s, char c)
{
	size_t	i;
	size_t	j;
	int		index;
	char	**split;

	if (!s || !(split = malloc((count_words(s, c) + 1) * sizeof(char *))))
		return (0);
	i = 0;
	j = 0;
	index = -1;
	while (i <= ft_strlen(s))
	{
		if (s[i] != c && index < 0)
			index = i;
		else if ((s[i] == c || i == ft_strlen(s)) && index >= 0)
		{
			split[j++] = word_dup(s, index, i);
			index = -1;
		}
		i++;
	}
	split[j] = 0;
	return (split);
}