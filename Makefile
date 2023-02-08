NAME =		ft_nmap
CC =		gcc
CFLAGS =	-Wall -Wextra -Werror
SRCS =		src/main.c src/manage_ports.c src/parse_params.c src/debug.c src/flags.c src/lst.c src/result.c src/libft.c src/time.c src/display.c src/parsing_ports.c src/addr.c src/fill_headers.c
INC =		ft_nmap.h
OBJS =		$(SRCS:.c=.o)


.PHONY: all clean fclean re

all: $(NAME)

$(NAME): $(OBJS)
	@ $(CC) $(CFLAGS) -o $(NAME) $(SRCS) -lm -lpcap -lpthread
	@echo "\033[1;32mprogram...compiled\t✓\033[0m"

clean:
	@rm -rf $(OBJS)
	@echo "\033[1;34mft_nmap\033[1;33m obj files removed\t\033[1;31m✓\033[0m"

fclean: clean
	@rm -rf $(NAME)
	@echo "\033[1;34mft_nmap\033[1;33m files deleted\t\t\033[1;31m✓\033[0m"

re: fclean all
