MAKEFLAGS += "-j 16"

NAME =		ft_nmap
CC =		gcc

CFLAGS =	-I inc -O3
CFLAGS +=	-Wall -Wextra -Werror
#CFLAGS +=	-fsanitize=address -g

SRCS =		src/main.c \
			src/manage_ports.c \
			src/parse_params.c \
			src/debug.c \
			src/flags.c \
			src/lst.c \
			src/result.c \
			src/libft.c \
			src/time.c \
			src/display.c \
			src/parsing_ports.c \
			src/addr.c \
			src/fill_headers.c

INC =		inc/ft_nmap.h

OBJS =		$(SRCS:.c=.o)


.PHONY: all clean fclean re

all: $(NAME)

%.o: %.c $(INC)
	@$(CC) $(CFLAGS) -c $< -o $@
	@echo "\033[1;33mcompiled\033[0;34m $<\033[40G\033[1;32m✓\033[0m"

$(NAME): $(OBJS)
	@$(CC) $(CFLAGS) -o $(NAME) $(SRCS) -lm -lpcap -lpthread
	@echo "\033[1;32m  linked\033[0;34m ft_nmap\033[40G\033[1;32m✓\033[0m"

clean:
	@rm -rf $(OBJS)
	@echo "\033[1;31m removed\033[0;34m objects files\033[40G\033[1;31m✓\033[0m"

fclean: clean
	@rm -rf $(NAME)
	@echo "\033[1;31m removed\033[0;34m ft_nmap\033[40G\033[1;31m✓\033[0m"

re:
	@make --no-print-directory fclean
	@make --no-print-directory all
