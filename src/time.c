#include "ft_nmap.h"

void wait_microseconds(unsigned int microseconds)
{
    struct timeval timeout;
    timeout.tv_sec = microseconds / 1000000;
    timeout.tv_usec = microseconds % 1000000;

    select(0, NULL, NULL, NULL, &timeout);
}

void	wait_seconds(unsigned int seconds) // to bypass sleep()
{
	struct timeval timeout;
	timeout.tv_sec = seconds;
	timeout.tv_usec = 0;

	select(0, NULL, NULL, NULL, &timeout);
}

void    save_current_time(struct timeval *destination)
{
	if (gettimeofday(destination, NULL) == -1)
		fprintf(stderr, "%s", strerror(errno));
}

void	display_total_time(void)
{
	double	elapsed_time;

	elapsed_time = nmap.ending_time.tv_sec - nmap.starting_time.tv_sec;
	printf("Scan took %.0lf secondss\n", elapsed_time);
}