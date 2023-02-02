#include "../inc/ft_nmap.h"

void			wait_interval(struct timeval start, long interval)
{
	struct timeval	current_time;
	struct timeval	goal_time;


		current_time = start;
		goal_time.tv_sec = current_time.tv_sec + (long)interval;
		goal_time.tv_usec = current_time.tv_usec + (long)((interval - (long)interval) * 1000000);
		while (timercmp(&current_time, &goal_time, <))
		{
			save_current_time(&current_time);
		}
}

double	calcul_request_time(struct timeval start, struct timeval end)
{
	return (((double)((double)end.tv_sec - (double)start.tv_sec) * 1000) +
		(double)((double)end.tv_usec - (double)start.tv_usec) / 1000);
}

void    save_current_time(struct timeval *destination)
{
	if (gettimeofday(destination, NULL) == -1)
		fprintf(stderr, "%s", strerror(errno));
}

void	display_request_time(struct timeval start, struct timeval end)
{
	double	elapsed_time;

	elapsed_time = calcul_request_time(start, end);
	printf("\nscan took  %.3lfs\n", elapsed_time);
}