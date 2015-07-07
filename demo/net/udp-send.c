/*
 * sender.c -- multicasts "hello, world!" to a multicast group once a second
 *
 * Antony Courtney,	25/11/94
 */

#include <time.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <error.h>
#include <stdlib.h>
#include <sched.h>
#include <pthread.h>
#include <sys/timerfd.h>
#include <boilerplate/trace.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define HELLO_PORT 12345
#define HELLO_GROUP "225.0.0.37"
#define ONE_BILLION	1000000000

#define check_pthread(expr)			\
	({ \
		int __e = (expr);		\
		if (__e) {			\
			printf("%s: %d\n", #expr, __e);	\
			exit(EXIT_FAILURE);		\
		}					\
	})

int main(int argc, char *argv[])
{
     struct sockaddr_in addr;
     int fd, tfd, err;
     char message[] = "Hello, World!\n";
     struct timespec last_print, start, now;
     struct sched_param sparm;
     unsigned long long diff, min = ~0ULL, max = 0, sum, count;
     struct itimerspec timer_conf;

     /* create what looks like an ordinary UDP socket */
     if ((fd=socket(AF_INET,SOCK_DGRAM,0)) < 0) {
	  perror("socket");
	  exit(1);
     }

     if (argc != 2) {
	 fprintf(stderr, "Local ip address expected as first and only argument\n");
	 exit(1);
     }

     memset(&addr,0,sizeof(addr));
     addr.sin_family=AF_INET;
     addr.sin_addr.s_addr=inet_addr(argv[1]); /* N.B.: differs from sender */
     addr.sin_port=htons(HELLO_PORT);

     /* bind to receive address */
     if (bind(fd,(struct sockaddr *) &addr,sizeof(addr)) < 0) {
	  perror("bind");
	  exit(1);
     }

     /* set up destination address */
     memset(&addr,0,sizeof(addr));
     addr.sin_family=AF_INET;
     addr.sin_addr.s_addr=inet_addr(HELLO_GROUP);
     addr.sin_port=htons(HELLO_PORT);

     sparm.sched_priority = 99;

     check_pthread(pthread_setschedparam(pthread_self(), SCHED_FIFO, &sparm));

     tfd = timerfd_create(CLOCK_MONOTONIC, 0);
     if (tfd == -1)
	     error(1, errno, "timerfd_create()");

     check_pthread(pthread_setmode_np(0, PTHREAD_WARNSW, NULL));

     /* now just sendto() our destination! */
     sum = 0;
     count = 0;
     err = clock_gettime(CLOCK_MONOTONIC, &start);
     start.tv_nsec += 1000000;
     if (start.tv_nsec > ONE_BILLION) {
	     start.tv_nsec -= ONE_BILLION;
	     start.tv_sec++;
     }
     timer_conf.it_value = start;
     timer_conf.it_interval.tv_sec = 0;
     timer_conf.it_interval.tv_nsec = 5000000;
     err = timerfd_settime(tfd, TFD_TIMER_ABSTIME, &timer_conf, NULL);
     if (err)
	     error(1, errno, "timerfd_settime()");
     clock_gettime(CLOCK_MONOTONIC, &last_print);

     while (1) {
	     uint64_t ticks;
	     clock_gettime(CLOCK_MONOTONIC, &start);
	     if (sendto(fd,message,sizeof(message),0,(struct sockaddr *) &addr,
			     sizeof(addr)) < 0) {
		     perror("sendto");
		     exit(1);
	     }
	     clock_gettime(CLOCK_MONOTONIC, &now);

	     diff = now.tv_sec * 1000000ULL + now.tv_nsec / 1000 -
		     (start.tv_sec * 1000000ULL + start.tv_nsec / 1000);
	     if (diff < min)
		     min = diff;
	     if (diff > max) {
		     xntrace_user_freeze(diff, 0);
		     max = diff;
	     }
	     sum += diff;
	     count++;

	     diff = now.tv_sec * 1000000ULL + now.tv_nsec / 1000 -
		     (last_print.tv_sec * 1000000ULL + last_print.tv_sec / 1000);
	     if (diff >= 1000000) {
		     fprintf(stderr, "%Lu, %Lu, %Lu\n",
			     min, sum / count, max);
		     last_print = now;
	     }

	     err = read(tfd, &ticks, sizeof(ticks));
	     if (err < 0)
		     error(1, errno, "read()");
     }
}
