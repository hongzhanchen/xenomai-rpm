/*
 * listener.c -- joins a multicast group and echoes all data it receives from
 *		the group to its stdout...
 *
 * Antony Courtney,	25/11/94
 * Modified by: Frédéric Bastien (25/03/04)
 * to compile without warning and work correctly
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>
#include <string.h>
#include <sched.h>
#include <pthread.h>
#include <errno.h>

#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#include <execinfo.h>

#define HELLO_PORT 12345
#define HELLO_GROUP "225.0.0.37"
#define MSGBUFSIZE 256

#define TO_US(ns) \
    (ns) / 1000, (ns) % 1000

static void check(const char *file, int line, const char *service, int status, int err)
{
	if (status >= 0)
		return;

	pthread_setmode_np(PTHREAD_WARNSW, 0, NULL);
	__real_fprintf(stderr, "%s:%d: %s: %s\n", file, line, service, strerror(err));

	exit(EXIT_FAILURE);
}

#define check_pthread(expr)						\
    ({									\
	    int _status = (expr);					\
	    check(__FILE__, __LINE__, #expr, -_status, _status);	\
    })

#define check_unix(expr)					\
    ({								\
	    int _status = (expr);				\
	    check(__FILE__, __LINE__, #expr, _status, errno);	\
    })

static const char *reason_str[] = {
	[SIGDEBUG_UNDEFINED] = "received SIGDEBUG for unknown reason",
	[SIGDEBUG_MIGRATE_SIGNAL] = "received signal",
	[SIGDEBUG_MIGRATE_SYSCALL] = "invoked syscall",
	[SIGDEBUG_MIGRATE_FAULT] = "triggered fault",
	[SIGDEBUG_MIGRATE_PRIOINV] = "owner is not in real-time mode",
	[SIGDEBUG_NOMLOCK] = "process memory not locked",
	[SIGDEBUG_WATCHDOG] = "watchdog triggered (period too short?)",
	[SIGDEBUG_LOCK_BREAK] = "scheduler lock break",
	[SIGDEBUG_MUTEX_SLEEP] = "caller sleeps with mutex",
};

static void sigdebug(int sig, siginfo_t *si, void *context)
{
	const char fmt[] = "%s, aborting.\n";
	unsigned int reason = sigdebug_reason(si);
	int n __attribute__ ((unused));
	static char buffer[256];
	void *bt[32];
	int nentries;

	if (reason >= sizeof(reason_str) / sizeof(reason_str[0]))
		reason = SIGDEBUG_UNDEFINED;

	n = snprintf(buffer, sizeof(buffer), fmt, reason_str[reason]);
	n = write(STDERR_FILENO, buffer, n);
	nentries = backtrace(bt, sizeof(bt) / sizeof(bt[0]));
	backtrace_symbols_fd(bt, nentries, STDERR_FILENO);

	signal(sig, SIG_DFL);
	kill(getpid(), sig);
}

int main(int argc, char *argv[])
{
	unsigned long long min, max, sum, count, gmin, gmax, gsum, gcount;
	struct sigaction sa __attribute__((unused));
	struct sockaddr_in addr;
	int fd, err;
	struct ip_mreq mreq;
	socklen_t addrlen;
	struct timespec last_print;
	struct sched_param sparm;
	char msgbuf[MSGBUFSIZE];
	bool first = true;

	if (argc != 2) {
		fprintf(stderr, "Local ip address expected as first and "
			"only argument\n");
		exit(EXIT_FAILURE);
	}

	sparm.sched_priority = 97;
	check_pthread(pthread_setschedparam(pthread_self(),
						    SCHED_FIFO, &sparm));

	check_unix(fd = socket(AF_INET,SOCK_DGRAM,0));

	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = sigdebug;
	sa.sa_flags = SA_SIGINFO;
	check_unix(sigaction(SIGDEBUG, &sa, NULL));

	memset(&addr,0,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(argv[1]);
	addr.sin_port = htons(HELLO_PORT);

	check_unix(bind(fd, (struct sockaddr *)&addr,sizeof(addr)));

	mreq.imr_multiaddr.s_addr = inet_addr(HELLO_GROUP);
	mreq.imr_interface.s_addr = addr.sin_addr.s_addr;
	check_unix(setsockopt(fd,IPPROTO_IP,
				IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)));

	gmin = min = ~0ULL;
	gmax = max = 0;
	gsum = sum = 0;
	gcount = count = 0;

	check_pthread(pthread_setmode_np(0, PTHREAD_WARNSW, NULL));

	check_unix(clock_gettime(CLOCK_REALTIME, &last_print));

	while (1) {
		struct timespec now;
		struct timeval packet;
		unsigned long long diff;

		addrlen = sizeof(addr);
		check_unix(recvfrom(fd, msgbuf, sizeof(msgbuf), 0,
					(struct sockaddr *)&addr, &addrlen));
		check_unix(clock_gettime(CLOCK_REALTIME, &now));

		err = ioctl(fd, SIOCGSTAMP, &packet);
		if (err < 0) {
			perror("ioctl");
			exit(1);
		}

		if (first) {
			first = false;
			continue;
		}

		diff = now.tv_sec * 1000000000ULL + now.tv_nsec -
			(packet.tv_sec * 1000000000ULL
			+ packet.tv_usec * 1000ULL);
		if ((long long)diff < 0)
			printf("%lu.%09lu - %lu.%06lu\n",
				now.tv_sec, now.tv_nsec,
				packet.tv_sec, packet.tv_usec);

		if (diff < min)
			min = diff;
		if (diff > max)
			max = diff;
		sum += diff;
		++count;

		diff = now.tv_sec * 1000000000ULL + now.tv_nsec -
			(last_print.tv_sec * 1000000000ULL
			+ last_print.tv_nsec);
		if (diff < 1000000000)
			continue;

		if (min < gmin)
			gmin = min;
		if (max > gmax)
			gmax = max;
		gsum += sum;
		gcount += count;

		printf("%g pps, %Lu.%03Lu %Lu.%03Lu %Lu.%03Lu "
			"| %Lu.%03Lu %Lu.%03Lu %Lu.%03Lu\n",
			count / (diff / 1000000000.0),
			TO_US(min), TO_US(sum / count), TO_US(max),
			TO_US(gmin), TO_US(gsum / gcount), TO_US(gmax));

		min = ~0ULL;
		max = 0;
		sum = 0;
		count = 0;
		last_print = now;
	}
}
