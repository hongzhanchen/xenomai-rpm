/*
 * sender.c -- multicasts "hello, world!" to a multicast group once a second
 *
 * Antony Courtney,	25/11/94
 */

#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <pthread.h>
#include <errno.h>
#include <signal.h>
#include <execinfo.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


#define HELLO_PORT 12345
#define HELLO_GROUP "225.0.0.37"

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

static void usage(const char *progname)
{
	fprintf(stderr, "%s address frequency\n"
		"Starts sending 'frequency' multicast UDP packets per second on"
		" the interface\nwith IP address 'address'.\n",
		progname);
}

int main(int argc, char *argv[])
{
	struct sigaction sa __attribute__((unused));
	struct sockaddr_in addr;
	int fd;
	char message[] = "Hello, World!\n";
	struct sched_param sparm;
	struct timespec next;
	double freq;
	unsigned period_ns;

	if (argc != 3) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	freq = atof(argv[2]);
	period_ns = freq ? 1000000000 / freq : 0;

	check_unix(fd = socket(AF_INET,SOCK_DGRAM, 0));

	addr.sin_addr.s_addr = inet_addr(argv[1]);

	check_unix(setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF,
				&addr.sin_addr, sizeof(addr.sin_addr)));

	sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = sigdebug;
	sa.sa_flags = SA_SIGINFO;
	check_unix(sigaction(SIGDEBUG, &sa, NULL));

	memset(&addr,0,sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(HELLO_GROUP);
	addr.sin_port = htons(HELLO_PORT);

	sparm.sched_priority = 99;
	check_pthread(pthread_setschedparam(pthread_self(),
						SCHED_FIFO, &sparm));

	check_unix(clock_gettime(CLOCK_MONOTONIC, &next));

	check_pthread(pthread_setmode_np(0, PTHREAD_WARNSW, NULL));

	while (1) {
		check_unix(sendto(fd,message,sizeof(message), 0,
					(struct sockaddr *)&addr,
					sizeof(addr)));

		if (!period_ns)
			continue;

		next.tv_nsec += period_ns;
		if (next.tv_nsec >= 1000000000) {
			next.tv_nsec -= 1000000000;
			next.tv_sec++;
		}
		check_unix(clock_nanosleep(CLOCK_MONOTONIC,
						TIMER_ABSTIME, &next, NULL));
	}
}
