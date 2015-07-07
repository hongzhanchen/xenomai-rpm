/*
 * Multicast RTT sender. Derived from.
 *
 * listener.c -- joins a multicast group and echoes all data it receives from
 *		the group to its stdout...
 *
 * Antony Courtney, 	25/11/94
 * Modified by: Frédéric Bastien (25/03/04)
 * to compile without warning and work correctly
 */

#include <stdio.h>
#include <time.h>
#include <stdlib.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <alchemy/task.h>
#include <alchemy/timer.h>
#include <rtdm/net.h>

#define RTT_PORT 12345
#define RTT_RECEIVER_GROUP "225.0.0.37"
#define RTT_SENDER_GROUP "224.0.0.37"

#define rt_inet_aton inet_addr
#define do_div(ull, u) ({ unsigned long _r = ull % u; ull /= u; _r; })

static int fd;

static void thread(void *arg)
{
	unsigned long long gmin, gmax, gsum, gcount;
	struct sockaddr_in addr, to_addr;
	RTIME period, start;
	int i, nbytes, err;
	socklen_t addrlen;
	char msgbuf[1500];

	(void)arg;

	memset(&to_addr, 0, sizeof(to_addr));
	to_addr.sin_family = AF_INET;
	to_addr.sin_addr.s_addr = rt_inet_aton(RTT_RECEIVER_GROUP);
	to_addr.sin_port = htons(RTT_PORT);

	start = 0;
	period = 1000000;
	err = rt_task_set_periodic(NULL, start, period);
	if (err < 0) {
		printf("make_periodic: %d\n", err);
		rt_task_delete(NULL);
	}

	gmin = ~0ULL;
	gmax = 0;
	gsum = 0;
	gcount = 0;

	/* now just enter a receive/send loop */
	for(;;) {
		unsigned long long smin, smax, ssum, savg, gavg,
			smin_us, smin_ns, savg_us, savg_ns, smax_us, smax_ns,
			gmin_us, gmin_ns, gavg_us, gavg_ns, gmax_us, gmax_ns;

		smin = ~0ULL;
		smax = 0;
		ssum = 0;

		for (i = 0; i < 1000; i++) {
			unsigned long overruns;
			long long rtt;

			err = rt_task_wait_period(&overruns);
			if (err == -ETIMEDOUT)
				printf("%ld overruns\n", overruns);
			else if (err < 0) {
				printf("wait_period: %d\n", err);
				rt_task_delete(NULL);
			}

			rtt = rt_timer_read();
			err = sendto(fd, msgbuf, 4, 0,
				(struct sockaddr *)&to_addr, sizeof(to_addr));
			if (err < 0) {
				perror("sendto");
				rt_task_delete(NULL);
			}

			addrlen = sizeof(addr);
			nbytes = recvfrom(fd, msgbuf, sizeof(msgbuf), 0,
					  (struct sockaddr *)&addr, &addrlen);
			rtt = rt_timer_read() - rtt;
			if (nbytes <= 0) {
				perror("recvfrom");
				rt_task_delete(NULL);
			}

			if (rtt < smin)
				smin = rtt;
			if (rtt > smax)
				smax = rtt;
			ssum += rtt;
		}

		if (smin < gmin)
			gmin = smin;
		if (smax > gmax)
			gmax = smax;
		gsum += ssum;
		gcount += 1000;

		savg = ssum + 500;
		do_div(savg, 1000);

		gavg = gsum + gcount / 2;
		do_div(gavg, gcount);

		smin_us = smin;
		smin_ns = do_div(smin_us, 1000);

		savg_us = savg;
		savg_ns = do_div(savg_us, 1000);

		smax_us = smax;
		smax_ns = do_div(smax_us, 1000);

		gmin_us = gmin;
		gmin_ns = do_div(gmin_us, 1000);

		gavg_us = gavg;
		gavg_ns = do_div(gavg_us, 1000);

		gmax_us = gmax;
		gmax_ns = do_div(gmax_us, 1000);

		printf("%Lu.%03Lu %Lu.%03Lu %Lu.%03Lu | %Lu.%03Lu %Lu.%03Lu %Lu.%03Lu\n",
			smin_us, smin_ns, savg_us, savg_ns, smax_us, smax_ns,
			gmin_us, gmin_ns, gavg_us, gavg_ns, gmax_us, gmax_ns);
	}
}

static int create_thread(RT_TASK *tid, int mode, void *arg)
{
	struct sockaddr_in addr;
	struct ip_mreq mreq;
	int err;

	/* create what looks like an ordinary UDP socket */
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return fd;
	}

	/* set up destination address */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	if (!arg) {
		printf("Local ip address expected as first and only argument\n");
		return -EINVAL;
	}

	addr.sin_addr.s_addr = rt_inet_aton(arg);
	addr.sin_port = htons(RTT_PORT);

	/* bind to receive address */
	err = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (err < 0) {
		perror("bind");
		return err;
	}

	/* use setsockopt() to request that the kernel join a multicast group */
	mreq.imr_multiaddr.s_addr = rt_inet_aton(RTT_SENDER_GROUP);
	mreq.imr_interface.s_addr = addr.sin_addr.s_addr;
	err = setsockopt(fd, IPPROTO_IP,
			 IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
	if (err < 0) {
		perror("setsockopt");
		rt_task_delete(NULL);
	}

	err = rt_task_spawn(tid, "rtt-mcast-measure", 8192, 99, mode,
		thread, NULL);
	if (err < 0)
		printf("rt_task_spawn: %d\n", err);

	return err;
}

int main(int argc, char *argv[])
{
	RT_TASK tid;
	int err;

	err = create_thread(&tid, T_JOINABLE, argc >= 2 ? argv[1] : NULL);
	if (err)
		exit(EXIT_FAILURE);

	err = rt_task_join(&tid);
	if (err < 0)
		printf("rt_task_join: %d\n", err);

	exit(EXIT_FAILURE);
}
