/*
 * Multicast RTT responder. Derived from.
 *
 * listener.c -- joins a multicast group and echoes all data it receives from
 *		the group to its stdout...
 *
 * Antony Courtney, 	25/11/94
 * Modified by: Frédéric Bastien (25/03/04)
 * to compile without warning and work correctly
 */

#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <rtdm/net.h>


#define RTT_PORT 12345
#define RTT_RECEIVER_GROUP "225.0.0.37"
#define RTT_SENDER_GROUP "224.0.0.37"

int main(int argc, char *argv[])
{
	struct sockaddr_in addr, to_addr;
	struct sched_param sparm;
	int add_rtskbs = 128;
	struct ip_mreq mreq;
	int fd, err, nbytes;
	socklen_t addrlen;
	char msgbuf[1500];

	sparm.sched_priority = 99;
	err = pthread_setschedparam(pthread_self(), SCHED_FIFO, &sparm);
	if (err) {
		fprintf(stderr, "pthread_setschedparam: %d\n", err);
		exit(EXIT_FAILURE);
	}

	/* create what looks like an ordinary UDP socket */
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		exit(EXIT_FAILURE);
	}

	/* set up destination address */
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	if (argc != 2) {
		fprintf(stderr, "Local ip address expected as first and only argument\n");
		exit(EXIT_FAILURE);
	}

	addr.sin_addr.s_addr = inet_addr(argv[1]);
	addr.sin_port = htons(RTT_PORT);

	/* bind to receive address */
	err = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
	if (err < 0) {
		perror("bind");
		exit(EXIT_FAILURE);
	}

	memset(&to_addr, 0, sizeof(to_addr));
	to_addr.sin_family = AF_INET;
	to_addr.sin_addr.s_addr = inet_addr(RTT_SENDER_GROUP);
	to_addr.sin_port = htons(RTT_PORT);

	/* use setsockopt() to request that the kernel join a multicast group */
	mreq.imr_multiaddr.s_addr = inet_addr(RTT_RECEIVER_GROUP);
	mreq.imr_interface.s_addr = addr.sin_addr.s_addr;
	err = setsockopt(fd, IPPROTO_IP,
			IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq));
	if (err < 0) {
		perror("setsockopt");
		exit(EXIT_FAILURE);
	}

	err = ioctl(fd, RTNET_RTIOC_EXTPOOL, &add_rtskbs);
	if (err < 0)
		perror("ioctl(RTNET_RTIOC_EXTPOOL)\n");

	/* now just enter a receive/send loop */
	while (1) {
		addrlen = sizeof(addr);
		nbytes = recvfrom(fd, msgbuf, sizeof(msgbuf), 0,
				(struct sockaddr *)&addr, &addrlen);
		if (nbytes <= 0) {
			perror("recvfrom");
			exit(EXIT_FAILURE);
		}

		err = sendto(fd, msgbuf, nbytes, 0,
			(struct sockaddr *)&to_addr, sizeof(addr));
		if (err < 0) {
			perror("sendto");
			exit(EXIT_FAILURE);
		}
	}
}
