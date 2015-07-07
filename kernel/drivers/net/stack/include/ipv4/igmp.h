/*
 *  include/ipv4/igmp.h - Internet Group Management Protocol  [IGMP]
 *
 *      Adapted from linux/igmp.h to RTnet by:
 *              Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>
 *	Original author:
 *		Alan Cox <Alan.Cox@linux.org>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 */

#ifndef __RTNET_IGMP_H_
#define __RTNET_IGMP_H_
#include <asm/byteorder.h>
#include <linux/init.h>
#include <linux/kconfig.h>
#include <linux/in.h>
#include <rtnet_socket.h>

struct igmphdr {
	__u8 type;
	__u8 code;		/* For newer IGMP */
	__u16 csum;
	__u32 group;
};

#define IGMP_HOST_MEMBERSHIP_QUERY	0x11	/* From RFC1112 */
#define IGMP_HOST_MEMBERSHIP_REPORT	0x12	/* Ditto */
#define IGMP_DVMRP			0x13	/* DVMRP routing */
#define IGMP_PIM			0x14	/* PIM routing */
#define IGMP_TRACE			0x15
#define IGMP_HOST_NEW_MEMBERSHIP_REPORT 0x16	/* New version of 0x11 */
#define IGMP_HOST_LEAVE_MESSAGE 	0x17

#define IGMP_MTRACE_RESP		0x1e
#define IGMP_MTRACE			0x1f

#define IGMP_DELAYING_MEMBER		0x01
#define IGMP_IDLE_MEMBER		0x02
#define IGMP_LAZY_MEMBER		0x03
#define IGMP_SLEEPING_MEMBER		0x04
#define IGMP_AWAKENING_MEMBER		0x05

#define IGMP_MINLEN			8

#define IGMP_MAX_HOST_REPORT_DELAY	10	/* max delay for response to */
						/* query (in seconds)   */

#define IGMP_TIMER_SCALE		10	/* denotes that the igmphdr->timer field */
						/* specifies time in 10th of seconds     */

#define IGMP_AGE_THRESHOLD		400	/* If this host don't hear any IGMP V1  */
						/* message in this period of time,      */
						/* revert to IGMP v2 router.            */

#define IGMP_ALL_HOSTS		htonl(0xE0000001L)
#define IGMP_ALL_ROUTER 	htonl(0xE0000002L)
#define IGMP_LOCAL_GROUP	htonl(0xE0000000L)
#define IGMP_LOCAL_GROUP_MASK	htonl(0xFFFFFF00L)

enum rtip_mc_state {
	RTIP_MC_NON_MEMBER,
	RTIP_MC_DELAYING_MEMBER,
	RTIP_MC_IDLE_MEMBER,
};

struct rtip_mc_socklist {
	struct rtip_mc_socklist	*next;
	struct ip_mreq		multi;
};

struct rtip_mc_list {
	struct rtnet_device	*interface;
	u32			multiaddr;
	struct rtip_mc_list	*next;
	int			users;
	enum rtip_mc_state	state;
};

static inline bool rtnet_in_multicast(u32 addr)
{
	return IS_ENABLED(CONFIG_XENO_DRIVERS_NET_RTIPV4_IGMP) &&
		IN_MULTICAST(addr);
}

#ifdef CONFIG_XENO_DRIVERS_NET_RTIPV4_IGMP
int rt_ip_mc_join_group(struct rtsocket *sk, struct ip_mreq *imr);
int rt_ip_mc_leave_group(struct rtsocket *sk, struct ip_mreq *imr);
void rt_ip_mc_drop_socket(struct rtsocket *sk);
void rt_ip_mc_dec_group(struct rtnet_device *rtdev, u32 addr);
void rt_ip_mc_inc_group(struct rtnet_device *rtdev, u32 addr);
void rt_igmp_init(void);
void rt_igmp_release(void);
#else
static inline void rt_igmp_init(void) { }
static inline void rt_igmp_release(void) { }
#endif

#endif /* __RTNET_IGMP_H_ */
