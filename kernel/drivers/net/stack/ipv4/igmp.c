/*
 *      ipv4/igmp.c - Internet Group Management Protocol  [IGMP]
 *
 *      Adapted from net/ipv4/igmp.c to RTnet by:
 *              Gilles Chanteperdrix <gilles.chanteperdrix@xenomai.org>
 *	Original author:
 *		Alan Cox <Alan.Cox@linux.org>
 *
 *	This program is free software; you can redistribute it and/or
 *	modify it under the terms of the GNU General Public License
 *	as published by the Free Software Foundation; either version
 *	2 of the License, or (at your option) any later version.
 *
 *	Fixes:
 *
 *		Alan Cox	:	Added lots of __inline__ to optimise
 *					the memory usage of all the tiny little
 *					functions.
 *		Alan Cox	:	Dumped the header building experiment.
 *		Alan Cox	:	Minor tweaks ready for multicast routing
 *					and extended IGMP protocol.
 *		Alan Cox	:	Removed a load of inline directives. Gcc 2.5.8
 *					writes utterly bogus code otherwise (sigh)
 *					fixed IGMP loopback to behave in the manner
 *					desired by mrouted, fixed the fact it has been
 *					broken since 1.3.6 and cleaned up a few minor
 *					points.
 *
 *		Chih-Jen Chang	:	Tried to revise IGMP to Version 2
 *		Tsu-Sheng Tsao		E-mail: chihjenc@scf.usc.edu and tsusheng@scf.usc.edu
 *					The enhancements are mainly based on Steve Deering's
 *					ipmulti-3.5 source code.
 *		Chih-Jen Chang	:	Added the igmp_get_mrouter_info and
 *		Tsu-Sheng Tsao		igmp_set_mrouter_info to keep track of
 *					the mrouted version on that device.
 *		Chih-Jen Chang	:	Added the max_resp_time parameter to
 *		Tsu-Sheng Tsao		igmp_heard_query(). Using this parameter
 *					to identify the multicast router version
 *					and do what the IGMP version 2 specified.
 *		Chih-Jen Chang	:	Added a timer to revert to IGMP V2 router
 *		Tsu-Sheng Tsao		if the specified time expired.
 *		Alan Cox	:	Stop IGMP from 0.0.0.0 being accepted.
 *		Alan Cox	:	Use GFP_ATOMIC in the right places.
 *		Christian Daudt :	igmp timer wasn't set for local group
 *					memberships but was being deleted,
 *					which caused a "del_timer() called
 *					from %p with timer not initialized\n"
 *					message (960131).
 *		Christian Daudt :	removed del_timer from
 *					igmp_timer_expire function (960205).
 *             Christian Daudt :       igmp_heard_report now only calls
 *                                     igmp_timer_expire if tm->running is
 *                                     true (960216).
 *		Malcolm Beattie :	ttl comparison wrong in igmp_rcv made
 *					igmp_heard_query never trigger. Expiry
 *					miscalculation fixed in igmp_heard_query
 *					and random() made to return unsigned to
 *					prevent negative expiry times.
 *		Alexey Kuznetsov:	Wrong group leaving behaviour, backport
 *					fix from pending 2.1.x patches.
 *		Alan Cox:		Forget to enable FDDI support earlier.
 *		Alexey Kuznetsov:	Fixed leaving groups on device down.
 *		Alexey Kuznetsov:	Accordance to igmp-v2-06 draft.
 */

#include <ipv4/igmp.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <rtnet_socket.h>
#include <rtdev.h>
#include <ipv4/protocol.h>
#include <ipv4/route.h>
#include <ipv4/arp.h>

#define IGMP_REPLY_POOL_SIZE  8
#define IP_MAX_MEMBERSHIPS 20
#define RT_IGMP_SKB_PRIO     RTSKB_PRIO_VALUE(QUEUE_MIN_PRIO-1,		\
						RTSKB_DEF_NRT_CHANNEL)
/***
 *  It is not part of the socket pool. It may furthermore be used concurrently
 *  by multiple tasks because all fields are static excect skb_pool, but that
 *  is spin lock protected.
 */
static struct rtsocket igmp_socket;
static struct rtip_mc_list *mc_list;
static rtdm_lock_t  mc_list_lock;
static rtdm_mutex_t mc_socklist_lock;
rtdm_task_t rtnet_igmp_task;

#define IGMP_SIZE (sizeof(struct igmphdr)+sizeof(struct iphdr)+4)

static int rt_igmp_send_report(struct rtnet_device *rtdev, u32 group, int type)
{
	struct rtskb *skb;
	struct iphdr *iph;
	struct igmphdr *ih;
	struct dest_route rt;
	u32 dst;
	int len;
	int err;
	char buf[MAX_ADDR_LEN];
	/* According to IGMPv2 specs, LEAVE messages are
	 * sent to all-routers group.
	 */
	dst = group;
	if (type == IGMP_HOST_LEAVE_MESSAGE)
		dst = IGMP_ALL_ROUTER;
	if (rt_arp_mc_map(dst, buf, rtdev, 0) == 0) {
		memcpy(rt.dev_addr, buf, sizeof(buf));
		rt.rtdev = rtdev;
		rt.ip = dst;
	}

	len = (rtdev->hard_header_len + 15) & ~15;
	skb = alloc_rtskb(len + IGMP_SIZE + 15, &global_pool);
	if (skb == NULL) {
		printk("can't alloc rtskb \n");
		return -ENOMEM;
	}

	skb->rtdev = rtdev;
	skb->priority = RT_IGMP_SKB_PRIO;
	rtskb_reserve(skb, len);
	skb->nh.iph = iph = (struct iphdr *)rtskb_put(skb, sizeof(*iph) + 4);
	iph->version = 4;
	iph->ihl = (sizeof(struct iphdr) + 4) >> 2;
	iph->tos = 0xc0;
	iph->frag_off = htons(IP_DF);
	iph->ttl = 1;
	iph->daddr = rt.ip;
	iph->saddr = rtdev->local_ip;
	iph->protocol = IPPROTO_IGMP;
	iph->tot_len = htons(IGMP_SIZE);
	iph->id = htons(0);
	((u8 *) & iph[1])[0] = IPOPT_RA;
	((u8 *) & iph[1])[1] = 4;
	((u8 *) & iph[1])[2] = 0;
	((u8 *) & iph[1])[3] = 0;
	ip_send_check(iph);
	ih = (struct igmphdr *)rtskb_put(skb, sizeof(struct igmphdr));
	ih->type = type;
	ih->code = 0;
	ih->csum = 0;
	ih->group = group;
	ih->csum = ip_compute_csum((void *)ih, sizeof(struct igmphdr));

	if (rtdev->hard_header) {
		err = rtdev->hard_header(skb, rtdev, ETH_P_IP, rt.dev_addr,
					 rtdev->dev_addr, skb->len);
		if (err < 0) {
		    kfree_rtskb(skb);
		    return err;
		}
	}

	return rtdev_xmit(skb);
}

static void igmp_heard_query(struct rtnet_device *rtdev, u32 group)
{
    struct rtip_mc_list	*im;
    unsigned long     flags;

    rtdm_lock_get_irqsave(&mc_list_lock, flags);
    for (im = mc_list; im != NULL; im = im->next)
	if (im->multiaddr != IGMP_ALL_HOSTS
	    && (!group || im->multiaddr == group))
	    im->state = RTIP_MC_DELAYING_MEMBER;
    rtdm_lock_put_irqrestore(&mc_list_lock, flags);
}

static void igmp_heard_report(struct rtnet_device *rtdev, u32 group)
{
    struct rtip_mc_list	*im;
    unsigned long     flags;

    rtdm_lock_get_irqsave(&mc_list_lock, flags);
    for (im = mc_list; im != NULL; im = im->next)
	if (im->multiaddr == group
	    && im->state == RTIP_MC_DELAYING_MEMBER)
	    im->state = RTIP_MC_IDLE_MEMBER;
    rtdm_lock_put_irqrestore(&mc_list_lock, flags);
}

void rt_igmp_rcv(struct rtskb *skb)
{
	/* This basically follows the spec line by line -- see RFC1112 */
	struct igmphdr *ih = skb->h.igmph;
	struct rtnet_device *rtdev = skb->rtdev;
	int len = skb->len;
	if (len < sizeof(struct igmphdr) || ip_compute_csum((void *)ih, len))
		goto cleanup;

	switch (ih->type) {
	case IGMP_HOST_MEMBERSHIP_QUERY:
		igmp_heard_query(rtdev, ih->group);
		break;
	case IGMP_HOST_MEMBERSHIP_REPORT:
	case IGMP_HOST_NEW_MEMBERSHIP_REPORT:
		igmp_heard_report(rtdev, ih->group);
		break;
	case IGMP_PIM:
	case IGMP_DVMRP:
	case IGMP_TRACE:
	case IGMP_HOST_LEAVE_MESSAGE:
	case IGMP_MTRACE:
	case IGMP_MTRACE_RESP:
		break;
	default:
		rtdm_printk(KERN_DEBUG
			    "New IGMP type=0x%x, why we do not know about it?\n",
			    ih->type);
	}

cleanup:
	kfree_rtskb(skb);
}

/*
 *	Add a filter to a device
 */
static void rt_ip_mc_filter_add(struct rtnet_device *rtdev, u32 addr)
{
	char buf[MAX_ADDR_LEN];

	/* Checking for IFF_MULTICAST here is WRONG-WRONG-WRONG.
	   We will get multicast token leakage, when IFF_MULTICAST
	   is changed. This check should be done in dev->set_multicast_list
	   routine. Something sort of:
	   if (dev->mc_list && dev->flags&IFF_MULTICAST) { do it; }
	   --ANK
	 */
	if (rt_arp_mc_map(addr, buf, rtdev, 0) == 0)
		rt_dev_mc_add(rtdev, buf, rtdev->addr_len, 0);
}

/*
 *	Remove a filter from a device
 */
static void rt_ip_mc_filter_del(struct rtnet_device *rtdev, u32 addr)
{
	char buf[MAX_ADDR_LEN];
	struct rtnet_device *dev = rtdev;

	if (rt_arp_mc_map(addr, buf, dev, 0) == 0)
		rt_dev_mc_delete(dev, buf, dev->addr_len, 0);
}

static void igmp_group_dropped(struct rtip_mc_list *im)
{
    unsigned long flags;
    enum rtip_mc_state oldstate;

    rtdm_lock_get_irqsave(&mc_list_lock, flags);
    oldstate = im->state;
    if (oldstate != RTIP_MC_NON_MEMBER)
	im->state = RTIP_MC_NON_MEMBER;
    rtdm_lock_put_irqrestore(&mc_list_lock, flags);

    if (oldstate != RTIP_MC_NON_MEMBER)
	rt_ip_mc_filter_del(im->interface, im->multiaddr);
}

static void igmp_group_added(struct rtip_mc_list *im)
{
    unsigned long flags;
    enum rtip_mc_state oldstate;

    rtdm_lock_get_irqsave(&mc_list_lock, flags);
    oldstate = im->state;
    if (oldstate == RTIP_MC_NON_MEMBER) {
	if (im->multiaddr == IGMP_ALL_HOSTS)
	    im->state = RTIP_MC_IDLE_MEMBER;
	else
	    im->state = RTIP_MC_DELAYING_MEMBER;
    }
    rtdm_lock_put_irqrestore(&mc_list_lock, flags);

    if (oldstate != RTIP_MC_NON_MEMBER) {
	return;
    }

    rt_ip_mc_filter_add(im->interface, im->multiaddr);

    if (im->multiaddr != IGMP_ALL_HOSTS && rtdm_in_rt_context())
	rt_igmp_send_report(im->interface,
			    im->multiaddr, IGMP_HOST_MEMBERSHIP_REPORT);
}

void rt_ip_mc_inc_group(struct rtnet_device *rtdev, u32 addr)
{
    struct rtip_mc_list *im, *iml;
    unsigned long flags;

    iml = rtdm_malloc(sizeof(*im));
    if (!iml)
	return;
    iml->users = 1;
    iml->interface = rtdev;
    iml->multiaddr = addr;
    iml->state = RTIP_MC_NON_MEMBER;

    rtdm_lock_get_irqsave(&mc_list_lock, flags);
    for (im = mc_list; im; im = im->next) {
	if (im->multiaddr == addr && im->interface == rtdev) {
	    im->users++;
	    rtdm_lock_put_irqrestore(&mc_list_lock, flags);
	    rtdm_free(iml);
	    return;
	}
    }
    iml->next = mc_list;
    mc_list = iml;
    rtdm_lock_put_irqrestore(&mc_list_lock, flags);

    igmp_group_added(iml);
}

/*
 *	A socket has left a multicast group on device dev
 */
void rt_ip_mc_dec_group(struct rtnet_device *rtdev, u32 addr)
{
    struct rtip_mc_list *i, **ip;
    unsigned long	flags;
    rtdm_lock_get_irqsave(&mc_list_lock, flags);
    for (ip = &mc_list; (i = *ip) != NULL; ip = &i->next) {
	if (i->multiaddr == addr && i->interface == rtdev) {
	    if (--i->users == 0) {
		*ip = i->next;
		rtdm_lock_put_irqrestore(&mc_list_lock, flags);
		igmp_group_dropped(i);
		rtdm_free(i);
		return;
	    }
	    break;
	}
    }
    rtdm_lock_put_irqrestore(&mc_list_lock, flags);
}

static struct rtnet_device *rt_ip_mc_find_dev(const struct ip_mreq *imr)
{
    struct rtnet_device *rtdev = NULL;

    if (imr->imr_interface.s_addr)
	rtdev = rt_ip_dev_find(imr->imr_interface.s_addr);

    return rtdev;
}

/*
 *	Join a socket to a group
 */

int rt_ip_mc_join_group(struct rtsocket *sk, const struct ip_mreq *imr)
{
    int err = 0;
    u32 addr = imr->imr_multiaddr.s_addr;
    struct rtnet_device *rtdev = rt_ip_mc_find_dev(imr);
    struct rtip_mc_socklist *i, *iml;

    if (!rtdev)
	return -ENODEV;

    if (!IN_MULTICAST(ntohl(addr))) {
	err = -EINVAL;
	goto done;
    }

    iml = rtdm_malloc(sizeof(*iml));
    if (!iml) {
	err = -ENOMEM;
	goto done;
    }
    iml->multi = *imr;

    rtdm_mutex_lock(&mc_socklist_lock);
    for (i = sk->prot.inet.mc_list; i; i = i->next)
	    if (i->multi.imr_multiaddr.s_addr == addr &&
		i->multi.imr_interface.s_addr == imr->imr_interface.s_addr) {
		rtdm_mutex_unlock(&mc_socklist_lock);
		rtdm_free(iml);
		err = 0;
		goto done;
	    }

    iml->next = sk->prot.inet.mc_list;
    sk->prot.inet.mc_list = iml;
    rtdm_mutex_unlock(&mc_socklist_lock);

    rt_ip_mc_inc_group(rtdev, addr);

  done:
    rtdev_dereference(rtdev);
    return err;
}

/*
 *	Ask a socket to leave a group.
 */
int rt_ip_mc_leave_group(struct rtsocket *sk, const struct ip_mreq *imr)
{
    u32 addr = imr->imr_multiaddr.s_addr;
    struct  rtnet_device *rtdev = rt_ip_mc_find_dev(imr);
    struct rtip_mc_socklist *i, **ip;

    if (!rtdev)
	return -ENODEV;

    rtdm_mutex_lock(&mc_socklist_lock);
    for (ip = &sk->prot.inet.mc_list; (i = *ip); ip = &i->next)
	    if (i->multi.imr_multiaddr.s_addr == addr &&
		i->multi.imr_interface.s_addr == imr->imr_interface.s_addr) {
		*ip = i->next;
		rtdm_mutex_unlock(&mc_socklist_lock);
		goto found;
	    }
    rtdm_mutex_unlock(&mc_socklist_lock);

    rtdev_dereference(rtdev);

    return -EADDRNOTAVAIL;

  found:
    rt_igmp_send_report(rtdev, addr, IGMP_HOST_LEAVE_MESSAGE);
    rt_ip_mc_dec_group(rtdev, addr);
    rtdev_dereference(rtdev);

    rtdm_free(i);

    return 0;
}

/*
 *	A socket is closing.
 */
void rt_ip_mc_drop_socket(struct rtsocket *sk)
{
    struct rtip_mc_socklist *i, *in;

    if (sk->prot.inet.mc_list == NULL)
	return;

    for (i = sk->prot.inet.mc_list; i; i = in) {
	struct rtnet_device *rtdev;

	in = i->next;
	rtdev = rt_ip_mc_find_dev(&i->multi);
	if (!rtdev)
	    continue;

	rt_ip_mc_dec_group(rtdev, i->multi.imr_multiaddr.s_addr);
	rtdev_dereference(rtdev);
    }
}

static void process(void *arg)
{
    struct rtip_mc_list *im;
    unsigned long flags;

    while(!rtdm_task_should_stop()){
	rtdm_lock_get_irqsave(&mc_list_lock, flags);
	for (im = mc_list; im; im = im->next) {
	    if (im->state == RTIP_MC_DELAYING_MEMBER) {
		im->state = RTIP_MC_IDLE_MEMBER;
		im->users++;
		rtdev_reference(im->interface);
		break;
	    }
	}
	rtdm_lock_put_irqrestore(&mc_list_lock, flags);

	if (im) {
	    rt_igmp_send_report(im->interface,
				im->multiaddr, IGMP_HOST_MEMBERSHIP_REPORT);
	    rt_ip_mc_dec_group(im->interface, im->multiaddr);
	    rtdev_dereference(im->interface);
	}

	rtdm_task_wait_period(NULL);
    }
}

static int rt_igmp_socket(struct rtdm_fd *fd)
{
	/* we don't support user-created ICMP sockets */
	return -ENOPROTOOPT;
}

static struct rtsocket *rt_igmp_dest_socket(struct rtskb *skb)
{
	/* Note that the socket's refcount is not used by this protocol.
	 * The socket returned here is static and not part of the global pool. */
	return &igmp_socket;
}

void rt_igmp_rcv_err(struct rtskb *skb)
{
	rtdm_printk("RTnet: rt_igmp_rcv err\n");
}

static struct rtinet_protocol igmp_protocol = {
	.protocol = IPPROTO_IGMP,
	.dest_socket = rt_igmp_dest_socket,
	.rcv_handler = rt_igmp_rcv,
	.err_handler = rt_igmp_rcv_err,
	.init_socket = rt_igmp_socket
};

static void rt_ip_mc_unregister(struct rtnet_device *rtdev)
{
    struct rtip_mc_list *i, **ip;
    unsigned long flags;

    if (rtdev->flags & IFF_LOOPBACK)
	return;

  restart:
    rtdm_lock_get_irqsave(&mc_list_lock, flags);
    for (ip = &mc_list; (i = *ip) != NULL; ip = &i->next) {
	if (i->interface != rtdev)
	    continue;
	*ip = i->next;
	rtdm_lock_put_irqrestore(&mc_list_lock, flags);

	igmp_group_dropped(i);
	rtdm_free(i);
	goto restart;
    }
    rtdm_lock_put_irqrestore(&mc_list_lock, flags);
}

static void rt_ip_mc_down(struct rtnet_device *rtdev)
{
    struct rtip_mc_list *i;
    unsigned long flags;

    if (rtdev->flags & IFF_LOOPBACK)
	return;

restart:
    rtdm_lock_get_irqsave(&mc_list_lock, flags);
    for (i = mc_list; i; i = i->next) {
	if (i->interface != rtdev || i->state == RTIP_MC_NON_MEMBER)
	    continue;
	rtdm_lock_put_irqrestore(&mc_list_lock, flags);

	igmp_group_dropped(i);
	goto restart;
    }
    rtdm_lock_put_irqrestore(&mc_list_lock, flags);

    rt_ip_mc_dec_group(rtdev, IGMP_ALL_HOSTS);
}

static void rt_ip_mc_up(struct rtnet_device *rtdev,
			struct rtnet_core_cmd *up_cmd)
{
    struct rtip_mc_list *i;
    unsigned long flags;

    if (rtdev->flags & IFF_LOOPBACK)
	return;

    rt_ip_mc_inc_group(rtdev, IGMP_ALL_HOSTS);

restart:
    rtdm_lock_get_irqsave(&mc_list_lock, flags);
    for (i = mc_list; i; i = i->next) {
	if (i->interface != rtdev || i->state != RTIP_MC_NON_MEMBER)
	    continue;
	rtdm_lock_put_irqrestore(&mc_list_lock, flags);

	igmp_group_added(i);
	goto restart;
    }
    rtdm_lock_put_irqrestore(&mc_list_lock, flags);
}

static struct rtdev_event_hook rtdev_hook = {
	.unregister_device = rt_ip_mc_unregister,
	.ifup = rt_ip_mc_up,
	.ifdown = rt_ip_mc_down,
};

void __init rt_igmp_init(void)
{
	unsigned int skbs;

	igmp_socket.protocol = IPPROTO_IGMP;
	igmp_socket.prot.inet.tos = 0;
	igmp_socket.priority = 0;
	rtdm_lock_init(&mc_list_lock);
	rtdm_mutex_init(&mc_socklist_lock);
	/* create the rtskb pool */
	skbs = rtskb_pool_init(&igmp_socket.skb_pool, IGMP_REPLY_POOL_SIZE,
			NULL, NULL);
	if (skbs < IGMP_REPLY_POOL_SIZE)
		printk("RTnet: allocated only %d igmp rtskbs\n", skbs);

	rt_inet_add_protocol(&igmp_protocol);
	rtdm_task_init(&rtnet_igmp_task, "igmp", process, 0,
		       RTDM_TASK_LOWEST_PRIORITY, 10000000);
	rtdev_add_event_hook(&rtdev_hook);
}

void rt_igmp_release(void)
{
	rtdev_del_event_hook(&rtdev_hook);
	rtdm_task_destroy(&rtnet_igmp_task);
	rt_inet_del_protocol(&igmp_protocol);
	rtskb_pool_release(&igmp_socket.skb_pool);
	rtdm_mutex_destroy(&mc_socklist_lock);
}
