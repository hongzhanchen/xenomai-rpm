/*
 * VLAN		An implementation of 802.1Q VLAN tagging.
 *
 * Authors:	Ben Greear <greearb@candelatech.com>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 */
#ifndef _RTNET_IF_VLAN_H_
#define _RTNET_IF_VLAN_H_

#include <rtdev.h>
#include <rtskb.h>
#include <uapi/linux/if_vlan.h>
#include <linux/if_vlan.h>

/* found in socket.c */
extern void rtvlan_ioctl_set(int (*hook)(struct net *, void __user *));

static inline bool is_rtvlan_dev(struct rtnet_device *dev)
{
	return !!(dev->priv_flags & IFF_802_1Q_VLAN);
}

struct rtvlan_pcpu_stats {
	u64			rx_packets;
	u64			rx_bytes;
	u64			rx_multicast;
	u64			tx_packets;
	u64			tx_bytes;
	seqcount_t		syncp;
	u32			rx_errors;
	u32			tx_dropped;
};

struct rtvlan_dev_priv {
	unsigned int				nr_ingress_mappings;
	u32					ingress_priority_map[8];
	unsigned int				nr_egress_mappings;
	struct vlan_priority_tci_mapping	*egress_priority_map[16];

	__be16					vlan_proto;
	u16					vlan_id;
	u16					flags;

	struct rtnet_device			*real_dev;
	unsigned char				real_dev_addr[ETH_ALEN];

	struct rtvlan_pcpu_stats __percpu	*vlan_pcpu_stats;
	struct net_device_stats			stats;
	unsigned int				nest_level;
};

static inline struct rtvlan_dev_priv *rtvlan_dev_priv(const struct rtnet_device *dev)
{
	return dev->priv;
}

static inline u16
rtvlan_dev_get_egress_qos_mask(struct rtnet_device *dev, u32 skprio)
{
	struct vlan_priority_tci_mapping *mp;

	smp_rmb(); /* coupled with smp_wmb() in rtvlan_dev_set_egress_priority() */

	mp = rtvlan_dev_priv(dev)->egress_priority_map[(skprio & 0xF)];
	while (mp) {
		if (mp->priority == skprio) {
			return mp->vlan_qos; /* This should already be shifted
					      * to mask correctly with the
					      * VLAN's TCI */
		}
		mp = mp->next;
	}
	return 0;
}

static inline void
rtvlan_insert_tag(struct rtskb *skb, __be16 vlan_proto, u16 vlan_tci)
{
	struct vlan_ethhdr *veth;

	veth = (struct vlan_ethhdr *)rtskb_push(skb, VLAN_HLEN);

	/* Move the mac addresses to the beginning of the new header. */
	memmove(skb->data, skb->data + VLAN_HLEN, 2 * ETH_ALEN);

	/* first, the ethernet type */
	veth->h_vlan_proto = vlan_proto;

	/* now, the TCI */
	veth->h_vlan_TCI = htons(vlan_tci);
}

static inline void
rtvlan_put_tag(struct rtskb *skb, __be16 vlan_proto, u16 vlan_tci)
{
	rtvlan_insert_tag(skb, vlan_proto, vlan_tci);
	skb->protocol = vlan_proto;
}

#endif /* !(_RTNET_IF_VLAN_H_) */
