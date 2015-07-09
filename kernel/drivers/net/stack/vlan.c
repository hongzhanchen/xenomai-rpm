/*
 * INET		802.1Q VLAN
 *		Ethernet-type device handling.
 *
 * Authors:	Ben Greear <greearb@candelatech.com>
 *		Please send support related email to: netdev@vger.kernel.org
 *		VLAN Home Page: http://www.candelatech.com/~greear/vlan.html
 *
 * Fixes:
 *		Fix for packet capture - Nick Eggleston <nick@dccinc.com>;
 *		Add HW acceleration hooks - David S. Miller <davem@redhat.com>;
 *		Correct all the locking - David S. Miller <davem@redhat.com>;
 *		Use hash table for VLAN groups - David S. Miller <davem@redhat.com>
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 */

#include <linux/module.h>
#include <linux/slab.h>

#include <rtdev.h>
#include <rtnet_port.h>
#include <rtif_vlan.h>

static unsigned short rtvlan_name_type = VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD;

struct rtnet_device *__rtdev_real_dev(struct rtnet_device *dev)
{
	if (is_rtvlan_dev(dev))
		dev = rtvlan_dev_priv(dev)->real_dev;

	return dev;
}
EXPORT_SYMBOL_GPL(__rtdev_real_dev);

static inline u16 rtvlan_dev_vlan_id(const struct rtnet_device *dev)
{
	return rtvlan_dev_priv(dev)->vlan_id;
}

static void vlan_dev_set_rx_mode(struct rtnet_device *vlan_dev)
{
	struct rtvlan_dev_priv *vlan = rtvlan_dev_priv(vlan_dev);
	struct rtnet_device *real_dev = vlan->real_dev;

	rt_dev_mc_upload(real_dev);
}

/*
 *	Create the VLAN header for an arbitrary protocol layer
 *
 *	saddr=NULL	means use device source address
 *	daddr=NULL	means leave destination address (eg unresolved arp)
 *
 *  This is called when the SKB is moving down the stack towards the
 *  physical devices.
 */
static int vlan_dev_hard_header(struct rtskb *skb, struct rtnet_device *dev,
				unsigned short type,
				void *daddr, void *saddr,
				unsigned int len)
{
	struct rtvlan_dev_priv *vlan = rtvlan_dev_priv(dev);
	struct vlan_hdr *vhdr;
	unsigned int vhdrlen = 0;
	u16 vlan_tci = 0;
	int rc;

	if (!(vlan->flags & VLAN_FLAG_REORDER_HDR)) {
		vhdr = (struct vlan_hdr *) rtskb_push(skb, VLAN_HLEN);

		vlan_tci = vlan->vlan_id;
		vlan_tci |= rtvlan_dev_get_egress_qos_mask(dev, skb->priority);
		vhdr->h_vlan_TCI = htons(vlan_tci);

		/*
		 *  Set the protocol type. For a packet of type ETH_P_802_3/2 we
		 *  put the length in here instead.
		 */
		if (type != ETH_P_802_3 && type != ETH_P_802_2)
			vhdr->h_vlan_encapsulated_proto = htons(type);
		else
			vhdr->h_vlan_encapsulated_proto = htons(len);

		skb->protocol = vlan->vlan_proto;
		type = ntohs(vlan->vlan_proto);
		vhdrlen = VLAN_HLEN;
	}

	/* Before delegating work to the lower layer, enter our MAC-address */
	if (saddr == NULL)
		saddr = dev->dev_addr;

	/* Now make the underlying real hard header */
	dev = vlan->real_dev;
	rc = dev->hard_header(skb, dev, type, daddr, saddr, len + vhdrlen);
	if (rc > 0)
		rc += vhdrlen;
	return rc;
}

static netdev_tx_t vlan_dev_hard_start_xmit(struct rtskb *skb,
					    struct rtnet_device *dev)
{
	struct rtvlan_dev_priv *vlan = rtvlan_dev_priv(dev);
	struct vlan_ethhdr *veth = (struct vlan_ethhdr *)skb->data;
	struct rtnet_device *real_dev = vlan->real_dev;
	unsigned int len;
	int ret;

	/* Handle non-VLAN frames if they are sent to us, for example by DHCP.
	 *
	 * NOTE: THIS ASSUMES DIX ETHERNET, SPECIFICALLY NOT SUPPORTING
	 * OTHER THINGS LIKE FDDI/TokenRing/802.3 SNAPs...
	 */
	if (veth->h_vlan_proto != vlan->vlan_proto ||
		(vlan->flags & VLAN_FLAG_REORDER_HDR)) {
		u16 vlan_tci;
		vlan_tci = vlan->vlan_id;
		vlan_tci |= rtvlan_dev_get_egress_qos_mask(dev, skb->priority);
		rtvlan_put_tag(skb, vlan->vlan_proto, vlan_tci);
	}

	skb->rtdev = real_dev;
	len = skb->len;

	ret = real_dev->start_xmit(skb, real_dev);

	if (likely(ret == 0)) {
		struct rtvlan_pcpu_stats *stats;

		stats = this_cpu_ptr(vlan->vlan_pcpu_stats);
		raw_write_seqcount_begin(&stats->syncp);
		stats->tx_packets++;
		stats->tx_bytes += len;
		raw_write_seqcount_end(&stats->syncp);
	} else {
		this_cpu_inc(vlan->vlan_pcpu_stats->tx_dropped);
	}

	return ret;
}

void vlan_dev_set_ingress_priority(const struct rtnet_device *dev,
				   u32 skb_prio, u16 vlan_prio)
{
	struct rtvlan_dev_priv *vlan = rtvlan_dev_priv(dev);

	if (vlan->ingress_priority_map[vlan_prio & 0x7] && !skb_prio)
		vlan->nr_ingress_mappings--;
	else if (!vlan->ingress_priority_map[vlan_prio & 0x7] && skb_prio)
		vlan->nr_ingress_mappings++;

	vlan->ingress_priority_map[vlan_prio & 0x7] = skb_prio;
}

int vlan_dev_set_egress_priority(const struct rtnet_device *dev,
				 u32 skb_prio, u16 vlan_prio)
{
	struct rtvlan_dev_priv *vlan = rtvlan_dev_priv(dev);
	struct vlan_priority_tci_mapping *mp = NULL;
	struct vlan_priority_tci_mapping *np;
	u32 vlan_qos = (vlan_prio << VLAN_PRIO_SHIFT) & VLAN_PRIO_MASK;

	/* See if a priority mapping exists.. */
	mp = vlan->egress_priority_map[skb_prio & 0xF];
	while (mp) {
		if (mp->priority == skb_prio) {
			if (mp->vlan_qos && !vlan_qos)
				vlan->nr_egress_mappings--;
			else if (!mp->vlan_qos && vlan_qos)
				vlan->nr_egress_mappings++;
			mp->vlan_qos = vlan_qos;
			return 0;
		}
		mp = mp->next;
	}

	/* Create a new mapping then. */
	mp = vlan->egress_priority_map[skb_prio & 0xF];
	np = kmalloc(sizeof(struct vlan_priority_tci_mapping), GFP_KERNEL);
	if (!np)
		return -ENOBUFS;

	np->next = mp;
	np->priority = skb_prio;
	np->vlan_qos = vlan_qos;
	/* Before inserting this element in hash table, make sure all its fields
	 * are committed to memory.
	 * coupled with smp_rmb() in vlan_dev_get_egress_qos_mask()
	 */
	smp_wmb();
	vlan->egress_priority_map[skb_prio & 0xF] = np;
	if (vlan_qos)
		vlan->nr_egress_mappings++;
	return 0;
}

static inline u32 vlan_get_ingress_priority(struct rtnet_device *dev,
					    u16 vlan_tci)
{
	struct rtvlan_dev_priv *vip = rtvlan_dev_priv(dev);

	return vip->ingress_priority_map[(vlan_tci >> VLAN_PRIO_SHIFT) & 0x7];
}

/* Flags are defined in the vlan_flags enum in include/linux/if_vlan.h file. */
static int
vlan_dev_change_flags(const struct rtnet_device *dev, u32 flags, u32 mask)
{
	struct rtvlan_dev_priv *vlan = rtvlan_dev_priv(dev);
	u32 old_flags = vlan->flags;

	if (mask & ~(VLAN_FLAG_REORDER_HDR | VLAN_FLAG_LOOSE_BINDING))
		return -EINVAL;

	vlan->flags = (old_flags & ~mask) | (flags & mask);

	return 0;
}

static void
vlan_dev_get_realdev_name(const struct rtnet_device *dev, char *result)
{
	strncpy(result, rtvlan_dev_priv(dev)->real_dev->name, 23);
}

static int vlan_dev_open(struct rtnet_device *dev)
{
	struct rtvlan_dev_priv *vlan = rtvlan_dev_priv(dev);
	struct rtnet_device *real_dev = vlan->real_dev;

	if (!(real_dev->flags & IFF_UP) &&
	    !(vlan->flags & VLAN_FLAG_LOOSE_BINDING))
		return -ENETDOWN;

	ether_addr_copy(vlan->real_dev_addr, real_dev->dev_addr);

	vlan_dev_set_rx_mode(dev);

	if (rtnetif_carrier_ok(real_dev))
		rtnetif_carrier_on(dev);
	return 0;
}

static int vlan_dev_stop(struct rtnet_device *dev)
{
	rtnetif_carrier_off(dev);
	return 0;
}

static struct net_device_stats *vlan_dev_get_stats(struct rtnet_device *dev)
{
	struct rtvlan_dev_priv *vlan = rtvlan_dev_priv(dev);
	struct net_device_stats *stats = &vlan->stats;

	memset(stats, '\0', sizeof(*stats));

	if (rtvlan_dev_priv(dev)->vlan_pcpu_stats) {
		struct rtvlan_pcpu_stats *p;
		u32 rx_errors = 0, tx_dropped = 0;
		int i;

		for_each_possible_cpu(i) {
			u64 rxpackets, rxbytes, rxmulticast, txpackets, txbytes;
			unsigned int start;

			p = per_cpu_ptr(rtvlan_dev_priv(dev)->vlan_pcpu_stats, i);
			do {
				start = raw_seqcount_begin(&p->syncp);
				rxpackets	= p->rx_packets;
				rxbytes		= p->rx_bytes;
				rxmulticast	= p->rx_multicast;
				txpackets	= p->tx_packets;
				txbytes		= p->tx_bytes;
			} while (read_seqcount_retry(&p->syncp, start));

			stats->rx_packets	+= rxpackets;
			stats->rx_bytes		+= rxbytes;
			stats->multicast	+= rxmulticast;
			stats->tx_packets	+= txpackets;
			stats->tx_bytes		+= txbytes;
			/* rx_errors & tx_dropped are u32 */
			rx_errors	+= p->rx_errors;
			tx_dropped	+= p->tx_dropped;
		}
		stats->rx_errors  = rx_errors;
		stats->tx_dropped = tx_dropped;
	}
	return stats;
}

static int vlan_dev_init(struct rtnet_device *dev)
{
	struct rtvlan_dev_priv *vlan = rtvlan_dev_priv(dev);
	struct rtnet_device *real_dev = vlan->real_dev;
	int i;

	rtnetif_carrier_off(dev);

	/* IFF_BROADCAST|IFF_MULTICAST; ??? */
	dev->flags  = real_dev->flags & ~(IFF_UP | IFF_PROMISC | IFF_ALLMULTI
					| IFF_MASTER | IFF_SLAVE);
	dev->link_state	 =
		(real_dev->link_state & (1<<__RTNET_LINK_STATE_NOCARRIER)) |
		(1<<__RTNET_LINK_STATE_PRESENT);

	dev->features = NETIF_F_LLTX;

	if (is_zero_ether_addr(dev->dev_addr))
		ether_addr_copy(dev->dev_addr, real_dev->dev_addr);;
	if (is_zero_ether_addr(dev->broadcast))
		memcpy(dev->broadcast, real_dev->broadcast, dev->addr_len);

	dev->open = vlan_dev_open;
	dev->stop = vlan_dev_stop;
	dev->hard_header_len = real_dev->hard_header_len + VLAN_HLEN;
	dev->hard_header = vlan_dev_hard_header;
	dev->hard_start_xmit = vlan_dev_hard_start_xmit;
	dev->get_stats = vlan_dev_get_stats;
	if (real_dev->set_multicast_list)
		dev->set_multicast_list = vlan_dev_set_rx_mode;

	vlan->vlan_pcpu_stats = alloc_percpu(typeof(*vlan->vlan_pcpu_stats));
	if (!rtvlan_dev_priv(dev)->vlan_pcpu_stats)
		return -ENOMEM;

	for_each_possible_cpu(i) {
		struct rtvlan_pcpu_stats *vlan_stat;
		vlan_stat = per_cpu_ptr(vlan->vlan_pcpu_stats, i);
		seqcount_init(&vlan_stat->syncp);
	}

	return 0;
}

static void vlan_dev_uninit(struct rtnet_device *dev)
{
	struct vlan_priority_tci_mapping *pm;
	struct rtvlan_dev_priv *vlan = rtvlan_dev_priv(dev);
	int i;

	for (i = 0; i < ARRAY_SIZE(vlan->egress_priority_map); i++) {
		while ((pm = vlan->egress_priority_map[i]) != NULL) {
			vlan->egress_priority_map[i] = pm->next;
			kfree(pm);
		}
	}
}

static void vlan_dev_free(struct rtnet_device *dev)
{
	struct rtvlan_dev_priv *vlan = rtvlan_dev_priv(dev);

	vlan_dev_uninit(dev);
	free_percpu(vlan->vlan_pcpu_stats);
	vlan->vlan_pcpu_stats = NULL;
	rt_unregister_rtnetdev(dev);
	rt_rtdev_disconnect(dev);
	rtdev_free(dev);
}

static bool vlan_hw_filter_capable(const struct rtnet_device *dev)
{
	return !!(dev->features & NETIF_F_HW_VLAN_CTAG_FILTER);
}

static struct rtnet_device *__rtvlan_find_dev(struct rtnet_device *dev, u16 vid)
{
	struct rtnet_device *vlan_dev;

	if (vid == 0)
		return dev;

	list_for_each_entry(vlan_dev, &dev->vlan_link, vlan_link) {
		struct rtvlan_dev_priv *vlan = rtvlan_dev_priv(vlan_dev);

		if (vlan->vlan_id == vid)
			return vlan_dev;
	}

	return NULL;
}

static struct rtnet_device *rtvlan_find_dev(struct rtnet_device *dev, u16 vid)
{
	struct rtnet_device *vlan_dev;
	unsigned long flags;

	rtdm_lock_get_irqsave(&dev->rtdev_lock, flags);
	vlan_dev = __rtvlan_find_dev(dev, vid);
	if (vlan_dev)
		rtdev_reference(vlan_dev);
	rtdm_lock_put_irqrestore(&dev->rtdev_lock, flags);

	return vlan_dev;
}

static int rtvlan_vid_add(struct rtnet_device *dev)
{
	struct rtvlan_dev_priv *vlan = rtvlan_dev_priv(dev);
	struct rtnet_device *real_dev = vlan->real_dev;
	u16 vid = vlan->vlan_id;
	unsigned long flags;
	int err = 0;

	rtdm_lock_get_irqsave(&dev->rtdev_lock, flags);
	if (__rtvlan_find_dev(real_dev, vid)) {
		err = -EEXIST;
		goto out;
	}

	list_add(&dev->vlan_link, &real_dev->vlan_link);

	if (vlan_hw_filter_capable(real_dev))
		real_dev->vlan_rx_add_vid(real_dev, vid);
  out:
	rtdm_lock_put_irqrestore(&dev->rtdev_lock, flags);

	return err;
}

static void rtvlan_vid_del(struct rtnet_device *dev)
{
	struct rtvlan_dev_priv *vlan = rtvlan_dev_priv(dev);
	struct rtnet_device *real_dev = vlan->real_dev;
	u16 vid = vlan->vlan_id;
	unsigned long flags;

	rtdm_lock_get_irqsave(&dev->rtdev_lock, flags);
	if (__rtvlan_find_dev(real_dev, vid) != dev)
		goto out;

	list_del(&dev->vlan_link);

	if (vlan_hw_filter_capable(real_dev))
		real_dev->vlan_rx_kill_vid(real_dev, vid);
  out:
	rtdm_lock_put_irqrestore(&dev->rtdev_lock, flags);
}

void unregister_vlan_dev(struct rtnet_device *dev)
{
	struct rtvlan_dev_priv *vlan = rtvlan_dev_priv(dev);
	struct rtnet_device *real_dev = vlan->real_dev;
	u16 vlan_id = vlan->vlan_id;

	if (vlan_id)
		rtvlan_vid_del(dev);

	/* Get rid of the vlan's reference to real_dev */
	rtdev_dereference(real_dev);
	vlan_dev_free(dev);
}


/*  Attach a VLAN device to a mac address (ie Ethernet Card).
 *  Returns 0 if the device was created or a negative error code otherwise.
 */
static int register_vlan_device(struct rtnet_device *real_dev, u16 vlan_id)
{
	struct rtnet_device *new_dev;
	struct rtvlan_dev_priv *vlan;
	char name[IFNAMSIZ];
	int err;

	if (vlan_id >= VLAN_VID_MASK)
		return -ERANGE;

	/* Gotta set up the fields for the device.
	   Only one type of device name supported
	 */
	switch (rtvlan_name_type) {
	case VLAN_NAME_TYPE_RAW_PLUS_VID:
		/* name will look like:	 eth1.0005 */
		snprintf(name, IFNAMSIZ, "%s.%.4i", real_dev->name, vlan_id);
		break;
	case VLAN_NAME_TYPE_PLUS_VID_NO_PAD:
		/* Put our vlan.VID in the name.
		 * Name will look like:	 vlan5
		 */
		snprintf(name, IFNAMSIZ, "rtvlan%i", vlan_id);
		break;
	case VLAN_NAME_TYPE_RAW_PLUS_VID_NO_PAD:
		/* Put our vlan.VID in the name.
		 * Name will look like:	 eth0.5
		 */
		snprintf(name, IFNAMSIZ, "%s.%i", real_dev->name, vlan_id);
		break;
	case VLAN_NAME_TYPE_PLUS_VID:
		/* Put our vlan.VID in the name.
		 * Name will look like:	 vlan0005
		 */
	default:
		snprintf(name, IFNAMSIZ, "rtvlan%.4i", vlan_id);
	}

	rtdev_reference(real_dev);

	new_dev = rt_alloc_etherdev(sizeof(struct rtvlan_dev_priv), 0);
	if (new_dev == NULL) {
		err = -ENOBUFS;
		goto err;
	}
	rtdev_alloc_name(new_dev, name);
	rt_rtdev_connect(new_dev, &RTDEV_manager);
	new_dev->vers = RTDEV_VERS_2_0;

	new_dev->priv_flags |= IFF_802_1Q_VLAN;
	new_dev->priv_flags &= ~(IFF_XMIT_DST_RELEASE | IFF_TX_SKB_SHARING);

	memset(new_dev->broadcast, 0, ETH_ALEN);

	/* need 4 bytes for extra VLAN header info,
	 * hope the underlying device can handle it.
	 */
	new_dev->mtu = real_dev->mtu;
	new_dev->priv_flags |= (real_dev->priv_flags & IFF_UNICAST_FLT);

	vlan = rtvlan_dev_priv(new_dev);
	vlan->vlan_proto = htons(ETH_P_8021Q);
	vlan->vlan_id = vlan_id;
	vlan->real_dev = real_dev;
	vlan->flags = VLAN_FLAG_REORDER_HDR;

	err = vlan_dev_init(new_dev);
	if (err < 0)
		goto out_free_newdev;

	err = rtvlan_vid_add(new_dev);
	if (err < 0)
		goto out_free_newdev;

	err = rt_register_rtnetdev(new_dev);
	if (err > 0) {
		err = -err;
		goto out_free_newdev;
	}

	return 0;

out_free_newdev:
	rt_rtdev_disconnect(new_dev);
	rtdev_free(new_dev);
  err:
	rtdev_dereference(real_dev);
	return err;
}

/*
 *	VLAN IOCTL handler.
 *	o execute requested action or pass command to the device driver
 *   arg is really a struct vlan_ioctl_args __user *.
 */
int rtvlan_ioctl_handler(void __user *arg)
{
	int err;
	struct vlan_ioctl_args args;
	struct rtnet_device *dev = NULL;

	if (copy_from_user(&args, arg, sizeof(args)))
		return -EFAULT;

	/* Null terminate this sucker, just in case. */
	args.device1[23] = 0;
	args.u.device2[23] = 0;

	switch (args.cmd) {
	case SET_VLAN_INGRESS_PRIORITY_CMD:
	case SET_VLAN_EGRESS_PRIORITY_CMD:
	case SET_VLAN_FLAG_CMD:
	case ADD_VLAN_CMD:
	case DEL_VLAN_CMD:
	case GET_VLAN_REALDEV_NAME_CMD:
	case GET_VLAN_VID_CMD:
		err = -ENODEV;
		dev = rtdev_get_by_name(args.device1);
		if (!dev)
			goto out;

		err = -EINVAL;
		if (args.cmd != ADD_VLAN_CMD && !is_rtvlan_dev(dev))
			goto out;
	}

	switch (args.cmd) {
	case SET_VLAN_INGRESS_PRIORITY_CMD:
		err = -EPERM;
		vlan_dev_set_ingress_priority(dev,
					      args.u.skb_priority,
					      args.vlan_qos);
		err = 0;
		break;

	case SET_VLAN_EGRESS_PRIORITY_CMD:
		err = -EPERM;
		err = vlan_dev_set_egress_priority(dev,
						   args.u.skb_priority,
						   args.vlan_qos);
		break;

	case SET_VLAN_FLAG_CMD:
		err = -EPERM;
		err = vlan_dev_change_flags(dev,
					    args.vlan_qos ? args.u.flag : 0,
					    args.u.flag);
		break;

	case SET_VLAN_NAME_TYPE_CMD:
		err = -EPERM;
		if ((args.u.name_type >= 0) &&
		    (args.u.name_type < VLAN_NAME_TYPE_HIGHEST)) {
			rtvlan_name_type = args.u.name_type;
			err = 0;
		} else {
			err = -EINVAL;
		}
		break;

	case ADD_VLAN_CMD:
		err = -EPERM;
		err = register_vlan_device(dev, args.u.VID);
		break;

	case DEL_VLAN_CMD:
		err = -EPERM;
		rtdev_dereference(dev); /*
					 * Must dereference before unregistering
					 * in order to avoid infinite loop in
					 * rt_unregister_rtnetdev
					 */
		unregister_vlan_dev(dev);
		return 0;

	case GET_VLAN_REALDEV_NAME_CMD:
		err = 0;
		vlan_dev_get_realdev_name(dev, args.u.device2);
		if (copy_to_user(arg, &args,
				 sizeof(struct vlan_ioctl_args)))
			err = -EFAULT;
		break;

	case GET_VLAN_VID_CMD:
		err = 0;
		args.u.VID = rtvlan_dev_vlan_id(dev);
		if (copy_to_user(arg, &args,
				 sizeof(struct vlan_ioctl_args)))
		      err = -EFAULT;
		break;

	default:
		err = -EOPNOTSUPP;
		break;
	}
out:
	if (dev)
		rtdev_dereference(dev);

	return err;
}

int rtvlan_proto_rx(struct rtskb *skb, struct rtpacket_type *pt)
{
	struct vlan_ethhdr *veth = (struct vlan_ethhdr *)skb->mac.raw;
	struct rtvlan_pcpu_stats *rx_stats;
	struct rtnet_device *vlan_dev;
	struct rtvlan_dev_priv *vlan;
	u16 vlan_tci;

	vlan_tci = ntohs(veth->h_vlan_TCI);
	vlan_dev = rtvlan_find_dev(skb->rtdev, vlan_tci & VLAN_VID_MASK);
	if (!vlan_dev) {
		kfree_rtskb(skb);
		rtdev_dereference(skb->rtdev);
		return 0;
	}
	vlan = rtvlan_dev_priv(vlan_dev);

	skb->priority = vlan_get_ingress_priority(vlan_dev, vlan_tci);
	skb->protocol = veth->h_vlan_encapsulated_proto;
	skb->rtdev = vlan_dev;

	if (skb->pkt_type == PACKET_OTHERHOST
		&& ether_addr_equal(veth->h_dest, vlan_dev->dev_addr))
		skb->pkt_type = PACKET_HOST;

	if (vlan->flags & VLAN_FLAG_REORDER_HDR) {
		memmove(skb->mac.raw + VLAN_HLEN, skb->mac.raw, 2 * ETH_ALEN);
#ifdef CONFIG_XENO_DRIVERS_NET_ADDON_RTCAP
		skb->cap_start += VLAN_HLEN;
		skb->cap_len -= VLAN_HLEN;
#endif
	}
	rtskb_pull(skb, VLAN_HLEN);

	rx_stats = this_cpu_ptr(rtvlan_dev_priv(vlan_dev)->vlan_pcpu_stats);

	raw_write_seqcount_begin(&rx_stats->syncp);
	rx_stats->rx_packets++;
	rx_stats->rx_bytes += skb->len;
	if (skb->pkt_type == PACKET_MULTICAST)
		rx_stats->rx_multicast++;
	raw_write_seqcount_end(&rx_stats->syncp);

	rt_stack_deliver(skb);
	return 0;
}

struct rtpacket_type rtvlan_packet_type = {
	.type = __constant_htons(ETH_P_8021Q),
	.handler = rtvlan_proto_rx,
};

void rtvlan_proto_init(void)
{
	rtdev_add_pack(&rtvlan_packet_type);
}

void rtvlan_proto_release(void)
{
	rtdev_remove_pack(&rtvlan_packet_type);
}
