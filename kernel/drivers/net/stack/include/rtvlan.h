#ifndef RTNET_RTVLAN_H
#define RTNET_RTVLAN_H

#ifdef CONFIG_XENO_DRIVERS_NET_VLAN
void rtvlan_proto_init(void);

void rtvlan_proto_release(void);

int rtvlan_ioctl_handler(void __user *arg);
#else
static inline void rtvlan_proto_init(void)
{
}

static inline void rtvlan_proto_release(void)
{
}

static inline int rtvlan_ioctl_handler(void __user *arg)
{
	return -ENOSYS;
}
#endif

#endif /* RTNET_RTVLAN_H */
