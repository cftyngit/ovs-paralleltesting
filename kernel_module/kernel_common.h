#ifndef __KERNEL_COMMON_H__
#define __KERNEL_COMMON_H__

#include <linux/version.h>
#include <linux/etherdevice.h>

#include "ovs_func.h"

#include "../commom.h"

#if DEBUG==1
#define PRINT_DEBUG(str, ...)	do {printk(KERN_DEBUG str, ##__VA_ARGS__);} while (0)
#else
#define PRINT_DEBUG(str, ...)	do {} while (0)
#endif

#if INFO==1
#define PRINT_INFO(str, ...)	do {printk(KERN_INFO str, ##__VA_ARGS__);} while (0)
#else
#define PRINT_INFO(str, ...)	do {} while (0)
#endif

#if NOERR==1
#define PRINT_ERROR(str, ...)	do {printk(KERN_ERR str, ##__VA_ARGS__);} while (0)
#else
#define PRINT_ERROR(str, ...)	do {} while (0)
#endif

extern struct host_info server;
extern struct host_info mirror;

int pd_modify_ip_mac ( struct sk_buff* skb_mod );
void send_skbmod ( struct vport *p, struct sk_buff *skb_mod );
void vport_send_skmod ( struct vport *p, struct sk_buff *skb_mod );
void print_skb(struct sk_buff *skb);

#define CAUSE_BY_RMHOST 0
#define CAUSE_BY_MIRROR 1
#define CAUSE_BY_RETRAN 2

#endif
