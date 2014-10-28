#ifndef __KERNEL_COMMON_H__
#define __KERNEL_COMMON_H__

#include <linux/version.h>
#include <linux/etherdevice.h>

#include "ovs_func.h"
#include "ovs/datapath.h"
#include "../commom.h"

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
