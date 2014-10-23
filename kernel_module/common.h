#ifndef __COMMON_H__
#define __COMMON_H__

#include <linux/version.h>
#include <linux/etherdevice.h>

#include "ovs_func.h"

union my_ip_type
{
    unsigned char c[4];
    unsigned int i;
};

struct host_info
{
    union my_ip_type ip;
    unsigned char mac[6];
};

struct connection_info
{
    union my_ip_type ip;
    u16 port;
    u8 proto;
};

int pd_modify_ip_mac ( struct sk_buff* skb_mod );
void send_skbmod ( struct vport *p, struct sk_buff *skb_mod );
void print_skb(struct sk_buff *skb);

#define CAUSE_BY_RMHOST 0
#define CAUSE_BY_MIRROR 1
#define CAUSE_BY_RETRAN 2

#endif