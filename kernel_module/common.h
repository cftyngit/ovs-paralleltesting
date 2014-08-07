#ifndef __COMMON_H__
#define __COMMON_H__

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

struct buf_data
{
    struct sk_buff* skb;
    struct vport* p;
};

struct playback_args
{
    union my_ip_type ip;
    u16 client_port;
    u8 cause;
};

int pd_modify_ip_mac ( struct sk_buff* skb_mod );
void send_skbmod ( struct vport *p, struct sk_buff *skb_mod );

#endif