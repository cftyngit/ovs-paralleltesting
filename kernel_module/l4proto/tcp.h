#ifndef __L4PROTO_TCP_H__
#define __L4PROTO_TCP_H__

#include <linux/skbuff.h>
#include <net/tcp.h>
#include "../common.h"
#include "../connect_state.h"

#define FAKE_SEQ 4321

int modify_tcp_header( struct sk_buff* skb_mod, union my_ip_type ip, u16 client_port );
int respond_tcp_syn_ack(const struct sk_buff* skb, struct net_device* netdev);

#endif