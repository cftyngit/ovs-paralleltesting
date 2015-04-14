#ifndef PACK_DISPATCHER_H_
#define PACK_DISPATCHER_H_

#include <linux/slab.h>
#include <linux/slub_def.h>
#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/vmalloc.h>
#include <linux/kernel.h>
#include <linux/radix-tree.h>
#include <uapi/linux/in.h>

#include "ovs/ovs_func.h"

#define PT_ACTION_CONTINUE 0        /*not IPv4 packet*/
#define PT_ACTION_DROP -1           /*mirror to client*/
#define PT_ACTION_FROM_RMHOST 1
#define PT_ACTION_FROM_TARGET 2
#define PT_ACTION_FROM_MIRROR 3

#include "kernel_common.h"
#include "connect_state.h"
#include "l4proto/tcp.h"
#include "util/compare_buffer.h"
#include "util/packet_buffer.h"
#include "packet_comparer.h"

void init_packet_dispatcher(void);

int pd_check_action(struct sk_buff *skb, struct other_args *arg);

int pd_action_from_mirror(struct sk_buff *skb, struct other_args *arg);
int pd_action_from_client(struct sk_buff *skb, struct other_args *arg);
int pd_action_from_server(struct sk_buff *skb, struct other_args *arg);

#endif


