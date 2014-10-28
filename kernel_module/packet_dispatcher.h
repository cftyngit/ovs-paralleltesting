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

#include "ovs_func.h"

#define PT_ACTION_CONTINUE 0        /*not IPv4 packet*/
#define PT_ACTION_DROP -1           /*mirror to client*/
#define PT_ACTION_CLIENT_TO_SERVER 1
#define PT_ACTION_SERVER_TO_CLIENT 2

#include "kernel_common.h"
#include "connect_state.h"
#include "l4proto/tcp.h"
#include "util/compare_buffer.h"
#include "util/packet_buffer.h"
#include "packet_comparer.h"

/*union ip
{
    unsigned char c[4];
    unsigned int i;
};*/

void init_packet_dispatcher(void);

int pd_check_action(struct vport *p, struct sk_buff *skb);

int pd_action_from_mirror(struct vport *p, struct sk_buff *skb);
int pd_action_from_client(struct vport *p, struct sk_buff *skb);
int pd_action_from_server(struct vport *p, struct sk_buff *skb);

#endif


