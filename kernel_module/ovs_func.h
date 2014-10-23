#ifndef __OVS_FUNC_H__
#define __OVS_FUNC_H__

#include <linux/kallsyms.h>

#include "ovs/flow.h"
#include "ovs/flow_table.h"
#include "ovs/vport.h"
#include "ovs/datapath.h"

#define ovs_flow_extract (*ovs_flow_extract_hi)
#define ovs_flow_tbl_lookup_stats (*ovs_flow_tbl_lookup_stats_hi)
#define ovs_dp_upcall (*ovs_dp_upcall_hi)
#define ovs_flow_stats_update (*ovs_flow_stats_update_hi)
#define ovs_execute_actions (*ovs_execute_actions_hi)

extern int (*ovs_flow_extract_hi)(struct sk_buff *, u16, struct sw_flow_key *);
extern struct sw_flow* (*ovs_flow_tbl_lookup_stats_hi)(struct flow_table*, const struct sw_flow_key*, u32*);
extern int (*ovs_dp_upcall_hi)(struct datapath*, struct sk_buff*, const struct dp_upcall_info*);
extern void (*ovs_flow_stats_update_hi)(struct sw_flow *, __be16 tcp_flags, struct sk_buff *);
extern int (*ovs_execute_actions_hi)(struct datapath*, struct sk_buff*);

void ovs_dp_process_received_packet_hi(struct vport *p, struct sk_buff *skb);
int init_ovs_func(void);

#endif
