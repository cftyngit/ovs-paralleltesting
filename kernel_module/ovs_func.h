#ifndef __OVS_FUNC_H__
#define __OVS_FUNC_H__

#include <linux/kallsyms.h>
#include <linux/skbuff.h>
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
    #include "ovs/3.17.2/datapath.h"
    #define ovs_vport_find_upcall_portid(p, skb) (*ovs_vport_find_upcall_portid_hi)(p, skb)
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
    #include "ovs/3.16.3/datapath.h"
    #define ovs_vport_find_upcall_portid(p, skb) (p->upcall_portid)
#else
    #include "ovs/3.14.24/datapath.h"
    #define ovs_vport_find_upcall_portid(p, skb) (p->upcall_portid)
#endif

#define ovs_flow_extract (*ovs_flow_extract_hi)
#define ovs_flow_tbl_lookup_stats (*ovs_flow_tbl_lookup_stats_hi)
#define ovs_dp_upcall (*ovs_dp_upcall_hi)
#define ovs_flow_stats_update (*ovs_flow_stats_update_hi)
#define ovs_execute_actions (*ovs_execute_actions_hi)
#define ovs_vport_send (*ovs_vport_send_hi)
#define ovs_lookup_vport (*ovs_lookup_vport_hi)

extern int (*ovs_flow_extract_hi)(struct sk_buff *, u16, struct sw_flow_key *);
extern struct sw_flow* (*ovs_flow_tbl_lookup_stats_hi)(struct flow_table*, const struct sw_flow_key*, u32*);
extern int (*ovs_dp_upcall_hi)(struct datapath*, struct sk_buff*, const struct dp_upcall_info*);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
extern void (*ovs_flow_stats_update_hi)(struct sw_flow *, __be16 tcp_flags, struct sk_buff *);
#else
extern void (*ovs_flow_stats_update_hi)(struct sw_flow*, struct sk_buff*);
#endif
extern int (*ovs_execute_actions_hi)(struct datapath*, struct sk_buff*);
extern struct vport* (*ovs_lookup_vport_hi)(const struct datapath *, u16);
extern int (*ovs_vport_send_hi)(struct vport *, struct sk_buff *);
extern u32 (*ovs_vport_find_upcall_portid_hi)(const struct vport *, struct sk_buff *);

void ovs_dp_process_received_packet_hi(struct vport *p, struct sk_buff *skb);
int init_ovs_func(void);

static inline struct vport *ovs_vport_rcu(const struct datapath *dp, int port_no)
{
    WARN_ON_ONCE(!rcu_read_lock_held());
    return ovs_lookup_vport(dp, port_no);
}
#endif
