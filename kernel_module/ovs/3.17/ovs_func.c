#include "ovs_func.h"
#include "packet_dispatcher.h"

int (*ovs_flow_extract_hi)(struct sk_buff *, u16, struct sw_flow_key *);
struct sw_flow* (*ovs_flow_tbl_lookup_stats_hi)(struct flow_table*, const struct sw_flow_key*, u32*);
int (*ovs_dp_upcall_hi)(struct datapath*, struct sk_buff*, const struct dp_upcall_info*);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
void (*ovs_flow_stats_update_hi)(struct sw_flow *, __be16 tcp_flags, struct sk_buff *);
#else
void (*ovs_flow_stats_update_hi)(struct sw_flow*, struct sk_buff*);
#endif
int (*ovs_execute_actions_hi)(struct datapath*, struct sk_buff*);
//struct vport* (*ovs_vport_rcu_hi)(const struct datapath *dp, int port_no);
int (*ovs_vport_send_hi)(struct vport *, struct sk_buff *);
struct vport* (*ovs_lookup_vport_hi)(const struct datapath *, u16);
u32 (*ovs_vport_find_upcall_portid_hi)(const struct vport *, struct sk_buff *);

int init_ovs_func()
{
	ovs_flow_extract_hi = (void*)kallsyms_lookup_name("ovs_flow_extract");
	if(ovs_flow_extract_hi == 0)
		return -1;

	ovs_flow_tbl_lookup_stats_hi = (void*)kallsyms_lookup_name("ovs_flow_tbl_lookup_stats");
	if(ovs_flow_tbl_lookup_stats_hi == 0)
		return -1;

	ovs_dp_upcall_hi = (void*)kallsyms_lookup_name("ovs_dp_upcall");
	if(ovs_dp_upcall_hi == 0)
		return -1;

	ovs_flow_stats_update_hi = (void*)kallsyms_lookup_name("ovs_flow_stats_update");
	if(ovs_flow_stats_update_hi == 0)
		return -1;

	ovs_execute_actions_hi = (void*)kallsyms_lookup_name("ovs_execute_actions");
	if(ovs_execute_actions_hi == 0)
		return -1;

	ovs_lookup_vport_hi = (void*)kallsyms_lookup_name("ovs_lookup_vport");
	if(*ovs_lookup_vport_hi == 0)
		return -1;

	ovs_vport_send_hi = (void*)kallsyms_lookup_name("ovs_vport_send");
    if(ovs_vport_send_hi == 0)
        return -1;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,17,0)
    ovs_vport_find_upcall_portid_hi = (void*)kallsyms_lookup_name("ovs_vport_find_upcall_portid");
    if(ovs_vport_find_upcall_portid_hi == 0)
        return -1;
#endif
	return 0;
}

void ovs_dp_process_received_packet_hi(struct vport *p, struct sk_buff *skb)
{
    struct datapath *dp = p->dp;
    struct sw_flow *flow;
    struct dp_stats_percpu *stats;
    struct sw_flow_key key;
    u64 *stats_counter;
    u32 n_mask_hit;
    int error;

    stats = this_cpu_ptr(dp->stats_percpu);

    /* Extract flow from 'skb' into 'key'. */
    error = ovs_flow_extract(skb, p->port_no, &key);
    if (unlikely(error)) {
        kfree_skb(skb);
        return;
    }
    switch(pd_check_action(p, skb))
	{
	case PT_ACTION_FROM_MIRROR:
		pd_action_from_mirror(p, skb);
		consume_skb(skb);
		return;
	case PT_ACTION_FROM_RMHOST:
		pd_action_from_client(p, skb);
		break;
	case PT_ACTION_FROM_TARGET:
		pd_action_from_server(p, skb);
		break;
	case PT_ACTION_CONTINUE:
		break;
	case PT_ACTION_DROP:
		return;
	}
    /* Look up flow. */
    flow = ovs_flow_tbl_lookup_stats(&dp->table, &key, &n_mask_hit);
    if (unlikely(!flow)) {
        struct dp_upcall_info upcall;

        upcall.cmd = OVS_PACKET_CMD_MISS;
        upcall.key = &key;
        upcall.userdata = NULL;
        upcall.portid = ovs_vport_find_upcall_portid(p, skb);
//        PRINT_DEBUG("[%s] upcall port: %u\n", __func__, upcall.portid);
        error = ovs_dp_upcall(dp, skb, &upcall);
        if (unlikely(error))
            kfree_skb(skb);
        else
            consume_skb(skb);
        stats_counter = &stats->n_missed;
        goto out;
    }

    OVS_CB(skb)->flow = flow;
    OVS_CB(skb)->pkt_key = &key;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
    ovs_flow_stats_update(OVS_CB(skb)->flow, key.tp.flags, skb);
#else
    ovs_flow_stats_update(OVS_CB(skb)->flow, skb);
#endif
    ovs_execute_actions(dp, skb);
    stats_counter = &stats->n_hit;

out:
    /* Update datapath statistics. */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,15,0)
    u64_stats_update_begin(&stats->syncp);
    (*stats_counter)++;
    stats->n_mask_hit += n_mask_hit;
    u64_stats_update_end(&stats->syncp);
#else
    u64_stats_update_begin(&stats->sync);
    (*stats_counter)++;
    stats->n_mask_hit += n_mask_hit;
    u64_stats_update_end(&stats->sync);
#endif
}
