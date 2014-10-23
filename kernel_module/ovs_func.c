#include "ovs_func.h"
#include "packet_dispatcher.h"

int (*ovs_flow_extract_hi)(struct sk_buff *, u16, struct sw_flow_key *);
struct sw_flow* (*ovs_flow_tbl_lookup_stats_hi)(struct flow_table*, const struct sw_flow_key*, u32*);
int (*ovs_dp_upcall_hi)(struct datapath*, struct sk_buff*, const struct dp_upcall_info*);
void (*ovs_flow_stats_update_hi)(struct sw_flow *, __be16 tcp_flags, struct sk_buff *);
int (*ovs_execute_actions_hi)(struct datapath*, struct sk_buff*);

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
    int is_mirror = 0;
	stats = this_cpu_ptr(dp->stats_percpu);
	error = (*ovs_flow_extract_hi)(skb, p->port_no, &key);
	
	if (unlikely(error)) {
		kfree_skb(skb);
		return;
	}

    switch(pd_check_action(skb))
	{
	case PT_ACTION_DROP:
		pd_action_from_mirror(p, skb);
		kfree_skb(skb);
		return;
		is_mirror = 1;
		break;
	case PT_ACTION_CLIENT_TO_SERVER:
		pd_action_from_client(p, skb);
		break;
	case PT_ACTION_SERVER_TO_CLIENT:
		pd_action_from_server(p, skb);
		break;
	case PT_ACTION_CONTINUE:
		break;
	}

	flow = (*ovs_flow_tbl_lookup_stats_hi)(&dp->table, &key, &n_mask_hit);
	if (unlikely(!flow)) {
		struct dp_upcall_info upcall;

		upcall.cmd = OVS_PACKET_CMD_MISS;
		upcall.key = &key;
		upcall.userdata = NULL;
		upcall.portid = p->upcall_portid;
		(*ovs_dp_upcall_hi)(dp, skb, &upcall);
		consume_skb(skb);
		stats_counter = &stats->n_missed;
		goto out;
	}

	OVS_CB(skb)->flow = flow;
	OVS_CB(skb)->pkt_key = &key;

	(*ovs_flow_stats_update_hi)(OVS_CB(skb)->flow, key.tp.flags, skb);
	//if(!is_mirror)
	    (*ovs_execute_actions_hi)(dp, skb);
	stats_counter = &stats->n_hit;

out:
	u64_stats_update_begin(&stats->syncp);
	(*stats_counter)++;
	stats->n_mask_hit += n_mask_hit;
	u64_stats_update_end(&stats->syncp);
}
