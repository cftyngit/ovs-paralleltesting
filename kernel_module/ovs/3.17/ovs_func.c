#include "../ovs_func.h"
#include "datapath.h"
#include "../../packet_dispatcher.h"
#include <linux/if_vlan.h>

const char* ovs_hook_sym_name = "ovs_vport_receive";

#define ovs_dp_process_received_packet (*ovs_dp_process_received_packet_hi)
#define ovs_vport_send (*ovs_vport_send_hi)
#define ovs_lookup_vport (*ovs_lookup_vport_hi)

void (*ovs_dp_process_received_packet_hi)(struct vport *p, struct sk_buff *skb);
int (*ovs_vport_send_hi)(struct vport *, struct sk_buff *);
struct vport* (*ovs_lookup_vport_hi)(const struct datapath *, u16);

void ovs_vport_receive_hi(struct vport *vport, struct sk_buff *skb, struct ovs_key_ipv4_tunnel *tun_key);

struct other_args
{
	struct vport *vport;
};
const size_t sizeof_other_args = sizeof(struct other_args);
void* ovs_hook_func = &ovs_vport_receive_hi;

int ovs_init_func(void)
{
	ovs_dp_process_received_packet_hi = (void*)kallsyms_lookup_name("ovs_dp_process_received_packet");
	if(ovs_dp_process_received_packet_hi == 0)
		return -1;

	ovs_vport_send_hi = (void*)kallsyms_lookup_name("ovs_vport_send");
	if(ovs_vport_send_hi == 0)
		return -1;

	ovs_lookup_vport_hi = (void*)kallsyms_lookup_name("ovs_lookup_vport");
	if(ovs_lookup_vport_hi == 0)
		return -1;

	return 0;
}

void ovs_vport_receive_hi(struct vport *vport, struct sk_buff *skb, struct ovs_key_ipv4_tunnel *tun_key)
{
	struct pcpu_sw_netstats *stats;
	struct other_args arg = {vport};

	stats = this_cpu_ptr(vport->percpu_stats);
	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes += skb->len;
	u64_stats_update_end(&stats->syncp);

	OVS_CB(skb)->tun_key = tun_key;

	switch(pd_check_action(skb, &arg))
	{
	case PT_ACTION_FROM_MIRROR:
		pd_action_from_mirror(skb, &arg);
		consume_skb(skb);
		return;
	case PT_ACTION_FROM_RMHOST:
		pd_action_from_client(skb, &arg);
		break;
	case PT_ACTION_FROM_TARGET:
		pd_action_from_server(skb, &arg);
		break;
	case PT_ACTION_CONTINUE:
		break;
	case PT_ACTION_DROP:
		return;
	}

	ovs_dp_process_received_packet(vport, skb);
}

inline void ovs_normal_output(struct sk_buff *skb, struct other_args *args)
{
	ovs_dp_process_received_packet(args->vport, skb);
}

static inline struct vport *ovs_vport_rcu(const struct datapath *dp, int port_no)
{
	WARN_ON_ONCE(!rcu_read_lock_held());
	return ovs_lookup_vport(dp, port_no);
}

inline void ovs_vport_output(struct sk_buff *skb, int port_no, struct other_args *args)
{
	struct vport *vport = args->vport;
	struct datapath *dp = vport->dp;

	vport = ovs_vport_rcu(dp, port_no);
	if (unlikely(!vport)) {
		kfree_skb(skb);
		return;
	}

	ovs_vport_send(vport, skb);
	return;
}

inline int ovs_get_port_no(struct other_args* args)
{
	return args->vport->port_no;
}
