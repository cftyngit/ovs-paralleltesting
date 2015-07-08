#include "../ovs_func.h"
#include "datapath.h"
#include "../../packet_dispatcher.h"
#include <linux/if_vlan.h>

const char* ovs_hook_sym_name = "ovs_vport_receive";

#define ovs_flow_key_extract (*ovs_flow_key_extract_hi)
#define ovs_dp_process_packet (*ovs_dp_process_packet_hi)
#define ovs_vport_send (*ovs_vport_send_hi)
#define ovs_lookup_vport (*ovs_lookup_vport_hi)
#define ovs_netdev_get_vport (*ovs_netdev_get_vport_hi)

int (*ovs_flow_key_extract_hi)(const struct ovs_tunnel_info *tun_info, struct sk_buff *skb, struct sw_flow_key *key);
void (*ovs_dp_process_packet_hi)(struct sk_buff *skb, struct sw_flow_key *key);
int (*ovs_vport_send_hi)(struct vport *, struct sk_buff *);
struct vport* (*ovs_lookup_vport_hi)(const struct datapath *, u16);
struct vport* (*ovs_netdev_get_vport_hi)(struct net_device *dev);

void ovs_vport_receive_hi(struct vport *vport, struct sk_buff *skb, const struct ovs_tunnel_info *tun_info);

struct other_args
{
	struct datapath *dp;
	struct vport* vport;
	const struct ovs_tunnel_info* tun_info;
};
const size_t sizeof_other_args = sizeof(struct other_args);
void* ovs_hook_func = &ovs_vport_receive_hi;

int ovs_init_func(void)
{
	ovs_flow_key_extract_hi = (void*)kallsyms_lookup_name("ovs_flow_key_extract");
	if(ovs_flow_key_extract_hi == 0)
		return -1;

	ovs_dp_process_packet_hi = (void*)kallsyms_lookup_name("ovs_dp_process_packet");
	if(ovs_dp_process_packet_hi == 0)
		return -1;

	ovs_vport_send_hi = (void*)kallsyms_lookup_name("ovs_vport_send");
	if(ovs_vport_send_hi == 0)
		return -1;

	ovs_lookup_vport_hi = (void*)kallsyms_lookup_name("ovs_lookup_vport");
	if(ovs_lookup_vport_hi == 0)
		return -1;

	ovs_netdev_get_vport_hi = (void*)kallsyms_lookup_name("ovs_netdev_get_vport");
	if(ovs_netdev_get_vport_hi == 0)
		return -1;

	return 0;
}
void ovs_vport_receive_hi(struct vport *vport, struct sk_buff *skb, const struct ovs_tunnel_info *tun_info)
{
	struct pcpu_sw_netstats *stats;
	struct sw_flow_key key;
	int error;
	struct other_args arg = {vport->dp, vport, tun_info};

	stats = this_cpu_ptr(vport->percpu_stats);
	u64_stats_update_begin(&stats->syncp);
	stats->rx_packets++;
	stats->rx_bytes += skb->len + (vlan_tx_tag_present(skb) ? VLAN_HLEN : 0);
	u64_stats_update_end(&stats->syncp);

	OVS_CB(skb)->input_vport = vport;
	OVS_CB(skb)->egress_tun_info = NULL;
	/* Extract flow from 'skb' into 'key'. */
	error = ovs_flow_key_extract(tun_info, skb, &key);
	if (unlikely(error)) {
		kfree_skb(skb);
		return;
	}

//	memmove(&arg.vport, vport, sizeof(struct vport));
//	memmove(&arg.tun_info, tun_info, sizeof(struct ovs_tunnel_info));
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
		if(pd_action_from_server(skb, &arg) != 0)
		{
			consume_skb(skb);
			return;
		}
		break;
	case PT_ACTION_CONTINUE:
		break;
	case PT_ACTION_DROP:
		return;
	}

	ovs_dp_process_packet(skb, &key);
}

inline void ovs_normal_output(struct sk_buff *skb, struct other_args *args)
{
	struct sw_flow_key key;
	int error;
	
	if(NULL == OVS_CB(skb)->input_vport)
		OVS_CB(skb)->input_vport = args->vport;

	error = ovs_flow_key_extract(args->tun_info, skb, &key);
	if (unlikely(error)) {
		kfree_skb(skb);
		return;
	}

	ovs_dp_process_packet(skb, &key);
}

static inline struct vport *ovs_vport_rcu(const struct datapath *dp, int port_no)
{
	WARN_ON_ONCE(!rcu_read_lock_held());
	return ovs_lookup_vport(dp, port_no);
}

inline void ovs_vport_output(struct sk_buff *skb, int port_no, struct other_args *args)
{
// 	struct datapath *dp = args->vport->dp;
	struct vport *this_vport = ovs_netdev_get_vport(skb->dev);
	struct datapath *dp = this_vport ? this_vport->dp : args->dp;
	struct vport *vport = ovs_vport_rcu(dp, port_no);
// 	struct vport *vport = args->vport->dp;

	if (likely(vport))
		ovs_vport_send(vport, skb);
	else
		kfree_skb(skb);
}

inline int ovs_get_port_no(struct other_args* args)
{
	return (args->vport->port_no);
}
