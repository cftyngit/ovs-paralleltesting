#ifndef DATAPATH_H
#define DATAPATH_H 1

#include "flow.h"
#include "flow_table.h"
#include <linux/u64_stats_sync.h>
#include <linux/netlink.h>

/**
 * struct datapath - datapath for flow-based packet switching
 * @rcu: RCU callback head for deferred destruction.
 * @list_node: Element in global 'dps' list.
 * @table: flow table.
 * @ports: Hash table for ports.  %OVSP_LOCAL port always exists.  Protected by
 * ovs_mutex and RCU.
 * @stats_percpu: Per-CPU datapath statistics.
 * @net: Reference to net namespace.
 *
 * Context: See the comment on locking at the top of datapath.c for additional
 * locking information.
 */
struct datapath {
	struct rcu_head rcu;
	struct list_head list_node;

	/* Flow table. */
	struct flow_table table;

	/* Switch ports. */
	struct hlist_head *ports;

	/* Stats. */
	struct dp_stats_percpu __percpu *stats_percpu;

#ifdef CONFIG_NET_NS
	/* Network namespace ref. */
	struct net *net;
#endif

	u32 user_features;
};

/**
 * struct dp_stats_percpu - per-cpu packet processing statistics for a given
 * datapath.
 * @n_hit: Number of received packets for which a matching flow was found in
 * the flow table.
 * @n_miss: Number of received packets that had no matching flow in the flow
 * table.  The sum of @n_hit and @n_miss is the number of packets that have
 * been received by the datapath.
 * @n_lost: Number of received packets that had no matching flow in the flow
 * table that could not be sent to userspace (normally due to an overflow in
 * one of the datapath's queues).
 * @n_mask_hit: Number of masks looked up for flow match.
 *   @n_mask_hit / (@n_hit + @n_missed)  will be the average masks looked
 *   up per packet.
 */
struct dp_stats_percpu {
	u64 n_hit;
	u64 n_missed;
	u64 n_lost;
	u64 n_mask_hit;
	struct u64_stats_sync sync;
};

struct dp_upcall_info {
	u8 cmd;
	const struct sw_flow_key *key;
	const struct nlattr *userdata;
	u32 portid;
};

struct ovs_skb_cb {
	struct sw_flow		*flow;
	struct sw_flow_key	*pkt_key;
	struct ovs_key_ipv4_tunnel  *tun_key;
};
#define OVS_CB(skb) ((struct ovs_skb_cb *)(skb)->cb)

#endif /* datapath.h */