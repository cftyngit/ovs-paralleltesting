#include "kernel_common.h"

//const union ip client = {{10, 0, 0, 1},};
//const union ip server = {{10, 0, 0, 2},};
//const union ip mirror = {{10, 0, 0, 3},};
//static struct host_info server = {{{10, 0, 0, 2}}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x02}};
//static struct host_info mirror = {{{10, 0, 0, 3}}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x03}};
struct host_info server = {{{10, 0, 0, 2}}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x02}, 0};
struct host_info mirror = {{{10, 0, 0, 3}}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x03}, 0};

static int do_output(struct datapath *dp, struct sk_buff *skb, int out_port)
{
	struct vport *vport;

	if (unlikely(!skb))
		return -ENOMEM;

	vport = ovs_vport_rcu(dp, out_port);
	if (unlikely(!vport)) {
		kfree_skb(skb);
		return -ENODEV;
	}

	ovs_vport_send(vport, skb);
	return 0;
}

void print_skb ( struct sk_buff *skb )
{
	struct sk_buff* skb_mod = skb;
    struct ethhdr* mac_header = eth_hdr ( skb_mod );
    unsigned short eth_type = ntohs ( mac_header->h_proto );
	printk ( KERN_INFO "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" );
	printk ( KERN_INFO "MAC: %x:%x:%x:%x:%x:%x -> %x:%x:%x:%x:%x:%x\n", mac_header->h_source[0],mac_header->h_source[1],
	mac_header->h_source[2],mac_header->h_source[3],
	mac_header->h_source[4],mac_header->h_source[5],
	mac_header->h_dest[0],mac_header->h_dest[1],
	mac_header->h_dest[2],mac_header->h_dest[3],
	mac_header->h_dest[4],mac_header->h_dest[5] );

	printk ( KERN_INFO "EtherType: 0x%x\n", eth_type );

	if ( 0x0800 == eth_type )
	{// if layer 3 protocol is IPv4
		struct iphdr* ip_header = ip_hdr ( skb_mod );
		unsigned char ip_proto = ip_header->protocol;
		char* ip_src = ( unsigned char* ) & ( ip_header->saddr );
		char* ip_dst = ( unsigned char* ) & ( ip_header->daddr );

		printk ( KERN_INFO "IP: %d.%d.%d.%d -> %d.%d.%d.%d\n", 
			ip_src[0], ip_src[1], ip_src[2], ip_src[3],
			ip_dst[0], ip_dst[1], ip_dst[2], ip_dst[3] );

		switch ( ip_proto )
		{
		case 0x11:
		{//UDP
			struct udphdr* udp_header = udp_hdr ( skb_mod );
			size_t data_size = ntohs ( udp_header->len ) - sizeof ( struct udphdr );
			printk ( KERN_INFO "UDP datasize: %lu\n", data_size );
			break;
		}
		case 0x06:
		{//TCP
			struct tcphdr* tcp_header = tcp_hdr ( skb_mod );
			size_t data_size = ntohs ( ip_header->tot_len ) - ( ( ip_header->ihl ) <<2 ) - ( ( tcp_header->doff ) <<2 );
			printk ( KERN_INFO "TCP flags: %d %d %d\n", tcp_header->syn, tcp_header->ack, tcp_header->fin );
			printk ( KERN_INFO "seq number: %u, ACK number: %u", ntohl ( tcp_header->seq ), ntohl ( tcp_header->ack_seq ) );
			printk ( KERN_INFO "TCP datasize: %hu - %hu = %lu\n", ntohs ( ip_header->tot_len ), ( tcp_header->doff ) <<2, data_size );
			break;
		}
		default:
			break;
		}
	}
	printk ( KERN_INFO "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" );
	return;
}

void send_skbmod ( struct vport *p, struct sk_buff *skb_mod )
{
    struct datapath *dp = p->dp;
    struct sw_flow *flow;
    struct dp_stats_percpu *stats;
    struct sw_flow_key key;
    u64 *stats_counter;
    u32 n_mask_hit;
    int error;

	/*if(mirror.port_no)
	{
		do_output(dp, skb_mod, mirror.port_no);
		return;
	}*/
    stats = this_cpu_ptr(dp->stats_percpu);

    /* Extract flow from 'skb' into 'key'. */
    error = ovs_flow_extract(skb_mod, p->port_no, &key);
    if (unlikely(error)) {
        kfree_skb(skb_mod);
        return;
    }
    
    /* Look up flow. */
    flow = ovs_flow_tbl_lookup_stats(&dp->table, &key, &n_mask_hit);
    if (unlikely(!flow)) {
        struct dp_upcall_info upcall;

        upcall.cmd = OVS_PACKET_CMD_MISS;
        upcall.key = &key;
        upcall.userdata = NULL;

        upcall.portid = ovs_vport_find_upcall_portid(p, skb_mod);
        printk("[%s] upcall port: %u\n", __func__, upcall.portid);
        //return;
        error = ovs_dp_upcall(dp, skb_mod, &upcall);
        //return;
        if (unlikely(error))
            kfree_skb(skb_mod);
        else
            consume_skb(skb_mod);
        stats_counter = &stats->n_missed;
        goto out;
    }
    //printk("[%s] %p\n", __func__, skb_mod);
    //printk("[%s] %p\n", __func__, OVS_CB(skb_mod));
    //return;
    OVS_CB(skb_mod)->flow = flow;
    
    OVS_CB(skb_mod)->pkt_key = &key;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,16,0)
    ovs_flow_stats_update(OVS_CB(skb_mod)->flow, key.tp.flags, skb_mod);
#else
    ovs_flow_stats_update(OVS_CB(skb_mod)->flow, skb_mod);
#endif
    ovs_execute_actions(dp, skb_mod);
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

int pd_modify_ip_mac ( struct sk_buff* skb_mod )
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(3,14,0)
    struct ethhdr* mac_header = eth_hdr ( skb_mod );
#endif
    struct iphdr* ip_header = ip_hdr ( skb_mod );
    int transport_len = skb_mod->len - skb_transport_offset(skb_mod);
    __be32 *addr = &(ip_header->daddr);
    __be32 new_addr = mirror.ip.i;
    skb_postpull_rcsum(skb_mod, eth_hdr(skb_mod), ETH_ALEN * 2);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
    ether_addr_copy(eth_hdr(skb_mod)->h_dest, mirror.mac);
#else
    memcpy(mac_header->h_dest, mirror.mac, ETH_ALEN);
#endif
    ovs_skb_postpush_rcsum(skb_mod, eth_hdr(skb_mod), ETH_ALEN * 2);
    //memcpy(mac_header->h_dest, mirror.mac, 6);
    if (ip_header->protocol == IPPROTO_TCP)
    {
        if (likely(transport_len >= sizeof(struct tcphdr)))
            inet_proto_csum_replace4(&tcp_hdr(skb_mod)->check, skb_mod, *addr, new_addr, 1);
    }
    else if (ip_header->protocol == IPPROTO_UDP)
    {
        if (likely(transport_len >= sizeof(struct udphdr)))
        {
            struct udphdr *udp_header = udp_hdr(skb_mod);

            if (udp_header->check || skb_mod->ip_summed == CHECKSUM_PARTIAL)
            {
                inet_proto_csum_replace4(&udp_header->check, skb_mod, *addr, new_addr, 1);
                if (!udp_header->check)
                    udp_header->check = CSUM_MANGLED_0;
            }
        }
    }

    csum_replace4(&ip_header->check, *addr, new_addr);
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,35)
    ;
#elif (LINUX_VERSION_CODE < KERNEL_VERSION(3,15,0))
    skb_mod->rxhash = 0;
#else
    skb_mod->hash = 0;
#endif
    *addr = new_addr;
    //ip_header->daddr = mirror.ip.i;
    //ip_header->check = 0;
    //ip_send_check ( ip_header );
    return 0;
}

