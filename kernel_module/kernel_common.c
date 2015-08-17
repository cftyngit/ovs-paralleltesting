#include "kernel_common.h"

//const union ip client = {{10, 0, 0, 1},};
//const union ip server = {{10, 0, 0, 2},};
//const union ip mirror = {{10, 0, 0, 3},};
struct host_info server = {{{10, 0, 0, 2}}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x02}, 0};
struct host_info mirror = {{{10, 0, 0, 3}}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x03}, 0};
//struct host_info server = {{{192, 168, 3, 2}}, {0x00, 0x13, 0x3b, 0x0e, 0xd9, 0x5f}, 5};
//struct host_info mirror = {{{192, 168, 3, 3}}, {0x00, 0x13, 0x3b, 0x0e, 0xd2, 0xa3}, 4};

void print_skb ( struct sk_buff *skb )
{
#if INFO==1
	struct sk_buff* skb_mod = skb;
    struct ethhdr* mac_header = eth_hdr ( skb_mod );
    unsigned short eth_type = ntohs ( mac_header->h_proto );
	PRINT_INFO ( "vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv" );
	PRINT_INFO ( "MAC: %x:%x:%x:%x:%x:%x -> %x:%x:%x:%x:%x:%x\n", mac_header->h_source[0],mac_header->h_source[1],
	mac_header->h_source[2],mac_header->h_source[3],
	mac_header->h_source[4],mac_header->h_source[5],
	mac_header->h_dest[0],mac_header->h_dest[1],
	mac_header->h_dest[2],mac_header->h_dest[3],
	mac_header->h_dest[4],mac_header->h_dest[5] );

	PRINT_INFO ( "EtherType: 0x%x\n", eth_type );

	if ( 0x0800 == eth_type )
	{// if layer 3 protocol is IPv4
		struct iphdr* ip_header = ip_hdr ( skb_mod );
		unsigned char ip_proto = ip_header->protocol;
		char* ip_src = ( unsigned char* ) & ( ip_header->saddr );
		char* ip_dst = ( unsigned char* ) & ( ip_header->daddr );

		PRINT_INFO ( "IP: %d.%d.%d.%d -> %d.%d.%d.%d\n", 
			ip_src[0], ip_src[1], ip_src[2], ip_src[3],
			ip_dst[0], ip_dst[1], ip_dst[2], ip_dst[3] );

		switch ( ip_proto )
		{
		case 0x11:
		{//UDP
			struct udphdr* udp_header = udp_hdr ( skb_mod );
			size_t data_size = ntohs ( udp_header->len ) - sizeof ( struct udphdr );
			PRINT_INFO ( "UDP datasize: %zu\n", data_size );
			break;
		}
		case 0x06:
		{//TCP
			struct tcphdr* tcp_header = tcp_hdr ( skb_mod );
			size_t data_size = ntohs ( ip_header->tot_len ) - ( ( ip_header->ihl ) <<2 ) - ( ( tcp_header->doff ) <<2 );
			PRINT_INFO ( "TCP flags: %d %d %d\n", tcp_header->syn, tcp_header->ack, tcp_header->fin );
			PRINT_INFO ( "seq number: %u, ACK number: %u", ntohl ( tcp_header->seq ), ntohl ( tcp_header->ack_seq ) );
			PRINT_INFO ( "TCP datasize: %hu - %hu = %zu\n", ntohs ( ip_header->tot_len ), ( tcp_header->doff ) <<2, data_size );
			break;
		}
		default:
			break;
		}
	}
	PRINT_INFO ( "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" );
	return;
#endif
}

inline void send_skbmod ( struct sk_buff *skb_mod, struct other_args* arg )
{
	dbg_send(skb_mod);
	if(1 && mirror.port_no)
		ovs_vport_output(skb_mod, mirror.port_no, arg);
	else
		ovs_normal_output(skb_mod, arg);
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
	/*
	 * modify from set_eth_addr in openvswitch/action.c
	 */
    skb_postpull_rcsum(skb_mod, eth_hdr(skb_mod), ETH_ALEN * 2);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,14,0)
    ether_addr_copy(eth_hdr(skb_mod)->h_dest, mirror.mac);
#else
    memcpy(mac_header->h_dest, mirror.mac, ETH_ALEN);
#endif

	if (skb_mod->ip_summed == CHECKSUM_COMPLETE)
		skb_mod->csum = csum_add(skb_mod->csum, csum_partial((const void*)eth_hdr(skb_mod), ETH_ALEN * 2, 0));
////////modify eth mac finish/////////////////////
	/*
	 * modify from set_ip_addr in openvswitch/action.c
	 */
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
	skb_clear_hash(skb_mod);
    *addr = new_addr;
    //ip_header->daddr = mirror.ip.i;
    //ip_header->check = 0;
    //ip_send_check ( ip_header );
    return 0;
}

inline void print_packet_buffer_usage(packet_buffer_t* packet_buf)
{
#if PKTBUFF_USAGE==1
	if(packet_buf && abs(jiffies - packet_buf->lastest_jiff) / HZ)
	{
		int seconds = packet_buf->lastest_jiff ? abs(jiffies - packet_buf->lastest_jiff) / HZ : 1;
		if(packet_buf->lastest_jiff && abs(jiffies - packet_buf->lastest_jiff) % HZ >= HZ >> 1)
			seconds++;
		packet_buf->lastest_jiff = jiffies;
		while(seconds--)
			printk("head: %p, jiff: %lu, size: %d\n", &packet_buf->buffer_head, jiffies, packet_buf->node_count);
	}
#endif
}
