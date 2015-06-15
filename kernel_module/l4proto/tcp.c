#include "tcp.h"

extern struct host_conn_info_set conn_info_set;
struct tcp_flags
{
#if defined(__LITTLE_ENDIAN_BITFIELD)
	__u16	res1:4,
		doff:4,
		fin:1,
		syn:1,
		rst:1,
		psh:1,
		ack:1,
		urg:1,
		ece:1,
		cwr:1;
#elif defined(__BIG_ENDIAN_BITFIELD)
	__u16	doff:4,
		res1:4,
		cwr:1,
		ece:1,
		urg:1,
		ack:1,
		psh:1,
		rst:1,
		syn:1,
		fin:1;
#else
#error	"Adjust your <asm/byteorder.h> defines"
#endif
};
int modify_tcp_header( struct sk_buff* skb_mod, union my_ip_type ip, u16 client_port )
{
    struct tcphdr* tcp_header = tcp_hdr ( skb_mod );
    struct tcp_conn_info* this_tcp_info = TCP_CONN_INFO(&conn_info_set, ip, client_port);

    if ( !(tcp_header->syn && !tcp_header->ack) )
    {
        unsigned int seq_server = this_tcp_info->seq_server;
        unsigned int seq_mirror = this_tcp_info->seq_mirror;
        if ( seq_mirror > seq_server )
            tcp_header->ack_seq = htonl ( ntohl ( tcp_header->ack_seq ) + ( seq_mirror - seq_server ) );
        else
            tcp_header->ack_seq = htonl ( ntohl ( tcp_header->ack_seq ) - ( seq_server - seq_mirror ) );
    }

    if(this_tcp_info->mirror_port)
        tcp_header->dest = htons(this_tcp_info->mirror_port);

    return 0;
}

int respond_tcp_syn_ack(const struct sk_buff* skb, const struct tcp_conn_info* tcp_info)
{
    struct socket *sock;
    struct net *net = NULL;
    struct sk_buff *skb_new = NULL;
    struct ethhdr *eth_header = NULL;
    struct iphdr *ip_header = NULL;
    struct tcphdr *tcp_header = NULL;
    struct ethhdr* sk_eth_header = eth_hdr(skb);
    struct iphdr* sk_ip_header = ip_hdr(skb);
    struct tcphdr* sk_tcp_header = tcp_hdr(skb);
    struct net_device* netdev = skb->dev;
    const unsigned char tcp_options[] = 
    {
        0x02, 0x04, 0x05, 0xb4, /*MSS = 1460*/
        0x01, 0x01,             /*NOP NOP*/
        0x04, 0x02,             /*SACK = true*/
        0x01,                   /*NOP*/
        0x03, 0x03, 0x09        /*window scale = 9*/
    };
    __be32 dip = sk_ip_header->saddr;
    __be32 sip = sk_ip_header->daddr;
    u8 *pdata = NULL;
    u32 skb_len;

    sock_create_kern(PF_INET, SOCK_STREAM, 0, &sock);
    net = sock_net((const struct sock *) sock->sk);
    skb_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(tcp_options) + (((TCPOLEN_TIMESTAMP>>2)+1)<<2) + LL_RESERVED_SPACE(netdev);
    /* dev_alloc_skb是一个缓冲区分配函数,主要被设备驱动使用.
     * 这是一个alloc_skb的包装函数, 它会在请求分配的大小上增加
     * 16 Bytes的空间以优化缓冲区的读写效率.*/
    skb_new = dev_alloc_skb(skb_len);
    if (!skb_new) 
    {
        return -1;
    }
    /* fill the skb.具体参照struct sk_buff.
     * skb_reserve()用来为协议头预留空间.
     * PACKET_OTHERHOST: packet type is "to someone else".
     * ETH_P_IP: Internet Protocol packet.
     * CHECKSUM_NONE表示完全由软件来执行校验和. */
    skb_reserve(skb_new, LL_RESERVED_SPACE(netdev));
    skb_new->dev = netdev;
    skb_new->pkt_type = PACKET_OTHERHOST;
    skb_new->protocol = htons(ETH_P_IP);
    skb_new->ip_summed = CHECKSUM_NONE;
    skb_new->priority = 0;

    /* 分配内存给ip头 */
    skb_set_network_header(skb_new, 0);
    skb_put(skb_new, sizeof(struct iphdr));
    /* 分配内存给tcp头 */
    skb_set_transport_header(skb_new, sizeof(struct iphdr));
    skb_put(skb_new, sizeof(struct tcphdr));

    /* construct tcp header in skb */
    tcp_header = tcp_hdr(skb_new);
    memset (tcp_header, 0, sizeof(struct tcphdr));

    tcp_header->ack_seq = htonl(ntohl(sk_tcp_header->seq) + 1);
    tcp_header->seq = htonl(FAKE_SEQ);
    tcp_header->source = sk_tcp_header->dest;
    tcp_header->dest = sk_tcp_header->source;
    tcp_header->doff = (u32)( 20 + sizeof(tcp_options) + (((TCPOLEN_TIMESTAMP>>2)+1)<<2) ) >> 2;
    tcp_header->syn = 1;
    tcp_header->ack = 1;
    tcp_header->window = htons(0);

    /* construct ip header in skb */
    ip_header = ip_hdr(skb_new);
    memset (ip_header, 0, sizeof(struct iphdr));
    ip_header->version = 4;
    ip_header->ihl = sizeof(struct iphdr) >> 2;
    ip_header->frag_off = 0;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->tos = 0;
    ip_header->daddr = dip;
    ip_header->saddr = sip;
    ip_header->ttl = 0x40;
    ip_header->tot_len = htons(skb_new->len + sizeof(tcp_options) + (((TCPOLEN_TIMESTAMP>>2)+1)<<2));
    ip_header->check = 0;
    ip_send_check(ip_header);
    /* caculate checksum */

    pdata = skb_put(skb_new, sizeof(tcp_options));
    if (pdata)
    {
        memmove(pdata, tcp_options, sizeof(tcp_options));
    }
    /*
     * setup tcp timestamp
     */
    pdata = skb_put(skb_new, ((TCPOLEN_TIMESTAMP>>2)+1)<<2);
    if (pdata)
    {
        const char timestamp[] = {TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP};
        memset(pdata, 0x01, (((TCPOLEN_TIMESTAMP>>2)+1)<<2) - TCPOLEN_TIMESTAMP);
        pdata+=(((TCPOLEN_TIMESTAMP>>2)+1)<<2) - TCPOLEN_TIMESTAMP;
        memmove(pdata, timestamp, sizeof(timestamp));
        pdata+=sizeof(timestamp);
        put_unaligned_be32(tcp_time_stamp, pdata);
        pdata+=4;
        put_unaligned_be32(get_tsval(skb), pdata);
    }
    skb_new->csum = skb_checksum(skb_new, ip_header->ihl*4, skb_new->len-ip_header->ihl*4, 0);
    tcp_header->check = 0;
    tcp_header->check = tcp_v4_check(skb_new->len - (ip_header->ihl<<2), ip_header->saddr, ip_header->daddr, skb_new->csum);

    /* construct ethernet header in skb */
    eth_header = (struct ethhdr *)skb_push(skb_new, 14);
    memset (eth_header, 0, sizeof(struct ethhdr));
    memcpy(eth_header->h_dest, sk_eth_header->h_source, ETH_ALEN);
    memcpy(eth_header->h_source, sk_eth_header->h_dest, ETH_ALEN);
    eth_header->h_proto = htons(ETH_P_IP);

    /* send packet */
    if (dev_queue_xmit(skb_new) < 0)
    {
        dev_put(netdev);
        kfree_skb(skb_new);
        PRINT_ERROR("send packet by skb failed.\n");
        sock_release(sock);
        return -1;
    }
///    printk("send packet by skb success.\n");
    sock_release(sock);
    return 0;
}

int ack_this_packet(const struct sk_buff* skb, const struct tcp_conn_info* tcp_info)
{
    struct socket *sock;
    struct net *net = NULL;
    struct sk_buff *skb_new = NULL;
    struct ethhdr *eth_header = NULL;
    struct iphdr *ip_header = NULL;
    struct tcphdr *tcp_header = NULL;
    struct ethhdr* sk_eth_header = eth_hdr(skb);
    struct iphdr* sk_ip_header = ip_hdr(skb);
    struct tcphdr* sk_tcp_header = tcp_hdr(skb);
    struct net_device* netdev = skb->dev;
//     size_t data_size = ntohs ( sk_ip_header->tot_len ) - ( ( sk_ip_header->ihl ) <<2 ) - ( ( sk_tcp_header->doff ) <<2 );
    __be32 dip = sk_ip_header->saddr;
    __be32 sip = sk_ip_header->daddr;
    //u8 *pdata = NULL;
    u32 skb_len;
	u8 *pdata = NULL;

    sock_create_kern(PF_INET, SOCK_STREAM, 0, &sock);
    net = sock_net((const struct sock *) sock->sk);
//	skb_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + LL_RESERVED_SPACE(netdev);
	skb_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + (((TCPOLEN_TIMESTAMP>>2)+1)<<2) + LL_RESERVED_SPACE(netdev);
    /* dev_alloc_skb是一个缓冲区分配函数,主要被设备驱动使用.
     * 这是一个alloc_skb的包装函数, 它会在请求分配的大小上增加
     * 16 Bytes的空间以优化缓冲区的读写效率.*/
    skb_new = dev_alloc_skb(skb_len);
    if (!skb_new) 
    {
        return -1;
    }
    /* fill the skb.具体参照struct sk_buff.
     * skb_reserve()用来为协议头预留空间.
     * PACKET_OTHERHOST: packet type is "to someone else".
     * ETH_P_IP: Internet Protocol packet.
     * CHECKSUM_NONE表示完全由软件来执行校验和. */
    skb_reserve(skb_new, LL_RESERVED_SPACE(netdev));
    skb_new->dev = netdev;
    skb_new->pkt_type = PACKET_OTHERHOST;
    skb_new->protocol = htons(ETH_P_IP);
    skb_new->ip_summed = CHECKSUM_NONE;
    skb_new->priority = 0;
    /* 分配内存给ip头 */
    skb_set_network_header(skb_new, 0);
    skb_put(skb_new, sizeof(struct iphdr));
    /* 分配内存给tcp头 */
    skb_set_transport_header(skb_new, sizeof(struct iphdr));
    skb_put(skb_new, sizeof(struct tcphdr));
    /* construct tcp header in skb */
    tcp_header = tcp_hdr(skb_new);
    memset (tcp_header, 0, sizeof(struct tcphdr));
// 	tcp_header->ack_seq = htonl( ntohl(sk_tcp_header->seq) + data_size + (sk_tcp_header->syn || sk_tcp_header->fin ? 1 : 0));
	tcp_header->ack_seq = htonl(tcp_info->seq_next);
    tcp_header->seq = sk_tcp_header->ack_seq;
    tcp_header->source = sk_tcp_header->dest;
    tcp_header->dest = sk_tcp_header->source;
//	tcp_header->doff = (u32)( sizeof(struct tcphdr) ) >> 2;
	tcp_header->doff = (u32)( sizeof(struct tcphdr) + (((TCPOLEN_TIMESTAMP>>2)+1)<<2) ) >> 2;
    tcp_header->ack = 1;
    tcp_header->window = sk_tcp_header->window;
    /* construct ip header in skb */
    ip_header = ip_hdr(skb_new);
    memset (ip_header, 0, sizeof(struct iphdr));
    ip_header->version = 4;
    ip_header->ihl = sizeof(struct iphdr) >> 2;
    ip_header->frag_off = 0;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->tos = 0;
    ip_header->daddr = dip;
    ip_header->saddr = sip;
    ip_header->ttl = 0x40;
    ip_header->tot_len = htons(skb_new->len + (((TCPOLEN_TIMESTAMP>>2)+1)<<2));
    ip_header->check = 0;
    /* caculate checksum */
    ip_send_check(ip_header);
    skb_new->csum = skb_checksum(skb_new, ip_header->ihl*4, skb_new->len-ip_header->ihl*4, 0);
	    /*
     * setup tcp timestamp
     */
    pdata = skb_put(skb_new, ((TCPOLEN_TIMESTAMP>>2)+1)<<2);
    if (pdata/* && tcp_info->tsval_current*/)
    {
        const char timestamp[] = {TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP};
        memset(pdata, 0x01, (((TCPOLEN_TIMESTAMP>>2)+1)<<2) - TCPOLEN_TIMESTAMP);
        pdata+=(((TCPOLEN_TIMESTAMP>>2)+1)<<2) - TCPOLEN_TIMESTAMP;
        memmove(pdata, timestamp, sizeof(timestamp));
        pdata+=sizeof(timestamp);
//         put_unaligned_be32(tcp_info->tsval_last_send, pdata);
		
		put_unaligned_be32(tcp_time_stamp, pdata);
        pdata+=4;
//         put_unaligned_be32(tcp_info->tsval_current, pdata);
// 		put_unaligned_be32(tcp_time_stamp, pdata);
		put_unaligned_be32(tcp_info->ts_recent, pdata);
    }
    tcp_header->check = 0;
    tcp_header->check = tcp_v4_check(skb_new->len - (ip_header->ihl<<2), ip_header->saddr, ip_header->daddr, skb_new->csum);
    /* construct ethernet header in skb */
    eth_header = (struct ethhdr *)skb_push(skb_new, 14);
    memset (eth_header, 0, sizeof(struct ethhdr));
    memcpy(eth_header->h_dest, sk_eth_header->h_source, ETH_ALEN);
    memcpy(eth_header->h_source, sk_eth_header->h_dest, ETH_ALEN);
    eth_header->h_proto = htons(ETH_P_IP);
	setup_options(skb_new, tcp_info);
    /* send packet */
    if (dev_queue_xmit(skb_new) < 0)
    {
        dev_put(netdev);
        kfree_skb(skb_new);
        PRINT_ERROR("send packet by skb failed.\n");
        sock_release(sock);
        return -1;
    }
///    printk("send packet by skb success.\n");
    sock_release(sock);
    return 0;
}

struct sk_buff* build_ack_sk_buff(struct sk_buff* skb, u32 seq_ack)
{
    struct sk_buff *skb_new = NULL;
    struct ethhdr *eth_header = NULL;
    struct iphdr *ip_header = NULL;
    struct tcphdr *tcp_header = NULL;
    struct ethhdr* sk_eth_header = eth_hdr(skb);
    struct iphdr* sk_ip_header = ip_hdr(skb);
    struct tcphdr* sk_tcp_header = tcp_hdr(skb);
    struct net_device* netdev = skb->dev;
    u8 *pdata = NULL;
    __be32 dip = sk_ip_header->daddr;
    __be32 sip = sk_ip_header->saddr;
    u32 skb_len;
    u32 skb_tsecr = get_tsecr(skb);

    skb_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + (((TCPOLEN_TIMESTAMP>>2)+1)<<2) + LL_RESERVED_SPACE(netdev);
    /* dev_alloc_skb是一个缓冲区分配函数,主要被设备驱动使用.
     * 这是一个alloc_skb的包装函数, 它会在请求分配的大小上增加
     * 16 Bytes的空间以优化缓冲区的读写效率.*/
    skb_new = dev_alloc_skb(skb_len);
    if (!skb_new) 
    {
        return NULL;
    }
    /* fill the skb.具体参照struct sk_buff.
     * skb_reserve()用来为协议头预留空间.
     * PACKET_OTHERHOST: packet type is "to someone else".
     * ETH_P_IP: Internet Protocol packet.
     * CHECKSUM_NONE表示完全由软件来执行校验和. */
    
    skb_reserve(skb_new, LL_RESERVED_SPACE(netdev));
    skb_new->dev = netdev;
    skb_new->pkt_type = skb->pkt_type;
    skb_new->protocol = skb->protocol;
    skb_new->ip_summed = CHECKSUM_NONE;
    skb_new->priority = skb->priority;

    /* 分配内存给ip头 */
    skb_set_network_header(skb_new, 0);
    skb_put(skb_new, sizeof(struct iphdr));
    /* 分配内存给tcp头 */
    skb_set_transport_header(skb_new, sizeof(struct iphdr));
    skb_put(skb_new, sizeof(struct tcphdr));
    /* construct tcp header in skb */
    tcp_header = tcp_hdr(skb_new);
    memset (tcp_header, 0, sizeof(struct tcphdr));
    tcp_header->ack_seq = htonl(seq_ack);
    tcp_header->seq = sk_tcp_header->seq;
    tcp_header->source = sk_tcp_header->source;
    tcp_header->dest = sk_tcp_header->dest;
    tcp_header->doff = ((u32)( sizeof(struct tcphdr) ) + (((TCPOLEN_TIMESTAMP>>2)+1)<<2)) >> 2;
    tcp_header->ack = 1;
    tcp_header->window = sk_tcp_header->window;
    /* construct ip header in skb */

    ip_header = ip_hdr(skb_new);
    memset (ip_header, 0, sizeof(struct iphdr));
    ip_header = ip_hdr(skb_new);
    ip_header->version = 4;
    ip_header->ihl = sizeof(struct iphdr) >> 2;
    ip_header->frag_off = 0;
    ip_header->protocol = IPPROTO_TCP;
    ip_header->tos = 0;
    ip_header->daddr = dip;
    ip_header->saddr = sip;
    ip_header->ttl = 0x40;
    ip_header->tot_len = htons(skb_new->len + (((TCPOLEN_TIMESTAMP>>2)+1)<<2));
    ip_header->check = 0;
    ip_send_check(ip_header);
    /* caculate checksum */
    pdata = skb_put(skb_new, (((TCPOLEN_TIMESTAMP>>2)+1)<<2));
    if (pdata && skb_tsecr) 
    {
//         const u32 ftsval = get_tsval(skb);
        const char timestamp[] = {TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP};
        memset(pdata, 0x01, (((TCPOLEN_TIMESTAMP>>2)+1)<<2) - TCPOLEN_TIMESTAMP);
        pdata += (((TCPOLEN_TIMESTAMP>>2)+1)<<2) - TCPOLEN_TIMESTAMP;
        memmove(pdata, timestamp, sizeof(timestamp));
        pdata+=sizeof(timestamp);
        put_unaligned_be32(tcp_time_stamp, pdata);
        pdata+=4;
//         put_unaligned_be32(skb_tsecr, pdata);
		put_unaligned_be32(skb_tsecr, pdata);
    }
     skb_new->csum = skb_checksum(skb_new, ip_header->ihl*4, skb_new->len-ip_header->ihl*4, 0);
     tcp_header->check = 0;
     tcp_header->check = tcp_v4_check(skb_new->len - (ip_header->ihl<<2), ip_header->saddr, ip_header->daddr, skb_new->csum);
 
     /* construct ethernet header in skb */
     eth_header = (struct ethhdr *)skb_push(skb_new, sizeof(struct ethhdr));
     memset (eth_header, 0, sizeof(struct ethhdr));
     skb_set_mac_header(skb_new, 0);
     memset (eth_header, 0, sizeof(struct ethhdr));
     memcpy(eth_header->h_dest, sk_eth_header->h_dest, ETH_ALEN);
     memcpy(eth_header->h_source, sk_eth_header->h_source, ETH_ALEN);
     eth_header->h_proto = htons(ETH_P_IP);

     return skb_new;
}

void setup_options(struct sk_buff* skb_mod, const struct tcp_conn_info* tcp_info)
{
	struct tcphdr* tcp_header = tcp_hdr(skb_mod);
	int length = (tcp_header->doff * 4) - sizeof(struct tcphdr);
	u32* new_options = kmalloc(length, GFP_KERNEL);
	u32* old_options = (u32 *)(tcp_header + 1);
	int opt_l = length / sizeof(u32);
	int i = 0;
	unsigned char* ptr = (unsigned char*)new_options;
	if(!new_options)
		return;

	memmove(new_options, (unsigned char *)(tcp_header + 1), length);

	while (length > 0)
	{
		int opcode = *ptr++;
		int opsize;

		switch (opcode)
		{
		case TCPOPT_EOL:
			return;
		case TCPOPT_NOP:        /* Ref: RFC 793 section 3.1 */
			length--;
			continue;
		default:
			opsize = *ptr++;
			if (opsize < 2) /* "silly options" */
				return;
			if (opsize > length)
				return; /* don't parse partial options */
			switch (opcode)
			{
			case TCPOPT_MSS:
				break;
			case TCPOPT_WINDOW:
				break;
			case TCPOPT_TIMESTAMP:
				if(opsize == TCPOLEN_TIMESTAMP)
				{
// 					u32 pkt_tsval = get_unaligned_be32(ptr + 0);
// 					if(after(tcp_info->tsval_last_send, pkt_tsval))
						put_unaligned_be32(tcp_time_stamp, (void*)ptr+0);

// 					put_unaligned_be32(tcp_time_stamp, (void*)ptr+4);
// 						put_unaligned_be32(tcp_info->tsval_current, (void*)ptr+4);
						put_unaligned_be32(tcp_info->ts_recent, (void*)ptr+4);
				}
				break;
			case TCPOPT_SACK_PERM:
				if (opsize == TCPOLEN_SACK_PERM)
				{
					u16 cancle_sack = 0x01 + (0x01<<8);
					put_unaligned_be16(cancle_sack, (void*)ptr-2);
				}
				break;
			case TCPOPT_SACK:
				break;
			case TCPOPT_EXP:
				break;
			}
			ptr += opsize-2;
			length -= opsize;
		}
	}
	for(i = 0; i < opt_l; ++i)
	{
		inet_proto_csum_replace4(&tcp_header->check, skb_mod, old_options[i], new_options[i], 0);
		old_options[i] = new_options[i];
		skb_clear_hash(skb_mod);
	}
	kfree(new_options);
}

u32 __get_timestamp(const struct sk_buff* skb, int off)
{
    const struct tcphdr* tcp_header = tcp_hdr(skb);
    int length = (tcp_header->doff * 4) - sizeof(struct tcphdr);
    const unsigned char* ptr = (const unsigned char *)(tcp_header + 1);

    while (length > 0)
    {
        int opcode = *ptr++;
        int opsize;

        switch (opcode)
        {
        case TCPOPT_EOL:
            return 0;
        case TCPOPT_NOP:        /* Ref: RFC 793 section 3.1 */
            length--;
            continue;
        default:
            opsize = *ptr++;
            if (opsize < 2) /* "silly options" */
                return 0;
            if (opsize > length)
                return 0; /* don't parse partial options */
            if ((TCPOPT_TIMESTAMP == opcode) && (TCPOLEN_TIMESTAMP == opsize))
                return get_unaligned_be32(ptr + off);

            ptr += opsize-2;
            length -= opsize;
        }
    }
    return 0;
}

u8 get_window_scaling(const struct sk_buff* skb)
{
    const struct tcphdr* tcp_header = tcp_hdr(skb);
    int length = (tcp_header->doff * 4) - sizeof(struct tcphdr);
    const unsigned char* ptr = (const unsigned char *)(tcp_header + 1);

    while (length > 0)
    {
        int opcode = *ptr++;
        int opsize;

        switch (opcode)
        {
        case TCPOPT_EOL:
            return 0;
        case TCPOPT_NOP:        /* Ref: RFC 793 section 3.1 */
            length--;
            continue;
        default:
            opsize = *ptr++;
            if (opsize < 2) /* "silly options" */
                return 0;
            if (opsize > length)
                return 0; /* don't parse partial options */
            if ((TCPOPT_WINDOW == opcode) && (TCPOLEN_WINDOW == opsize))
            {
                __u8 snd_wscale = *(__u8 *)ptr;
                if (snd_wscale > 14) 
                {
                    net_info_ratelimited("%s: Illegal window scaling value %d >14 received\n",  __func__, snd_wscale);
                    snd_wscale = 14;  
                }
                return snd_wscale;
            }
            ptr += opsize-2;
            length -= opsize;
        }
    }
        return 0;
}
int set_tcp_state ( struct sk_buff* skb_client, struct sk_buff* skb_mirror )
{
    struct tcphdr* tcp_header;
    struct iphdr* ip_header;
    unsigned short port;
    union my_ip_type ip;
    int state_reset = 0;
    int old_state;
///	int new_state;

    if ( ! ( ( skb_client == NULL ) ^ ( skb_mirror == NULL ) ) )
        return state_reset;

    tcp_header = skb_client ? tcp_hdr ( skb_client ) : tcp_hdr ( skb_mirror );
    ip_header = skb_client ? ip_hdr ( skb_client ) : ip_hdr ( skb_mirror );
    port = ntohs ( skb_client ? tcp_header->source : tcp_header->dest );
    ip.i = skb_client ? ip_header->saddr : ip_header->daddr;

    old_state = tcp_state_get(&conn_info_set, ip, port);
    switch ( old_state )
    {
    case TCP_STATE_CLOSED:
    case TCP_STATE_LISTEN:
        if ( skb_mirror && tcp_header->syn && !tcp_header->ack )
            tcp_state_set(&conn_info_set, ip, port, TCP_STATE_SYN_SEND);

        if ( skb_client && tcp_header->syn && !tcp_header->ack )
            tcp_state_set(&conn_info_set, ip, port, TCP_STATE_SYN_RCVD);

        break;
    case TCP_STATE_SYN_SEND:
        if ( skb_client && tcp_header->syn && tcp_header->ack )
            tcp_state_set(&conn_info_set, ip, port, TCP_STATE_ESTABLISHED);

        break;
    case TCP_STATE_SYN_RCVD:
        if ( skb_mirror && tcp_header->syn && tcp_header->ack )
            tcp_state_set(&conn_info_set, ip, port, TCP_STATE_ESTABLISHED);

        break;
    case TCP_STATE_ESTABLISHED:
        if ( tcp_header->fin )
        {
            struct tcp_conn_info* this_tcp_info = TCP_CONN_INFO(&conn_info_set, ip, port);
            if(NULL == this_tcp_info)
                break;
            if ( skb_client )
                this_tcp_info->state = TCP_STATE_FIN_WAIT1;
            else
                this_tcp_info->state = TCP_STATE_CLOSE_WAIT1;

            this_tcp_info->seq_fin = ntohl ( tcp_header->seq );
        }
        break;
    case TCP_STATE_FIN_WAIT1:
        if ( skb_mirror && (after(ntohl ( tcp_header->ack_seq ), TCP_CONN_INFO(&conn_info_set, ip, port)->seq_fin) ) )
            tcp_state_set(&conn_info_set, ip, port, TCP_STATE_FIN_WAIT2);
    case TCP_STATE_FIN_WAIT2:
        if ( skb_mirror && tcp_header->fin )
        {
            struct tcp_conn_info* this_tcp_info = TCP_CONN_INFO(&conn_info_set, ip, port);
            if(NULL == this_tcp_info)
                break;
            this_tcp_info->state = TCP_STATE_TIME_WAIT;
            if ( this_tcp_info->seq_rmhost_fake > this_tcp_info->seq_rmhost )
                this_tcp_info->seq_fin = ntohl ( tcp_header->seq ) - ( this_tcp_info->seq_rmhost_fake - this_tcp_info->seq_rmhost );
            else
                this_tcp_info->seq_fin = ntohl ( tcp_header->seq ) + ( this_tcp_info->seq_rmhost - this_tcp_info->seq_rmhost_fake );
        }
        break;
    case TCP_STATE_TIME_WAIT:
        if ( skb_client && ( after(ntohl ( tcp_header->ack_seq ), TCP_CONN_INFO(&conn_info_set, ip, port)->seq_fin) ) )
        {
            tcp_state_reset(&conn_info_set, ip, port);
            state_reset = 1;
        }
        break;
    case TCP_STATE_CLOSE_WAIT1:
        if ( skb_client && (after(ntohl ( tcp_header->ack_seq ), TCP_CONN_INFO(&conn_info_set, ip, port)->seq_fin) ) )
            tcp_state_set(&conn_info_set, ip, port, TCP_STATE_CLOSE_WAIT2);

    case TCP_STATE_CLOSE_WAIT2:
        if ( skb_client && tcp_header->fin )
        {
            struct tcp_conn_info* this_tcp_info = TCP_CONN_INFO(&conn_info_set, ip, port);
            if(NULL == this_tcp_info)
                break;

            this_tcp_info->state = TCP_STATE_LAST_ACK;
            if ( this_tcp_info->seq_rmhost_fake > this_tcp_info->seq_rmhost )
                this_tcp_info->seq_fin = ntohl ( tcp_header->seq ) + ( this_tcp_info->seq_rmhost_fake - this_tcp_info->seq_rmhost );
            else
                this_tcp_info->seq_fin = ntohl ( tcp_header->seq ) - ( this_tcp_info->seq_rmhost - this_tcp_info->seq_rmhost_fake );
        }
        break;
    case TCP_STATE_LAST_ACK:
        if ( skb_mirror && after(ntohl ( tcp_header->ack_seq ), TCP_CONN_INFO(&conn_info_set, ip, port)->seq_fin) )
        {
            tcp_state_reset(&conn_info_set, ip, port);
            state_reset = 1;
        }
        break;
    }
///    new_state = tcp_state_get(&conn_info_set, ip, port);
///    if(old_state != new_state )
///        printk ( KERN_INFO "set_tcp_state %s trigger from %d to %d\n", skb_client ? "rmhost" : "mirror", old_state, new_state );

    return state_reset;
}
int tcp_playback_packet(union my_ip_type ip, u16 client_port, u8 cause)
{
    struct sk_buff* skb_mod = NULL;
    struct buf_data* bd = NULL;
    struct buf_data* bd_tmp = NULL;
    struct tcp_conn_info* this_tcp_info = TCP_CONN_INFO(&conn_info_set, ip, client_port);
    packet_buffer_t* packet_buf = this_tcp_info == NULL ? NULL :  & ( this_tcp_info->buffers.packet_buffer );
    struct tcphdr* tcp_header;
    unsigned char should_break = cause == CAUSE_BY_RETRAN ? 1 : 0;
    int state_reset = 0;
	unsigned long flags = 0;
//	int data_packet_counter = 0;
    if(NULL == this_tcp_info || NULL == packet_buf)
    {
        PRINT_ERROR("get this_tcp_info fail\n");
        return -1;
    }
    if(CAUSE_BY_RMHOST == cause && this_tcp_info->send_wnd_right_dege != this_tcp_info->playback_ptr)
	{
//		PRINT_DEBUG("line %d\n", __LINE__);
		return 0;
	}
	spin_lock(&packet_buf->packet_lock);
    do
    {
        u32 seq_server = 0;
        u32 seq_mirror = 0;
        u32 seq_tmp = 0;
        u32 data_size = 0;
		struct list_head* info_playback_ptr= 0;
        struct list_head* pkt_ptr_tmp = info_playback_ptr;
        struct iphdr* ip_header = NULL;
		u32 skb_seq = 0;
		u32 skb_ack_seq = 0;
		struct tcp_flags skb_tcp_flags;
		u32 skb_tsval = 0;
		u32 skb_nseq = 0;
		u32 log_nseq = 0;
		u32 info_seq_next;
		int info_state;
		u32 info_ackseq_last_from_target;
		u32 info_window_current;
		u16 info_mirror_port;
		u32 seq_rmhost = 0;
		u32 seq_rmhost_fake = 0;
		int info_flying_packet_count;
		u32 info_seq_last_ack;
		u32 info_seq_last_send;
		unsigned char info_init;
		int pkt_build_by_our = 0;

		spin_lock_irqsave(&this_tcp_info->info_lock, flags);
		seq_server = this_tcp_info->seq_server;
		seq_mirror = this_tcp_info->seq_mirror;
		info_playback_ptr = this_tcp_info->playback_ptr;
		log_nseq = (this_tcp_info->seq_last_send + (u32)this_tcp_info->last_send_size);
		info_seq_next = this_tcp_info->seq_next;
		info_state = this_tcp_info->state;
		info_ackseq_last_from_target = this_tcp_info->ackseq_last_from_target;
		info_window_current = this_tcp_info->window_current;
		seq_rmhost = this_tcp_info->seq_rmhost;
		seq_rmhost_fake = this_tcp_info->seq_rmhost_fake;
		info_mirror_port = this_tcp_info->mirror_port;
		info_flying_packet_count = this_tcp_info->flying_packet_count;
		info_seq_last_ack = this_tcp_info->seq_last_ack;
		info_seq_last_send = this_tcp_info->seq_last_send;
		info_init = this_tcp_info->init;
		spin_unlock_irqrestore(&this_tcp_info->info_lock, flags);

		pkt_ptr_tmp = info_playback_ptr;

        if ( cause != CAUSE_BY_RETRAN && (TCP_STATE_SYN_RCVD == info_state || TCP_STATE_FIN_WAIT1 == info_state || TCP_STATE_CLOSED == info_state) )
		{
			PRINT_INFO("line %d\n", __LINE__);
			break;
		}

		bd = pkt_buffer_peek_data_from_ptr ( packet_buf, &pkt_ptr_tmp );
		if ( NULL == bd )
		{
			PRINT_DEBUG("NULL == bd\n");
			break;
		}
        /*
         * peek new packet from packet buffer to see whether it's ack seq is newer
         * than the lastest packet from mirror
         */
		skb_mod = skb_copy ( bd->skb, GFP_ATOMIC );
		if(!skb_mod)
		{
			PRINT_ERROR("skb_copy fail\n");
			break;
		}
        tcp_header = tcp_hdr ( skb_mod );
        if ( seq_mirror > seq_server )
            seq_tmp = ntohl ( tcp_header->ack_seq ) + ( seq_mirror - seq_server );
        else
            seq_tmp = ntohl ( tcp_header->ack_seq ) - ( seq_server - seq_mirror );
		/**
		 * if the packet that we want to send has a ACK asq > lastest seq from mirror
		 * means we can't send this packet right now, 
		 * we build an ack to mirror to prevent unwanted retransmission from mirror
		 */
		if(cause != CAUSE_BY_RETRAN && after(seq_tmp, info_seq_next))
		{
			kfree_skb(skb_mod);
			break;
//             struct sk_buff* tmp = NULL;
// 			PRINT_DEBUG("seq_tmp: %u, seq_next: %u\n", seq_tmp, info_seq_next);
//             if( TCP_STATE_ESTABLISHED == info_state && !before(info_ackseq_last_from_target, ntohl(tcp_header->seq)) )
//             {
//                 u32 target_ack_seq = 0;
//                 if ( seq_mirror > seq_server )
//                     target_ack_seq = info_seq_next - ( seq_mirror - seq_server );
//                 else
//                     target_ack_seq = info_seq_next + ( seq_server - seq_mirror );
// 
// 				PRINT_DEBUG("build skb ack_seq: %u\n", info_seq_next);
//                 tmp = build_ack_sk_buff(skb_mod, target_ack_seq);
//                 kfree_skb(skb_mod);
//                 if(NULL == tmp)
// 				{
// 					PRINT_DEBUG("build_ack_sk_buff fail\n");
//                     break;
// 				}
//                 should_break = 1;
// 				pkt_build_by_our = 1;
//                 skb_mod = tmp;
//                 pkt_ptr_tmp = info_playback_ptr;
//             }
//             else
//             {
// 				PRINT_DEBUG("TCP_STATE_ESTABLISHED != this_tcp_info->state\n");
// 				PRINT_DEBUG("ackseq_last_from_target: %u, tcp_header->seq: %u\n", info_ackseq_last_from_target, ntohl(tcp_header->seq));
//                 kfree_skb(skb_mod);
//                 break;
//             }
        }
        tcp_header = tcp_hdr ( skb_mod );
        ip_header = ip_hdr ( skb_mod );
        data_size = ntohs ( ip_header->tot_len ) - ( ( ip_header->ihl ) <<2 ) - ( ( tcp_header->doff ) <<2 );
        //printk("[%s] data_size: %u, window_current: %u\n", __func__, data_size, this_tcp_info->window_current);
		if(cause != CAUSE_BY_RETRAN && data_size > info_window_current)
		{
			PRINT_DEBUG("data_size: %u, window_current: %u\n", data_size, info_window_current);
			should_break = 1;
		}
		/*
		 * if the ack seq of "ready to respond" packet is not used to ack new mirror packet
		 * we can remove it from packet buffer and send to mirror
		 */

        /*
         * SYN packet doesn't need to chenge seq number
         */
		if ( !(tcp_header->syn && !tcp_header->ack) )
		{
			/*
			 * If skb_mod is SYN-ACK, aka, mirror client case
			 * check if we has send fake SYN-ACK
			 */
			if(tcp_header->syn && seq_rmhost_fake)
			{
				struct tcp_flags* old_flags = (struct tcp_flags*)(&(tcp_header->ack_seq) + 1);
				struct tcp_flags new_flags;
				u32 new_seq = htonl(ntohl(tcp_header->seq) + 1);
				memmove(&new_flags, old_flags, sizeof(new_flags));
				set_tcp_state ( skb_mod, NULL ); // setup tcp state to TCP_STATE_ESTABLISHED
				this_tcp_info->seq_rmhost = ntohl(tcp_header->seq);
				seq_rmhost = this_tcp_info->seq_rmhost;
				/*
				 * make the SYN-ACK from rmhost to an ack packet
				 * to open received window
				 */
				new_flags.syn = 0;
				inet_proto_csum_replace2(&tcp_header->check, skb_mod, *(u16*)old_flags, *(u16*)(&new_flags), 0);
				skb_clear_hash(skb_mod);
				memmove(old_flags, &new_flags, sizeof(struct tcp_flags));
				inet_proto_csum_replace4(&tcp_header->check, skb_mod, tcp_header->seq, new_seq, 0);
				skb_clear_hash(skb_mod);
				tcp_header->seq = new_seq;
			}
			/*
			 * setup ack seql
			 */
			if ( seq_mirror > seq_server )
			{
				u32 new_seq = htonl ( ntohl ( tcp_header->ack_seq ) + ( seq_mirror - seq_server ) );
				inet_proto_csum_replace4(&tcp_header->check, skb_mod, tcp_header->ack_seq, new_seq, 0);
				skb_clear_hash(skb_mod);
				tcp_header->ack_seq = new_seq;
			}
			else
			{
				u32 new_seq = htonl ( ntohl ( tcp_header->ack_seq ) - ( seq_server - seq_mirror ) );
				inet_proto_csum_replace4(&tcp_header->check, skb_mod, tcp_header->ack_seq, new_seq, 0);
				skb_clear_hash(skb_mod);
				tcp_header->ack_seq = new_seq;
			}
			/*
			 * setup seq number
			 */
			if ( seq_rmhost_fake > seq_rmhost )
			{
				u32 new_seq = htonl ( ntohl ( tcp_header->seq ) + ( seq_rmhost_fake - seq_rmhost ) );
				inet_proto_csum_replace4(&tcp_header->check, skb_mod, tcp_header->seq, new_seq, 0);
				skb_clear_hash(skb_mod);
				tcp_header->seq = new_seq;
			}
			else if ( seq_rmhost_fake < seq_rmhost )
			{
				u32 new_seq = htonl ( ntohl ( tcp_header->seq ) - ( seq_rmhost - seq_rmhost_fake ) );
				inet_proto_csum_replace4(&tcp_header->check, skb_mod, tcp_header->seq, new_seq, 0);
				skb_clear_hash(skb_mod);
				tcp_header->seq = new_seq;
			}
		}
		skb_nseq = (ntohl(tcp_header->seq) + (u32)data_size);
		/*
		 * make sure the ready-to-send packet is continus with previcious send packets
		 */
		if(CAUSE_BY_RETRAN != cause && data_size && after(ntohl(tcp_header->seq), log_nseq))
		{
			PRINT_INFO("skb seq: %u, log seq: (%u, %zu)\n", ntohl(tcp_header->seq), this_tcp_info->seq_last_send, this_tcp_info->last_send_size);
			kfree_skb(skb_mod);
			break;
		}
		setup_options(skb_mod, this_tcp_info);
		pd_modify_ip_mac ( skb_mod );
		if(info_mirror_port)
		{
			/*
			 * modify from set_tp_port in openvswich/action.c
			 */
			inet_proto_csum_replace2(&(tcp_header->check), skb_mod, tcp_header->dest, htons(info_mirror_port), 0);
			tcp_header->dest = htons(info_mirror_port);
			skb_clear_hash(skb_mod);
		}
		/**
		 * send packet
		 */
		if(1 && CAUSE_BY_RETRAN != cause && data_size && info_flying_packet_count > MAX_FLYING_PACKET)
		{
			PRINT_DEBUG("del_skbmod %d: (%u, %u) size: %zu, %d, retrans: %d\n", cause, ntohl(tcp_header->seq), ntohl(tcp_header->ack_seq), data_size, info_flying_packet_count, this_tcp_info->dup_ack_counter);
			kfree_skb(skb_mod);
			break;
		}
		else
		{
			if(CAUSE_BY_RETRAN != cause && data_size)
				info_flying_packet_count++;

			PRINT_DEBUG("send_skbmod %d: (%u, %u) size: %u, %d\n", cause, ntohl(tcp_header->seq), ntohl(tcp_header->ack_seq), data_size, info_flying_packet_count);
			skb_tcp_flags = *(struct tcp_flags*)(&(tcp_header->ack_seq) + 1);
			skb_seq = ntohl(tcp_header->seq);
			skb_ack_seq = ntohl(tcp_header->ack_seq);
			skb_tsval = get_tsval(skb_mod);
			send_skbmod(skb_mod, bd->p);
			if(pkt_build_by_our)
				goto setup_timer_finish;
		}
		/**
		 * setup timer, only sended packet need to setup timer
		 */
		if(data_size || skb_tcp_flags.syn || skb_tcp_flags.fin)
		{
			u32 seq_target = 0;
			struct retransmit_info* info = NULL;

			if ( seq_rmhost_fake > seq_rmhost )
				seq_target = info_seq_last_ack - ( seq_rmhost_fake - seq_rmhost );
			else
				seq_target = info_seq_last_ack + ( seq_rmhost - seq_rmhost_fake );

			if(after(skb_seq + data_size, seq_target) && bd->should_delete == 0)
			{
				info = kmalloc(sizeof(struct retransmit_info), GFP_KERNEL); //free at retransmit_by_timer
				if(info)
				{
					info->client_port = client_port;
					info->ip = ip;
					info->list.next = info_playback_ptr->next;
					info->tcp_info = this_tcp_info;
					info->bd = bd;
					info->timer = &bd->timer;
					spin_lock(&(this_tcp_info->retranstimer_lock));
					if(try_to_del_timer_sync(&bd->timer) < 0)
						bd->retrans_times = 0;

					init_timer(&(bd->timer));
					setup_timer(&(bd->timer), retransmit_by_timer, (unsigned long)info);
					mod_timer(&(bd->timer), jiffies + (HZ << bd->retrans_times));
					spin_unlock(&(this_tcp_info->retranstimer_lock));
				}
			}
		}
setup_timer_finish:
		/*
		 * update connection state
		 */
		setup_playback_ptr(pkt_ptr_tmp, this_tcp_info);

		spin_lock_irqsave(&this_tcp_info->info_lock, flags);
		this_tcp_info->flying_packet_count = info_flying_packet_count;
		if( !(info_init & INIT_LAST_SEND) ||
			skb_seq == info_seq_last_send ||
			after(skb_seq, info_seq_last_send) ||
			(before(skb_seq, info_seq_last_send) && after(skb_nseq, log_nseq)))
		{
			u32 data_size_f = data_size;
			this_tcp_info->init |= INIT_LAST_SEND;
			if(skb_tcp_flags.syn || skb_tcp_flags.fin)
				data_size_f++;

			this_tcp_info->seq_last_send = skb_seq;
			this_tcp_info->ackseq_last_playback = skb_ack_seq;
			this_tcp_info->last_send_size = data_size_f;
			this_tcp_info->window_current -= data_size;
		}
// 		if(!(info_init & INIT_TSVAL) || after(skb_tsval, this_tcp_info->tsval_last_send))
// 		{
// 			this_tcp_info->init |= INIT_TSVAL;
// 			this_tcp_info->tsval_last_send = skb_tsval;
// 		}
		/*
		 * setup send_window's right edge
		 */
		pkt_ptr_tmp = this_tcp_info->send_wnd_right_dege;
		bd_tmp = pkt_buffer_peek_data_from_ptr ( packet_buf, &pkt_ptr_tmp );
		if(bd_tmp && (skb_seq == ntohl(tcp_hdr(bd_tmp->skb)->seq) || after(skb_seq, ntohl(tcp_hdr(bd_tmp->skb)->seq))))
			this_tcp_info->send_wnd_right_dege = this_tcp_info->playback_ptr;
		spin_unlock_irqrestore(&this_tcp_info->info_lock, flags);

		if(!should_break)
            state_reset = set_tcp_state ( bd->skb, NULL );

//         if(this_tcp_info->playback_ptr != this_tcp_info->send_wnd_right_dege)
//             break;

//		if(data_size && ++data_packet_counter > 6)
//			break;
    }while ( 0 == should_break && 0 == state_reset /*&& this_tcp_info->dup_ack_counter <= 1*/ );
	spin_unlock(&packet_buf->packet_lock);
    return 0;
}

void slide_send_window(struct tcp_conn_info* this_tcp_info)
{
	packet_buffer_t* pbuf = &(this_tcp_info->buffers.packet_buffer);
	struct list_head* head = NULL;
	struct list_head *iterator, *tmp;
	u32 seq_target = 0;
	u32 seq_rmhost_fake = this_tcp_info->seq_rmhost_fake;
	u32 seq_rmhost = this_tcp_info->seq_rmhost;
	struct pkt_buffer_node *pbn;

	spin_lock_bh(&pbuf->packet_lock);
	head = &pbuf->buffer_head;
	if(list_empty(head))
		goto out;
	/**
	 * seq_target is the last seq acked by mirror
	 */
	if ( seq_rmhost_fake > seq_rmhost )
		seq_target = this_tcp_info->seq_last_ack - ( seq_rmhost_fake - seq_rmhost );
	else
		seq_target = this_tcp_info->seq_last_ack + ( seq_rmhost - seq_rmhost_fake );

	list_for_each_safe(iterator, tmp, head)
	{
		struct tcphdr* tcp_header = NULL;
		struct iphdr* ip_header = NULL;
		u16 data_size = 0;
		u16 data_size_f = 0;
		u32 seq_next = 0;
		pbn = list_entry(iterator, struct pkt_buffer_node, list);
		ip_header = ip_hdr ( pbn->bd->skb );
		tcp_header = tcp_hdr ( pbn->bd->skb );
		data_size = ntohs ( ip_header->tot_len ) - ( ( ip_header->ihl ) <<2 ) - ( ( tcp_header->doff ) <<2 );
		if(tcp_header->syn || tcp_header->fin)
			data_size_f = data_size + 1;
		else
			data_size_f = data_size;

		seq_next = ntohl(tcp_hdr ( pbn->bd->skb )->seq) + (u32)data_size_f;
/*		if( abs(seq_target - ntohl(tcp_hdr ( pbn->bd->skb )->seq) + data_size_f) < U32_MAX>>1 
			&& ntohl(tcp_hdr ( pbn->bd->skb )->seq) + data_size_f <= seq_target )*/
		if(seq_next == seq_target || before(seq_next, seq_target) || pbn->bd->should_delete)
		{
			if( iterator == this_tcp_info->playback_ptr )
				break;

			if(pkt_buffer_delete(iterator, pbuf) != 0)
				break;

			if(data_size && this_tcp_info->flying_packet_count)
				this_tcp_info->flying_packet_count--;
		}
		else
			break;
	}
out:
	spin_unlock_bh(&pbuf->packet_lock);
	return;
}

u32 seq_to_target(const u32 seq_mirror, const struct tcp_conn_info* tcp_info)
{
    u32 initseq_target = tcp_info->seq_server;
    u32 initseq_mirror = tcp_info->seq_mirror;
    if ( initseq_target > initseq_mirror )
        return seq_mirror + ( initseq_target - initseq_mirror );
    else
        return seq_mirror - ( initseq_mirror - initseq_target );
}

u32 seq_to_mirror(const u32 seq_target, const struct tcp_conn_info* tcp_info)
{
    u32 initseq_target = tcp_info->seq_server;
    u32 initseq_mirror = tcp_info->seq_mirror;
    if ( initseq_mirror > initseq_target )
        return seq_target + ( initseq_mirror - initseq_target );
    else
        return seq_target - ( initseq_target - initseq_mirror );
}

struct list_head* find_retransmit_ptr(const u32 seq_target, struct tcp_conn_info* this_tcp_info)
{
    u32 real_target_seq;
    const u32 seq_rmhost_fake = this_tcp_info->seq_rmhost_fake;
    const u32 seq_rmhost = this_tcp_info->seq_rmhost;
    struct pkt_buffer_node *pbn;
    struct list_head* iterator = NULL;
	packet_buffer_t* pbuf = &(this_tcp_info->buffers.packet_buffer);
    struct list_head* head = NULL;
    struct list_head* ret = NULL;
    struct iphdr* ip_header;
    struct tcphdr* tcp_header;
    size_t data_size;
	struct list_head* retp = kmalloc(sizeof(struct list_head), GFP_KERNEL); //free at packet_dispatcher line 340 352
	if(!retp)
		return NULL;

	spin_lock_bh(&pbuf->packet_lock);
	head = &pbuf->buffer_head;
	ret = head;
    if(list_empty(head))
	{
		kfree(retp);
		retp = NULL;
		goto out;
	}
    if ( seq_rmhost_fake > seq_rmhost )
        real_target_seq = seq_target - ( seq_rmhost_fake - seq_rmhost );
    else
        real_target_seq = seq_target + ( seq_rmhost - seq_rmhost_fake );

    list_for_each(iterator, head)
    {
        pbn = list_entry(iterator, struct pkt_buffer_node, list);
        ip_header = ip_hdr(pbn->bd->skb);
        tcp_header = tcp_hdr(pbn->bd->skb);
        data_size = ntohs ( ip_header->tot_len ) - ( ( ip_header->ihl ) <<2 ) - ( ( tcp_header->doff ) <<2 );
        if((ntohl(tcp_header->seq) == real_target_seq || before(ntohl(tcp_header->seq), real_target_seq))
			&& after(ntohl(tcp_header->seq) + data_size, real_target_seq))
		{
			PRINT_DEBUG("[%s] target_seq: %u, real: %u, get: %zu(%u,%zu) at %p, ret %p\n", __func__, seq_target, real_target_seq, ntohl(tcp_header->seq) + data_size, ntohl(tcp_header->seq), data_size, pbn->bd, ret);
			retp->next = ret->next;
            goto out;
		}
        ret = iterator;
    }
    ret = NULL;
	kfree(retp);
	retp = NULL;
out:
	spin_unlock_bh(&pbuf->packet_lock);
    return retp;
}

void setup_playback_ptr(struct list_head* target_prt, struct tcp_conn_info* this_tcp_info)
{
	if(NULL == target_prt || LIST_POISON1 == target_prt || LIST_POISON2 == target_prt)
	{
		PRINT_ERROR("target ptr is invalid");
		return;
	}
	this_tcp_info->playback_ptr = target_prt;
}

int retransmit_form_ptr(struct list_head* ptr, union my_ip_type ip, u16 port, struct tcp_conn_info* this_tcp_info)
{
	int ret = 0;
	if(NULL == ptr)
	{
		PRINT_ERROR("retrans ptr is NULL");
		return -1;
	}
	setup_playback_ptr(ptr, this_tcp_info);
	ret = tcp_playback_packet(ip, port, CAUSE_BY_RETRAN);
	return ret;
}

void retransmit_by_timer(unsigned long ptr)
{
    struct retransmit_info* info = (void*)ptr;
    //unsigned long tmp = ptr;
    //this_retrans_info = tmp;
    struct tcp_conn_info* this_tcp_info = info->tcp_info;
    struct list_head* retrans_ptr_tmp = &info->list;
    struct list_head* retrans_ptr = &info->list;
    struct buf_data* bd;
    union my_ip_type ip = info->ip;
    u16 client_port = info->client_port;
	packet_buffer_t* pbuf = &this_tcp_info->buffers.packet_buffer;
    //kfree(info);
    //printk("[%s] ptr: %lu\n", __func__, 123);
    spin_lock_bh(&pbuf->packet_lock);
    bd = pkt_buffer_peek_data_from_ptr ( & ( this_tcp_info->buffers.packet_buffer ), &retrans_ptr_tmp );
	spin_unlock_bh(&pbuf->packet_lock);
	if(NULL == bd)
		goto exit;

    if(bd->retrans_times < 4)
        bd->retrans_times++;

	rcu_read_lock();
    retransmit_form_ptr(retrans_ptr, ip, client_port, this_tcp_info);
	rcu_read_unlock();
exit:
	if(bd->should_delete && spin_trylock_bh(&pbuf->packet_lock))
	{
		pkt_buffer_delete(retrans_ptr_tmp->next, & ( this_tcp_info->buffers.packet_buffer ));
		spin_unlock_bh(&pbuf->packet_lock);
	}

	kfree(info);
}

int packet_buff_limiter(struct tcp_conn_info* this_tcp_info)
{
	struct sk_buff* send_skb = NULL;
	struct sk_buff* ack_skb = NULL;
	struct sk_buff* info_last_ack_send_from_target = NULL;
	char over_limit = 0;
	int node_count = 0;

	spin_lock_bh(&this_tcp_info->info_lock);
	info_last_ack_send_from_target = this_tcp_info->last_ack_send_from_target;
	node_count = this_tcp_info->buffers.packet_buffer.node_count;
	spin_unlock_bh(&this_tcp_info->info_lock);

	if(node_count < PACKET_BUFFER_SOFT_LIMIT || info_last_ack_send_from_target == NULL)
		return 0;

	ack_skb = skb_clone (info_last_ack_send_from_target, GFP_ATOMIC);
	
	if(1 && node_count > PACKET_BUFFER_HARD_LIMIT)
	{
		PRINT_INFO("node_count: %d\n", node_count);
		send_skb = skb_copy (ack_skb, GFP_ATOMIC);
		tcp_hdr(send_skb)->window = 0;
		send_skbmod(send_skb, this_tcp_info->other_args_from_target);
		over_limit = 1;
	}
	else if(node_count > PACKET_BUFFER_SOFT_LIMIT)
	{
		PRINT_INFO("node_count: %d\n", node_count);
		send_skb = skb_clone (ack_skb, GFP_ATOMIC);
		send_skbmod(send_skb, this_tcp_info->other_args_from_target);
		send_skb = skb_clone (ack_skb, GFP_ATOMIC);
		send_skbmod(send_skb, this_tcp_info->other_args_from_target);
		send_skb = skb_clone (ack_skb, GFP_ATOMIC);
		send_skbmod(send_skb, this_tcp_info->other_args_from_target);
		over_limit = 2;
	}
	kfree_skb(ack_skb);
	if(over_limit == 2)
	{
		spin_lock_bh(&this_tcp_info->info_lock);
		if(info_last_ack_send_from_target == this_tcp_info->last_ack_send_from_target)
		{
			this_tcp_info->last_ack_send_from_target = NULL;
			kfree_skb(info_last_ack_send_from_target);
		}
		spin_unlock_bh(&this_tcp_info->info_lock);
	}
	if(over_limit == 1)
		return 1;
	else
		return 0;
}
