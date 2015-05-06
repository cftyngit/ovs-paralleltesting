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
    if (pdata && tcp_info->tsval_current) 
    {
        const u32 ftsval = FAKE_TSVAL;
        const char timestamp[] = {TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP};
        memset(pdata, 0x01, (((TCPOLEN_TIMESTAMP>>2)+1)<<2) - TCPOLEN_TIMESTAMP);
        pdata+=(((TCPOLEN_TIMESTAMP>>2)+1)<<2) - TCPOLEN_TIMESTAMP;
        memmove(pdata, timestamp, sizeof(timestamp));
        pdata+=sizeof(timestamp);
        put_unaligned_be32(ftsval, pdata);
        pdata+=4;
        put_unaligned_be32(tcp_info->tsval_current, pdata);
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
    size_t data_size = ntohs ( sk_ip_header->tot_len ) - ( ( sk_ip_header->ihl ) <<2 ) - ( ( sk_tcp_header->doff ) <<2 );
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
    tcp_header->ack_seq = htonl( ntohl(sk_tcp_header->seq) + data_size + (sk_tcp_header->syn || sk_tcp_header->fin ? 1 : 0));
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
    if (pdata && tcp_info->tsval_current) 
    {
        const char timestamp[] = {TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP};
        memset(pdata, 0x01, (((TCPOLEN_TIMESTAMP>>2)+1)<<2) - TCPOLEN_TIMESTAMP);
        pdata+=(((TCPOLEN_TIMESTAMP>>2)+1)<<2) - TCPOLEN_TIMESTAMP;
        memmove(pdata, timestamp, sizeof(timestamp));
        pdata+=sizeof(timestamp);
        put_unaligned_be32(tcp_info->tsval_last_send, pdata);
        pdata+=4;
        put_unaligned_be32(tcp_info->tsval_current, pdata);
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
    ip_header->tot_len = htons(skb_new->len) + (((TCPOLEN_TIMESTAMP>>2)+1)<<2);
    ip_header->check = 0;
    ip_send_check(ip_header);
    /* caculate checksum */
    pdata = skb_put(skb_new, (((TCPOLEN_TIMESTAMP>>2)+1)<<2));
    if (pdata && skb_tsecr) 
    {
        const u32 ftsval = get_tsval(skb);
        const char timestamp[] = {TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP};
        memset(pdata, 0x01, (((TCPOLEN_TIMESTAMP>>2)+1)<<2) - TCPOLEN_TIMESTAMP);
        pdata += (((TCPOLEN_TIMESTAMP>>2)+1)<<2) - TCPOLEN_TIMESTAMP;
        memmove(pdata, timestamp, sizeof(timestamp));
        pdata+=sizeof(timestamp);
        put_unaligned_be32(ftsval, pdata);
        pdata+=4;
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
	u32* new_options = kmalloc(length, GFP_ATOMIC);
	u32* old_options = (u32 *)(tcp_header + 1);
	int opt_l = length / sizeof(u32);
	int i = 0;
	unsigned char* ptr = (unsigned char*)new_options;

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
					u32 pkt_tsval = get_unaligned_be32(ptr + 0);
					if(tcp_info->tsval_last_send > pkt_tsval)
						put_unaligned_be32(tcp_info->tsval_last_send, (void*)ptr+0);

					put_unaligned_be32(tcp_info->tsval_current, (void*)ptr+4);
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
        if ( skb_mirror && ( ntohl ( tcp_header->ack_seq ) > TCP_CONN_INFO(&conn_info_set, ip, port)->seq_fin ) )
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
        if ( skb_client && ( ntohl ( tcp_header->ack_seq ) > TCP_CONN_INFO(&conn_info_set, ip, port)->seq_fin ) )
        {
            tcp_state_reset(&conn_info_set, ip, port);
            state_reset = 1;
        }
        break;
    case TCP_STATE_CLOSE_WAIT1:
        if ( skb_client && ( ntohl ( tcp_header->ack_seq ) > TCP_CONN_INFO(&conn_info_set, ip, port)->seq_fin ) )
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
        if ( skb_mirror && ntohl ( tcp_header->ack_seq ) > TCP_CONN_INFO(&conn_info_set, ip, port)->seq_fin )
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
	int data_packet_counter = 0;
    if(NULL == this_tcp_info || NULL == packet_buf)
    {
        PRINT_ERROR("[%s] get this_tcp_info fail\n", __func__);
        return -1;
    }
    if(CAUSE_BY_RMHOST == cause && this_tcp_info->send_wnd_right_dege != this_tcp_info->playback_ptr)
	{
		PRINT_DEBUG("[%s] line %d\n", __func__, __LINE__);
        return 0;
	}
	spin_lock(&packet_buf->packet_lock);
    do
    {
        int tcp_s = tcp_state_get(&conn_info_set, ip, client_port);
        u32 seq_server = this_tcp_info->seq_server;
        u32 seq_mirror = this_tcp_info->seq_mirror;
        u32 seq_tmp = 0;
        size_t data_size = 0;
        struct list_head* pkt_ptr_tmp = this_tcp_info->playback_ptr;
        struct iphdr* ip_header = NULL;

        if ( cause != CAUSE_BY_RETRAN && (TCP_STATE_SYN_RCVD == tcp_s || TCP_STATE_FIN_WAIT1 == tcp_s || TCP_STATE_CLOSED == tcp_s) )
		{
			PRINT_DEBUG("[%s] line %d\n", __func__, __LINE__);
            break;
		}

		bd = pkt_buffer_peek_data_from_ptr ( packet_buf, &pkt_ptr_tmp );
        if ( NULL == bd )
		{
			PRINT_DEBUG("[%s] NULL == bd\n", __func__);
            break;
		}
		if(cause == CAUSE_BY_RETRAN)
			printk(KERN_EMERG "[%s] retrans: %p, ptr: %p\n", __func__, bd, this_tcp_info->playback_ptr);
        /*
         * peek new packet from packet buffer to see whether it's ack seq is newer
         * than the lastest packet from mirror
         */

        skb_mod = skb_copy ( bd->skb, GFP_ATOMIC );
        tcp_header = tcp_hdr ( skb_mod );
        if ( seq_mirror > seq_server )
            seq_tmp = ntohl ( tcp_header->ack_seq ) + ( seq_mirror - seq_server );
        else
            seq_tmp = ntohl ( tcp_header->ack_seq ) - ( seq_server - seq_mirror );

        if(cause != CAUSE_BY_RETRAN && seq_tmp > this_tcp_info->seq_next)
        {
            struct sk_buff* tmp = NULL;
			PRINT_DEBUG("[%s] seq_tmp: %u, seq_next: %u\n", __func__, seq_tmp, this_tcp_info->seq_next);
            if( TCP_STATE_ESTABLISHED == this_tcp_info->state && this_tcp_info->ackseq_last_from_target >= ntohl(tcp_header->seq))
            {
                u32 target_ack_seq = 0;
                if ( seq_mirror > seq_server )
                    target_ack_seq = this_tcp_info->seq_next - ( seq_mirror - seq_server );
                else
                    target_ack_seq = this_tcp_info->seq_next + ( seq_server - seq_mirror );

                tmp = build_ack_sk_buff(skb_mod, target_ack_seq);
                kfree_skb(skb_mod);
                if(NULL == tmp)
				{
					PRINT_DEBUG("[%s] build_ack_sk_buff fail\n", __func__);
                    break;
				}
                should_break = 1;
                skb_mod = tmp;
                pkt_ptr_tmp = this_tcp_info->playback_ptr;
            }
            else
            {
				PRINT_DEBUG("[%s] TCP_STATE_ESTABLISHED != this_tcp_info->state\n", __func__);
				PRINT_DEBUG("[%s] ackseq_last_from_target: %u, tcp_header->seq: %u\n", __func__, this_tcp_info->ackseq_last_from_target, ntohl(tcp_header->seq));
                kfree_skb(skb_mod);
                break;
            }
        }
        tcp_header = tcp_hdr ( skb_mod );
        ip_header = ip_hdr ( skb_mod );
        data_size = ntohs ( ip_header->tot_len ) - ( ( ip_header->ihl ) <<2 ) - ( ( tcp_header->doff ) <<2 );
        //printk("[%s] data_size: %u, window_current: %u\n", __func__, data_size, this_tcp_info->window_current);
        if(cause != CAUSE_BY_RETRAN && data_size > this_tcp_info->window_current)
        {
			PRINT_DEBUG("[%s] data_size: %zu, window_current: %u\n", __func__, data_size, this_tcp_info->window_current);
            kfree_skb(skb_mod);
            break;
        }
        /*
         * if the ack seq of "ready to respond" packet is not used to ack new mirror packet
         * we can remove it from packet buffer and send to mirror
         */

		if(data_size || tcp_header->syn || tcp_header->fin)
		{
			u32 seq_target = 0;
			u32 seq_rmhost_fake = this_tcp_info->seq_rmhost_fake;
			u32 seq_rmhost = this_tcp_info->seq_rmhost;
			struct retransmit_info* info = NULL;

			if ( seq_rmhost_fake > seq_rmhost )
				seq_target = this_tcp_info->seq_last_ack - ( seq_rmhost_fake - seq_rmhost );
			else
				seq_target = this_tcp_info->seq_last_ack + ( seq_rmhost - seq_rmhost_fake );
			if(cause == CAUSE_BY_RETRAN)
				printk(KERN_EMERG "[%s] retrans timer: %p, next_seq: %u, acked_seq: %u, ptr: %p\n", __func__, bd, ntohl(tcp_header->seq), seq_target, this_tcp_info->playback_ptr);
			if(ntohl(tcp_header->seq) + data_size > seq_target)
			{
				info = kmalloc(sizeof(struct retransmit_info), GFP_ATOMIC);
				info->client_port = client_port;
				info->ip = ip;
				info->list.next = this_tcp_info->playback_ptr->next;
				info->tcp_info = this_tcp_info;
				info->bd = bd;
				info->timer = &bd->timer;
				PRINT_DEBUG("[%s] retrans info: %p\n", __func__, info);
				spin_lock(&(this_tcp_info->retranstimer_lock));
				if(timer_pending(&(bd->timer)))
				{
					del_timer_sync(&(bd->timer));
					init_timer(&(bd->timer));
				}
				setup_timer(&(bd->timer), retransmit_by_timer, (unsigned long)info);
				//mod_timer(&(bd->timer), jiffies + msecs_to_jiffies(200));
				PRINT_DEBUG("[%s] setup_timer: %u\n", __func__, bd->retrans_times);
				mod_timer(&(bd->timer), jiffies + (HZ << bd->retrans_times));
				spin_unlock(&(this_tcp_info->retranstimer_lock));
			}
		}

        setup_playback_ptr(pkt_ptr_tmp, this_tcp_info);
        /*
         * setup send_window's right edge
         */
        pkt_ptr_tmp = this_tcp_info->send_wnd_right_dege;
        bd_tmp = pkt_buffer_peek_data_from_ptr ( packet_buf, &pkt_ptr_tmp );
        //printk("[%s] bd_tmp: %p, tcp_header->seq: %u\n", __func__, bd_tmp, ntohl(tcp_header->seq));
        if(bd_tmp && ntohl(tcp_header->seq) >= ntohl(tcp_hdr(bd_tmp->skb)->seq))
            this_tcp_info->send_wnd_right_dege = this_tcp_info->playback_ptr;
        /*
         * SYN packet doesn't need to chenge seq number
         */
		if ( !(tcp_header->syn && !tcp_header->ack) )
		{
			u32 seq_rmhost = this_tcp_info->seq_rmhost;
			u32 seq_rmhost_fake = this_tcp_info->seq_rmhost_fake;
			/*
			 * If skb_mod is SYN-ACK, aka, mirror client case
			 * check if we has send fake SYN-ACK
			 */
			if(tcp_header->syn && this_tcp_info->seq_rmhost_fake)
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
        this_tcp_info->window_current -= data_size;
        /*
        if(this_tcp_info->mirror_port)
            tcp_header->dest = htons(this_tcp_info->mirror_port);
        */
        if(get_tsval(skb_mod) > this_tcp_info->tsval_last_send)
            this_tcp_info->tsval_last_send = get_tsval(skb_mod);
		setup_options(skb_mod, this_tcp_info);
        pd_modify_ip_mac ( skb_mod );
		if(this_tcp_info->mirror_port)
		{
			/*
			 * modify from set_tp_port in openvswich/action.c
			 */
			inet_proto_csum_replace2(&(tcp_header->check), skb_mod, tcp_header->dest, htons(this_tcp_info->mirror_port), 0);
			tcp_header->dest = htons(this_tcp_info->mirror_port);
			skb_clear_hash(skb_mod);
		}
        this_tcp_info->seq_last_send = ntohl(tcp_header->seq);
        this_tcp_info->ackseq_last_playback = ntohl(tcp_header->ack_seq);
        this_tcp_info->last_send_size = data_size;

		PRINT_DEBUG("[%s] send_skbmod: %u, %u\n", __func__, ntohl(tcp_header->seq), ntohl(tcp_header->ack_seq));
        //send_skbmod ( bd->p, skb_mod );
		send_skbmod(skb_mod, bd->p);
		
        if(!should_break)
            state_reset = set_tcp_state ( bd->skb, NULL );

        if(this_tcp_info->playback_ptr != this_tcp_info->send_wnd_right_dege)
            break;

		if(data_size && ++data_packet_counter > 6)
			break;
    }while ( 0 == should_break && 0 == state_reset && this_tcp_info->dup_ack_counter <= 1 );
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

	spin_lock(&pbuf->packet_lock);
	head = &pbuf->buffer_head;
    if(list_empty(head))
        goto out;

    if ( seq_rmhost_fake > seq_rmhost )
        seq_target = this_tcp_info->seq_last_ack - ( seq_rmhost_fake - seq_rmhost );
    else
        seq_target = this_tcp_info->seq_last_ack + ( seq_rmhost - seq_rmhost_fake );

    list_for_each_safe(iterator, tmp, head)
    {
		struct tcphdr* tcp_header = NULL;
		struct iphdr* ip_header = NULL;
		u16 data_size = 0;
        pbn = list_entry(iterator, struct pkt_buffer_node, list);
		ip_header = ip_hdr ( pbn->bd->skb );
		tcp_header = tcp_hdr ( pbn->bd->skb );
		data_size = ntohs ( ip_header->tot_len ) - ( ( ip_header->ihl ) <<2 ) - ( ( tcp_header->doff ) <<2 );
		if(tcp_header->syn || tcp_header->fin)
			data_size += 1;

        if(ntohl(tcp_hdr ( pbn->bd->skb )->seq) + data_size <= seq_target )
        {
			int ret = 0, ret2 = 0;
            if( iterator == this_tcp_info->playback_ptr )
                break;

///            printk("[%s] del pkt %p %u\n", __func__, iterator, ntohl(tcp_hdr ( pbn->bd->skb )->seq));
            //printk("[%s] del pkt \n", __func__, ntohl(tcp_hdr ( pbn->bd->skb )->seq));
            
//			if(timer_pending(&(pbn->bd->timer)))
//			printk(KERN_EMERG "[%s] del pkt %p, seq_target: %u\n", __func__, pbn->bd, seq_target);
//			printk(KERN_EMERG "[%s] seq_origin %u, seq_new: %u, seq_target: %u\n", __func__, ntohl(tcp_header->seq), ntohl(tcp_header->seq) + data_size, seq_target);
			ret2 = timer_pending(&pbn->bd->timer);
			ret = try_to_del_timer_sync(&pbn->bd->timer);
			printk(KERN_EMERG "[%s] bd: %p, pending: %d, try_del: %d\n", __func__, pbn->bd, ret2, ret);
			if(ret < 0)
				break;
			list_del(iterator);
            kfree(pbn->bd->p);
            kfree_skb(pbn->bd->skb);
            kfree(pbn->bd);
            kfree(pbn);
        }
        else
            break;
    }
out:
	spin_unlock(&pbuf->packet_lock);
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
    struct list_head* ret = head;
    struct iphdr* ip_header;
    struct tcphdr* tcp_header;
    size_t data_size;

	spin_lock(&pbuf->packet_lock);
	head = &pbuf->buffer_head;
    if(list_empty(head))
	{
		spin_unlock(&pbuf->packet_lock);
        return NULL;
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
///        printk("[%s] %p check seq: %u, target_seq: %u\n", __func__, iterator, ntohl(tcp_hdr ( pbn->bd->skb )->seq), real_target_seq);
        if(ntohl(tcp_header->seq) <= real_target_seq && ntohl(tcp_header->seq) + data_size > real_target_seq)
		{
			PRINT_DEBUG("[%s] target_seq: %u, real: %u, get: %zu\n", __func__, seq_target, real_target_seq, ntohl(tcp_header->seq) + data_size);
            goto out;
		}
        ret = iterator;
    }
    ret = NULL;
out:
	spin_unlock(&pbuf->packet_lock);
    return ret;
}

void setup_playback_ptr(struct list_head* target_prt, struct tcp_conn_info* this_tcp_info)
{
    if(NULL == target_prt || LIST_POISON1 == target_prt || LIST_POISON2 == target_prt)
        return;
    spin_lock(&(this_tcp_info->playback_ptr_lock));
    this_tcp_info->playback_ptr = target_prt;
    spin_unlock(&(this_tcp_info->playback_ptr_lock));
}

int retransmit_form_ptr(struct list_head* ptr, union my_ip_type ip, u16 port, struct tcp_conn_info* this_tcp_info)
{
    if(NULL == ptr)
        return -1;

    setup_playback_ptr(ptr, this_tcp_info);
    return tcp_playback_packet(ip, port, CAUSE_BY_RETRAN);
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
    //kfree(info);
    //printk("[%s] ptr: %lu\n", __func__, 123);
    
    bd = pkt_buffer_peek_data_from_ptr ( & ( this_tcp_info->buffers.packet_buffer ), &retrans_ptr_tmp );
    if(NULL == bd)
        return;
	printk(KERN_EMERG "[%s] get bd: %p, should bd: %p, timer: %p", __func__, bd, info->bd, info->timer);
    if(bd->retrans_times < 7)
        bd->retrans_times++;
//	PRINT_DEBUG("[%s] before retransmit_form_ptr\n", __func__);
	rcu_read_lock();
    retransmit_form_ptr(retrans_ptr, ip, client_port, this_tcp_info);
	rcu_read_unlock();
}

