#include "tcp.h"

extern struct host_conn_info_set conn_info_set;

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
        printk("send packet by skb failed.\n");
        sock_release(sock);
        return -1;
    }
    printk("send packet by skb success.\n");
    sock_release(sock);
    return 0;
}

int ack_this_packet(const struct sk_buff* skb)
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

    sock_create_kern(PF_INET, SOCK_STREAM, 0, &sock);
    net = sock_net((const struct sock *) sock->sk);
    skb_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + LL_RESERVED_SPACE(netdev);
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
    tcp_header->ack_seq = htonl( ntohl(sk_tcp_header->seq) + data_size );
    tcp_header->seq = sk_tcp_header->ack_seq;
    tcp_header->source = sk_tcp_header->dest;
    tcp_header->dest = sk_tcp_header->source;
    tcp_header->doff = (u32)( sizeof(struct tcphdr) ) >> 2;
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
    ip_header->tot_len = htons(skb_new->len);
    ip_header->check = 0;
    /* caculate checksum */
    ip_send_check(ip_header);
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
        printk("send packet by skb failed.\n");
        sock_release(sock);
        return -1;
    }
    printk("send packet by skb success.\n");
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
    //const unsigned char tcp_options[] = "";
    //u8 *pdata = NULL;
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

    //skb_put(skb_new, sizeof(struct ethhdr));
    /* 分配内存给ip头 */
    skb_set_network_header(skb_new, 0);
    skb_put(skb_new, sizeof(struct iphdr));
    /* 分配内存给tcp头 */
    skb_set_transport_header(skb_new, sizeof(struct iphdr));
    skb_put(skb_new, sizeof(struct tcphdr));
    //return NULL;
    /* construct tcp header in skb */
    tcp_header = tcp_hdr(skb_new);
    //memcpy (tcp_header, sk_tcp_header, sizeof(struct tcphdr));

    //tcp_header->doff = (u32)( sizeof(struct tcphdr) ) >> 2;
    //tcp_header->ack = 1;
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
     //eth_header = eth_hdr(skb_new);
     memset (eth_header, 0, sizeof(struct ethhdr));
     memcpy(eth_header->h_dest, sk_eth_header->h_dest, ETH_ALEN);
     memcpy(eth_header->h_source, sk_eth_header->h_source, ETH_ALEN);
     eth_header->h_proto = htons(ETH_P_IP);
     //printk("[%s] skb->head: %p\n", __func__, skb_new->head);
     //printk("[%s] eth_header: %p, eth_hdr: %p\n", __func__, eth_header, eth_hdr(skb_new));
     //printk("[%s] ip_header: %p, ip_hdr: %p\n", __func__, ip_header, ip_hdr(skb_new));
     //printk("[%s] tcp_header: %p, tcp_hdr: %p\n", __func__, tcp_header, tcp_hdr(skb_new));
     //print_skb(skb_new);
     return skb_new;
}

void setup_options(struct sk_buff* skb_mod, const struct tcp_conn_info* tcp_info)
{
    const struct tcphdr* tcp_header = tcp_hdr(skb_mod);
    int length = (tcp_header->doff * 4) - sizeof(struct tcphdr);
    const unsigned char* ptr = (const unsigned char *)(tcp_header + 1);

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
                    put_unaligned_be32(tcp_info->tsval_current, (void*)ptr+4);
                }
                break;
            case TCPOPT_SACK_PERM:
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
    int old_state, new_state;

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
    new_state = tcp_state_get(&conn_info_set, ip, port);
    if(old_state != new_state )
        printk ( KERN_INFO "set_tcp_state %s trigger from %d to %d\n", skb_client ? "client" : "server", old_state, new_state );

    return state_reset;
}
int tcp_playback_packet(union my_ip_type ip, u16 client_port, u8 cause)
{
    struct sk_buff* skb_mod = NULL;
    struct buf_data* bd = NULL;
    struct tcp_conn_info* this_tcp_info = TCP_CONN_INFO(&conn_info_set, ip, client_port);
    struct list_head* packet_buf = this_tcp_info == NULL ? NULL :  & ( this_tcp_info->buffers.packet_buffer );
    struct tcphdr* tcp_header;
    unsigned char should_break = 0;
    int state_reset = 0;
    printk("into function: %s\n", __func__);
    if(NULL == this_tcp_info || NULL == packet_buf)
    {
        printk("[%s] get this_tcp_info fail\n", __func__);
        return -1;
    }

    while ( !should_break && 0 == state_reset )
    {
        int tcp_s = tcp_state_get(&conn_info_set, ip, client_port);
        u32 seq_server = this_tcp_info->seq_server;
        u32 seq_mirror = this_tcp_info->seq_mirror;
        u32 seq_tmp = 0;
        size_t data_size = 0;
        struct list_head* pkt_ptr_tmp = this_tcp_info->playback_ptr;
        struct iphdr* ip_header = NULL;
        
        if ( TCP_STATE_SYN_RCVD == tcp_s || TCP_STATE_FIN_WAIT1 == tcp_s || TCP_STATE_CLOSED == tcp_s )
            break;
        
        bd = pkt_buffer_peek_data_from_ptr ( packet_buf, &pkt_ptr_tmp );
        if ( NULL == bd )
            break;
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
        
        printk("seq_t %u, seq_c %u, seq_next %u\n", seq_tmp, this_tcp_info->seq_current, this_tcp_info->seq_next);
        if(seq_tmp > this_tcp_info->seq_next)
        {
            struct sk_buff* tmp = NULL;
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
                    break;

                should_break = 1;
                skb_mod = tmp;
                pkt_ptr_tmp = this_tcp_info->playback_ptr;
            }
            else
            {
                kfree_skb(skb_mod);
                break;
            }
        }
        tcp_header = tcp_hdr ( skb_mod );
        ip_header = ip_hdr ( skb_mod );
        data_size = ntohs ( ip_header->tot_len ) - ( ( ip_header->ihl ) <<2 ) - ( ( tcp_header->doff ) <<2 );
        printk("%u window_c %u, data_size %u\n", ntohl ( tcp_header->seq ), this_tcp_info->window_current, data_size);
        if( data_size > this_tcp_info->window_current)
        {
            kfree_skb(skb_mod);
            break;
        }
        /*
         * if the ack seq of "ready to respond" packet is not used to ack new mirror packet
         * we can remove it from packet buffer and send to mirror
         */
        this_tcp_info->playback_ptr = pkt_ptr_tmp;
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
                set_tcp_state ( skb_mod, NULL ); // setup tcp state to TCP_STATE_ESTABLISHED
                this_tcp_info->seq_rmhost = ntohl(tcp_header->seq);
                seq_rmhost = this_tcp_info->seq_rmhost;
                /*
                 * make the SYN-ACK from rmhost to an ack packet
                 * to open received window
                 */
                tcp_header->syn = 0;
                tcp_header->seq = htonl(ntohl(tcp_header->seq) + 1);
                //
                ////kfree_skb(skb_mod);
                ////goto send_skmod_finish;
                //return 0;
            }
            /*
             * setup ack seql
             */
            if ( seq_mirror > seq_server )
                tcp_header->ack_seq = htonl ( ntohl ( tcp_header->ack_seq ) + ( seq_mirror - seq_server ) );
            else
                tcp_header->ack_seq = htonl ( ntohl ( tcp_header->ack_seq ) - ( seq_server - seq_mirror ) );
            /*
             * setup seq number
             */
            if ( seq_rmhost_fake > seq_rmhost )
                tcp_header->seq = htonl ( ntohl ( tcp_header->seq ) + ( seq_rmhost_fake - seq_rmhost ) );
            else if ( seq_rmhost_fake < seq_rmhost )
                tcp_header->seq = htonl ( ntohl ( tcp_header->seq ) - ( seq_rmhost - seq_rmhost_fake ) );
        }
        /**/
        this_tcp_info->window_current -= data_size;
        if(this_tcp_info->mirror_port)
            tcp_header->dest = htons(this_tcp_info->mirror_port);

        setup_options(skb_mod, this_tcp_info);
        pd_modify_ip_mac ( skb_mod );

        //skb_mod->csum = skb_checksum(skb_mod, ip_header->ihl*4, skb_mod->len-ip_header->ihl*4, 0);
        tcp_header->check = 0;
        tcp_header->check = tcp_v4_check(skb_mod->len - (ip_header->ihl<<2), ip_header->saddr, ip_header->daddr, skb_mod->csum);

        this_tcp_info->seq_last_send = ntohl(tcp_header->seq);
        this_tcp_info->ackseq_last_playback = ntohl(tcp_header->ack_seq);
        this_tcp_info->last_send_size = data_size;
        printk("[%s] send %u, %u\n", __func__, ntohl(tcp_header->seq), ntohl(tcp_header->ack_seq));

        send_skbmod ( bd->p, skb_mod );

        if(!should_break)
            state_reset = set_tcp_state ( bd->skb, NULL );
    }
    return 0;
}

void slide_send_window(struct tcp_conn_info* this_tcp_info)
{
    struct list_head* head = &(this_tcp_info->buffers.packet_buffer);
    struct list_head *iterator, *tmp;
    u32 seq_target = 0;
    u32 seq_rmhost_fake = this_tcp_info->seq_rmhost_fake;
    u32 seq_rmhost = this_tcp_info->seq_rmhost;
    struct pkt_buffer_node *pbn;

    if(list_empty(head))
        return;

    if ( seq_rmhost_fake > seq_rmhost )
        seq_target = this_tcp_info->seq_last_ack - ( seq_rmhost_fake - seq_rmhost );
    else
        seq_target = this_tcp_info->seq_last_ack + ( seq_rmhost - seq_rmhost_fake );

    list_for_each_safe(iterator, tmp, head)
    {
        pbn = list_entry(iterator, struct pkt_buffer_node, list);
        if(ntohl(tcp_hdr ( pbn->bd->skb )->seq) < seq_target )
        {
            if( iterator == this_tcp_info->playback_ptr )
                break;

            printk("[%s] del pkt %p\n", __func__, iterator);
            list_del(iterator);
            kfree(pbn->bd->p);
            kfree_skb(pbn->bd->skb);
            kfree(pbn->bd);
            kfree(pbn);
        }
        else
            break;
    }
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
