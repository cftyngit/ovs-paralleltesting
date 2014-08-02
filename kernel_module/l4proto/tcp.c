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

    printk("iphdr: %d\n", sizeof(struct iphdr));
    printk("tcphdr: %d\n", sizeof(struct tcphdr));
    printk("skb_len: %d\n", skb_len);
    printk("netdev: %p\n", netdev);
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
    tcp_header->window = htons(14480);

    /* construct ip header in skb */
    ip_header = ip_hdr(skb_new);
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
    if (pdata && tcp_info->seq_current) 
    {
        const u32 ftsval = FAKE_TSVAL;
        const char timestamp[] = {TCPOPT_TIMESTAMP, TCPOLEN_TIMESTAMP};
        memset(pdata, 0x01, (((TCPOLEN_TIMESTAMP>>2)+1)<<2) - TCPOLEN_TIMESTAMP);
        pdata+=(((TCPOLEN_TIMESTAMP>>2)+1)<<2) - TCPOLEN_TIMESTAMP;
        memmove(pdata, timestamp, sizeof(timestamp));
        pdata+=sizeof(timestamp);
        put_unaligned_be32(ftsval, pdata);
        pdata+=4;
        put_unaligned_be32(tcp_info->seq_current, pdata);
    }
    skb_new->csum = skb_checksum(skb_new, ip_header->ihl*4, skb_new->len-ip_header->ihl*4, 0);
    tcp_header->check = 0;
    tcp_header->check = tcp_v4_check(skb_new->len - (ip_header->ihl<<2), ip_header->saddr, ip_header->daddr, skb_new->csum);

    /* construct ethernet header in skb */
    eth_header = (struct ethhdr *)skb_push(skb_new, 14);
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
            if ((TCPOPT_TIMESTAMP == opcode) && (opsize == TCPOLEN_TIMESTAMP))
                return get_unaligned_be32(ptr + off);

            ptr += opsize-2;
            length -= opsize;
        }
    }
    return 0;
}
