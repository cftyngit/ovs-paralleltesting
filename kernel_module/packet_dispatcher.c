#include "packet_dispatcher.h"
#include "tcp_state.h"

struct host_conn_info_set conn_info_set = HOST_CONN_INFO_SET_INIT;

//static struct queue_list_head udp_buffer;

void init_tcp_state(void)
{
    //int i = 0;
    /*for(i = 0; i < MAX_TCP_TABLE; ++i)
        tcp_info_table[i].state = TCP_STATE_LISTEN;*/
}

void init_packet_dispatcher()
{
    init_tcp_state();
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
    {
        // if layer 3 protocol is IPv4
        struct iphdr* ip_header = ip_hdr ( skb_mod );
        unsigned char ip_proto = ip_header->protocol;
        char* ip_src = ( unsigned char* ) & ( ip_header->saddr );
        char* ip_dst = ( unsigned char* ) & ( ip_header->daddr );

        printk ( KERN_INFO "IP: %d.%d.%d.%d -> %d.%d.%d.%d\n", ip_src[0], ip_src[1], ip_src[2], ip_src[3],
                 ip_dst[0], ip_dst[1], ip_dst[2], ip_dst[3] );

        switch ( ip_proto )
        {
        case 0x11:
        {
            //UDP
            struct udphdr* udp_header = udp_hdr ( skb_mod );
            size_t data_size = ntohs ( udp_header->len ) - sizeof ( struct udphdr );
            printk ( KERN_INFO "UDP datasize: %lu\n", data_size );
            break;
        }
        case 0x06:
        {
            //TCP
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
    int error;
    struct sw_flow *flow;
    struct datapath *dp = p->dp;
    struct sw_flow_key key;
    u32 n_mask_hit;
    struct dp_stats_percpu *stats;
    u64 *stats_counter;
    /*
     * copy from ovs_dp_process_received_packet
     */
    stats = this_cpu_ptr ( dp->stats_percpu );
    error = ovs_flow_extract ( skb_mod, p->port_no, &key );
    if ( unlikely ( error ) )
    {
        kfree_skb ( skb_mod );
        return;
    }
    flow = ovs_flow_tbl_lookup_stats ( &dp->table, &key, &n_mask_hit );
    if ( unlikely ( !flow ) )
    {
        struct dp_upcall_info upcall;
        upcall.cmd = OVS_PACKET_CMD_MISS;
        upcall.key = &key;
        upcall.userdata = NULL;
        upcall.portid = p->upcall_portid;
        ovs_dp_upcall ( dp, skb_mod, &upcall );
        consume_skb ( skb_mod );
        stats_counter = &stats->n_missed;
        goto mod_out;
    }
    OVS_CB ( skb_mod )->flow = flow;
    OVS_CB ( skb_mod )->pkt_key = &key;

    ovs_flow_stats_update ( OVS_CB ( skb_mod )->flow, key.tp.flags, skb_mod );
    ovs_execute_actions ( dp, skb_mod );
    stats_counter = &stats->n_hit;

mod_out:
    u64_stats_update_begin ( &stats->syncp );
    ( *stats_counter ) ++;
    stats->n_mask_hit += n_mask_hit;
    u64_stats_update_end ( &stats->syncp );


    return;
}

//const union ip client = {{10, 0, 0, 1},};
//const union ip server = {{10, 0, 0, 2},};
//const union ip mirror = {{10, 0, 0, 3},};
//static struct host_info server = {{{10, 0, 0, 2}}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x02}};
//static struct host_info mirror = {{{10, 0, 0, 3}}, {0x00, 0x00, 0x00, 0x00, 0x00, 0x03}};
static struct host_info server = {{{192, 168, 1, 1}}, {0xc0, 0xa0, 0xbb, 0xdc, 0xfa, 0x57}};
static struct host_info mirror = {{{192, 168, 2, 1}}, {0xc8, 0xd3, 0xa3, 0x98, 0x65, 0xdf}};

int pd_setup_hosts(struct host_info* set_server, struct host_info* set_mirror)
{
    //int i = 0;
    //for(i = 0; i < MAX_TCP_TABLE; ++i)
    {
        /*while(tcp_info_table[i].packet_buffer.count > 0)
            del_queue(&(tcp_info_table[i].packet_buffer));

        memset(&(tcp_info_table[i]), 0,sizeof(struct tcp_seq_info));*/
    }
    /*while(udp_buffer.count > 0)
        del_queue(&(udp_buffer));*/

    printk("old server ip = %d\n", server.ip.i);
    printk("old mirror ip = %d\n", mirror.ip.i);
    if(set_server != NULL)
    {
        server.ip.i = set_server->ip.i;
        memcpy(server.mac, set_server->mac, 6);
        printk("set server ip = %hhu.%hhu.%hhu.%hhu\n", server.ip.c[0], server.ip.c[1], server.ip.c[2], server.ip.c[3]);
        printk("set server MAC = %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", server.mac[0], server.mac[1], server.mac[2], server.mac[3], server.mac[4], server.mac[5]);
    }
    if(set_mirror != NULL)
    {
        mirror.ip.i = set_mirror->ip.i;
        memcpy(mirror.mac, set_mirror->mac, 6);
        printk("set mirror ip = %hhu.%hhu.%hhu.%hhu\n", mirror.ip.c[0], mirror.ip.c[1], mirror.ip.c[2], mirror.ip.c[3]);
        printk("set mirror MAC = %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", mirror.mac[0], mirror.mac[1], mirror.mac[2], mirror.mac[3], mirror.mac[4], mirror.mac[5]);
    }
    return 0;
}

int pd_check_action ( struct sk_buff *skb )
{
    struct ethhdr* mac_header = eth_hdr ( skb );
    union my_ip_type ip_src, ip_dst;
    struct iphdr* ip_header;
    unsigned short eth_type = ntohs ( mac_header->h_proto );

    if ( ETH_P_IP != eth_type )
        return PT_ACTION_CONTINUE;

    ip_header = ip_hdr ( skb );
    if ( ip_header->protocol != IPPROTO_UDP && ip_header->protocol != IPPROTO_TCP )
        return PT_ACTION_CONTINUE;

    ip_src.i = ip_header->saddr;
    ip_dst.i = ip_header->daddr;
	//printk("[%s] input port: %hu\n", );
    if ( ip_src.i == server.ip.i )
        return PT_ACTION_SERVER_TO_CLIENT;
    else if ( ip_src.i == mirror.ip.i )
        return PT_ACTION_DROP;
    else if ( ip_dst.i == server.ip.i )
        return PT_ACTION_CLIENT_TO_SERVER;

    return PT_ACTION_CONTINUE;
}

int pd_modify_ip_mac ( struct sk_buff* skb_mod )
{
    //struct ethhdr* mac_header = eth_hdr ( skb_mod );
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

int pd_respond_mirror ( union my_ip_type ip, u16 client_port, unsigned char proto, u8 cause )
{
    struct sk_buff* skb_mod = NULL;
    struct list_head* packet_buf = NULL;
    struct buf_data* bd = NULL;
#ifdef DEBUG
    printk("into function: %s\n", __func__);
#endif
    if ( IPPROTO_UDP == proto )
        packet_buf = & ( UDP_CONN_INFO(&conn_info_set, ip, client_port)->buffers.packet_buffer );
    else
        packet_buf = & ( TCP_CONN_INFO(&conn_info_set, ip, client_port)->buffers.packet_buffer );

    switch ( proto )
    {
    case IPPROTO_UDP:
        bd = pkt_buffer_get_data ( packet_buf );
        if( NULL == bd )
        {
            if(CAUSE_BY_MIRROR == cause)
            {
                pkt_buffer_barrier_remove ( packet_buf );
                bd = pkt_buffer_get_data ( packet_buf );
            }
            else
                return 0;
        }
        while ( NULL != bd )
        {
            struct udphdr* udp_header;
            skb_mod = bd->skb;
            udp_header = udp_hdr ( skb_mod );
            pd_modify_ip_mac ( skb_mod );
            if(UDP_CONN_INFO(&conn_info_set, ip, client_port)->mirror_port)
                udp_header->dest = htons(UDP_CONN_INFO(&conn_info_set, ip, client_port)->mirror_port);

            send_skbmod ( bd->p, skb_mod );
            kfree(bd->p);
            kfree(bd);
            bd = pkt_buffer_get_data ( packet_buf );
        }
        //pkt_buffer_barrier_remove ( packet_buf );
        break;
    case IPPROTO_TCP:
    {
        tcp_playback_packet( ip, client_port, cause);
    }
        break;
    default:
        //kfree_skb ( skb_mod );
        return -1;
        break;
    }
    return 0;
}

int pd_action_from_mirror ( struct vport *p, struct sk_buff *skb )
{
    struct iphdr* ip_header = ip_hdr ( skb );
    union my_ip_type ip = {.i = ip_header->daddr,};
    struct buffer_node* bn = kmalloc ( sizeof ( struct buffer_node ) , GFP_KERNEL );
///    printk("into function: %s\n", __func__);
    if ( UDP_PROTO == ip_header->protocol )
    {
        struct udphdr* udp_header   = udp_hdr ( skb );
        unsigned short client_port  = ntohs ( udp_header->dest );
        struct udp_conn_info* this_udp_info = UDP_CONN_INFO(&conn_info_set, ip, client_port);
        //size_t data_size            = ntohs ( udp_header->len ) - sizeof ( struct udphdr );
        //unsigned char* data         = kmalloc ( sizeof ( unsigned char ) * data_size + 1, GFP_KERNEL );
        //truct connection_info con_info = {.ip = ip, .port = client_port, .proto = IPPROTO_UDP,};

        /*if(data_size)
        {
            memcpy ( data, ( char * ) ( ( unsigned char * ) udp_header + sizeof ( struct udphdr ) ), data_size );
            bn->payload.data = data;
            bn->payload.length = data_size;
            bn->payload.remain = data_size;
            bn->seq_num = this_udp_info->current_seq_mirror;
            bn->seq_num_next = bn->seq_num + data_size;
            bn->opt_key = get_tsval(skb);
            this_udp_info->current_seq_mirror = bn->seq_num_next;
            compare_buffer_insert(bn, &this_udp_info->buffers.mirror_buffer);
            do_compare(&con_info, &this_udp_info->buffers.target_buffer, &this_udp_info->buffers.mirror_buffer, NULL);
        }*/
        this_udp_info->mirror_port = ntohs ( udp_header->source );
        if(list_empty(&this_udp_info->buffers.packet_buffer))
        {
            this_udp_info->unlock++;
            return 0;
        }
        pd_respond_mirror ( ip, client_port, UDP_PROTO, CAUSE_BY_MIRROR );
    }
    if ( TCP_PROTO == ip_header->protocol )
    {
        struct tcphdr* tcp_header   = tcp_hdr ( skb );
        unsigned short client_port  = ntohs ( tcp_header->dest );
        struct tcp_conn_info* this_tcp_info = TCP_CONN_INFO(&conn_info_set, ip, client_port);
        size_t data_size            = ntohs ( ip_header->tot_len ) - ( ( ip_header->ihl ) <<2 ) - ( ( tcp_header->doff ) <<2 );
        unsigned char* data         = kmalloc ( sizeof ( unsigned char ) * data_size, GFP_KERNEL );
        struct connection_info con_info = {.ip = ip, .port = client_port, .proto = IPPROTO_TCP,};
        u32 this_tsval = get_tsval(skb);
		printk("[%s] input port: %hu\n", __func__, p->port_no);
        if(TCP_STATE_LISTEN == this_tcp_info->state && !tcp_header->syn)
        {
            return 0;
        }

        if(data_size)
        {
            //memcpy ( data, ( char * ) ( ( unsigned char * ) tcp_header + ( tcp_header->doff * 4 ) ), data_size );
			//memmove ( data, (void *) skb->data + (tcp_header->doff*4 + ip_header->ihl*4 + sizeof(struct ethhdr)), data_size );
            skb_copy_bits(skb, (tcp_header->doff*4 + ip_header->ihl*4 + sizeof(struct ethhdr)), data, data_size);
			bn->payload.data = data;
            bn->payload.length = data_size;
            bn->payload.remain = data_size;
            bn->seq_num = ntohl(tcp_header->seq);
            bn->seq_num_next = bn->seq_num + data_size;
            bn->opt_key = get_tsval(skb);
            compare_buffer_insert(bn, &this_tcp_info->buffers.mirror_buffer);
            do_compare(&con_info, &this_tcp_info->buffers.target_buffer, &this_tcp_info->buffers.mirror_buffer, NULL);
        }
        /*
         * if get_tsval return 0, means this packet doesn't set tsval => doesn't need to update
         */
        if(this_tsval != 0)
            this_tcp_info->tsval_current = this_tsval;
        /*
         * setup window_current before SYN packet setup window scale option
         * because window size in SYN packet is 0
         */
        if(tcp_header->ack)
        {
            u32 this_ack_seq = ntohl(tcp_header->ack_seq);
            u32 respond_window = (ntohs(tcp_header->window) << this_tcp_info->window_scale);
            u32 send_size = 0;
            struct list_head* packet_buf = & ( this_tcp_info->buffers.packet_buffer );
            struct list_head* pkt_right_edge = this_tcp_info->send_wnd_right_dege->prev;
            struct buf_data* bd_edge = pkt_buffer_peek_data_from_ptr ( packet_buf, &pkt_right_edge );
            /*
             * if the ack seq is the lastest send pkt or bigger than lastest pkt
             * we can just use it's respond window size, otherwise, the respond window size have to minus
             * "send but not ack" size
             */
            if(this_ack_seq >= this_tcp_info->seq_last_send + this_tcp_info->last_send_size)
                send_size = 0;
            else
                send_size = this_tcp_info->seq_last_send + this_tcp_info->last_send_size - this_ack_seq;

///            printk("[%s] rep_win: %u, send_size: %u\n", __func__, respond_window, send_size);
            this_tcp_info->window_current = send_size > respond_window ? 0 : respond_window - send_size;
            this_tcp_info->seq_last_ack = ntohl(tcp_header->ack_seq);
            slide_send_window(this_tcp_info);
///            printk("[%s] bd_edge: %p\n", __func__, bd_edge);
            if(TCP_STATE_ESTABLISHED == this_tcp_info->state && bd_edge)
            {
                u32 seq_rmhost = this_tcp_info->seq_rmhost;
                u32 seq_rmhost_fake = this_tcp_info->seq_rmhost_fake;
                struct tcphdr* tcp_header_edge = tcp_hdr(bd_edge->skb);
                struct iphdr* ip_header_edge = ip_hdr(bd_edge->skb);
                size_t data_size_edge = ntohs ( ip_header_edge->tot_len ) - ( ( ip_header_edge->ihl ) <<2 ) - ( ( tcp_header_edge->doff ) <<2 );
                u32 seq_edge = 0;
                if ( seq_rmhost_fake > seq_rmhost )
                    seq_edge = ntohl ( tcp_header_edge->seq ) + ( seq_rmhost_fake - seq_rmhost );
                else
                    seq_edge = ntohl ( tcp_header_edge->seq ) - ( seq_rmhost - seq_rmhost_fake );
                /*
                 * process dup ACK and 3 dup ACK retransmission
                 */
///                printk("[%s] this_ack_seq: %u, seq_edge: %u, data_size_edge:%lu\n", __func__, this_ack_seq, seq_edge, data_size_edge);
                if(this_ack_seq < seq_edge + data_size_edge)
                {
                    struct list_head* playback_ptr = NULL;
                    printk("[%s] dup ack %u < %u\n", __func__, this_ack_seq, this_tcp_info->seq_last_send);
                    if(this_ack_seq != this_tcp_info->seq_dup_ack)
                    {
                        this_tcp_info->seq_dup_ack = this_ack_seq;
                        this_tcp_info->dup_ack_counter = 1;
                    }
                    else
                    {
                        ++this_tcp_info->dup_ack_counter;
                        if(1 && this_tcp_info->dup_ack_counter >= 3)
                        {//add re transmission func here
                            playback_ptr = find_retransmit_ptr(this_ack_seq, this_tcp_info);
                            this_tcp_info->window_current = respond_window;
                            setup_playback_ptr(playback_ptr, this_tcp_info);
                            printk("[%s] 3 dup ack %u \n", __func__, this_ack_seq);
                            goto retransmission;
                        }
                    }
                    if(this_tcp_info->playback_ptr != this_tcp_info->send_wnd_right_dege)
                    {
                        playback_ptr = find_retransmit_ptr(this_ack_seq, this_tcp_info);
                        this_tcp_info->window_current = respond_window;
                        setup_playback_ptr(playback_ptr, this_tcp_info);
                        goto retransmission;
                    }
retransmission:
                    if(NULL != playback_ptr)
                    {
///                        printk("[%s] playback_ptr: %p \n", __func__, playback_ptr);
                        pd_respond_mirror ( ip, client_port, TCP_PROTO, CAUSE_BY_RETRAN );
                        return 0;
                    }
                }
                else if(this_tcp_info->playback_ptr != this_tcp_info->send_wnd_right_dege)
                    setup_playback_ptr(this_tcp_info->send_wnd_right_dege, this_tcp_info);
            }
        }
        else
            this_tcp_info->window_current = ntohs(tcp_header->window) << this_tcp_info->window_scale;
///        printk("setup window_c = %u\n", this_tcp_info->window_current);
        if ( tcp_header->syn /*&& tcp_header->ack*/ )
        {
            this_tcp_info->seq_mirror = ntohl ( tcp_header->seq );
            this_tcp_info->mirror_port = ntohs ( tcp_header->source );
            this_tcp_info->window_scale = get_window_scaling(skb);
            if( (!tcp_header->ack) && (pkt_buffer_peek_data(&this_tcp_info->buffers.packet_buffer) == NULL) )
            {
                respond_tcp_syn_ack(skb, this_tcp_info);
                this_tcp_info->seq_rmhost_fake = FAKE_SEQ;
            }
        }
        /*
         * record lastest packet seq number
         */
        if(ntohl(tcp_header->seq) >= this_tcp_info->seq_current)
        {
            if ( tcp_header->syn || tcp_header->fin )
                data_size = data_size + 1;

            this_tcp_info->seq_current = ntohl(tcp_header->seq);
            this_tcp_info->seq_next = (ntohl(tcp_header->seq) + data_size);
        }
        set_tcp_state ( NULL, skb );
//from_mirror_respond_mirror:
        pd_respond_mirror ( ip, client_port, TCP_PROTO, CAUSE_BY_MIRROR );
        if(TCP_STATE_ESTABLISHED == this_tcp_info->state && data_size > 0 && ntohl(tcp_header->seq) < this_tcp_info->ackseq_last_playback)
            ack_this_packet(skb);
    }
    return 0;
}

int pd_action_from_client ( struct vport *p, struct sk_buff *skb )
{
    struct sk_buff* skb_mod = skb_copy ( skb, GFP_ATOMIC );
    struct iphdr* ip_header = ip_hdr ( skb_mod );
    union my_ip_type ip = {.i = ip_header->saddr,};
    struct list_head* packet_buf = NULL;

    struct vport* this_vport = kmalloc(sizeof(struct vport), GFP_KERNEL);
    struct buf_data* bd = kmalloc(sizeof(struct buf_data), GFP_KERNEL);
    struct pkt_buffer_node* pbn = kmalloc(sizeof(struct pkt_buffer_node), GFP_ATOMIC); 
#ifdef DEBUG
    printk("into function: %s\n", __func__);
#endif
    memcpy(this_vport, p, sizeof(struct vport));
    bd->p = this_vport;
    bd->skb = skb_mod;
    bd->retrans_times = 0;
    init_timer(&(bd->timer));
	printk("[%s] input port: %hu\n", __func__, p->port_no);
    if ( UDP_PROTO == ip_header->protocol )
    {
        struct udphdr* udp_header = udp_hdr ( skb_mod );
        u16 client_port = ntohs ( udp_header->source );
        struct udp_conn_info* this_udp_info = UDP_CONN_INFO(&conn_info_set, ip, client_port);
        packet_buf = & ( this_udp_info->buffers.packet_buffer );
        bd->conn_info = this_udp_info;
        pbn->seq_num = this_udp_info->current_seq_rmhost;
        pbn->seq_num_next = pbn->seq_num + 1;
        pbn->bd = bd;
        pbn->barrier = 0;
        this_udp_info->current_seq_rmhost = pbn->seq_num_next;
        //add_data ( packet_buf, bd );
        pkt_buffer_insert ( pbn, packet_buf );
        pd_respond_mirror ( ip, client_port, UDP_PROTO, CAUSE_BY_RMHOST );
    }

    if ( TCP_PROTO == ip_header->protocol )
    {
        struct tcphdr* tcp_header = tcp_hdr ( skb_mod );
        unsigned short client_port = ntohs ( tcp_header->source );
        struct tcp_conn_info* this_tcp_info = TCP_CONN_INFO(&conn_info_set, ip, client_port);
        size_t data_size = ntohs ( ip_header->tot_len ) - ( ( ip_header->ihl ) <<2 ) - ( ( tcp_header->doff ) <<2 );
        if(tcp_header->syn || tcp_header->fin)
            data_size = data_size + 1;

        if(TCP_STATE_LISTEN == this_tcp_info->state && !tcp_header->syn)
        {
            return 0;
        }
        packet_buf = & ( this_tcp_info->buffers.packet_buffer );
        bd->conn_info = this_tcp_info;
        pbn->seq_num = ntohl(tcp_header->seq);
        pbn->seq_num_next = pbn->seq_num + data_size;
        pbn->opt_key = get_tsval(skb_mod);
        pbn->bd = bd;
        pbn->barrier = 0;
        //add_data ( packet_buf, bd );
///        printk("[%s] tcp_header->seq: %u, seq_last_ack: %u\n", __func__, ntohl(tcp_header->seq), this_tcp_info->seq_last_ack);
///        printk("[%s] tcp_header->ack_seq: %u, seq_last_ack: %u\n", __func__, ntohl(tcp_header->ack_seq), seq_to_target(this_tcp_info->ackseq_last_playback, this_tcp_info));
        if(ntohl(tcp_header->seq) >= this_tcp_info->seq_last_ack || ntohl(tcp_header->ack_seq) >= seq_to_target(this_tcp_info->ackseq_last_playback, this_tcp_info))
            pkt_buffer_insert ( pbn, packet_buf );

        switch ( tcp_state_get(&conn_info_set, ip, client_port) )
        {
        case TCP_STATE_SYN_RCVD:
        case TCP_STATE_FIN_WAIT1:
            break;
        default:
            pd_respond_mirror ( ip, client_port, TCP_PROTO, CAUSE_BY_RMHOST );
            break;
        }
    }

    return 0;
}

int pd_action_from_server ( struct vport *p, struct sk_buff *skb )
{
    struct iphdr* ip_header = ip_hdr ( skb );
    union my_ip_type ip = {.i = ip_header->daddr,};
    struct buffer_node* bn = kmalloc ( sizeof ( struct buffer_node ) , GFP_KERNEL );
	printk("[%s] input port: %hu\n", __func__, p->port_no);
    if ( UDP_PROTO == ip_header->protocol )
    {
        struct udphdr* udp_header = udp_hdr ( skb );
        u16 client_port = ntohs ( udp_header->dest );
        struct udp_conn_info* this_udp_info = UDP_CONN_INFO(&conn_info_set, ip, client_port);
        struct list_head* packet_buf = & ( this_udp_info->buffers.packet_buffer );
        //size_t data_size            = ntohs ( udp_header->len ) - sizeof ( struct udphdr );
        //unsigned char* data         = kmalloc ( sizeof ( unsigned char ) * data_size + 1, GFP_KERNEL );
        //struct connection_info con_info = {.ip = ip, .port = client_port, .proto = IPPROTO_UDP,};

        if(this_udp_info->unlock == 0)
            pkt_buffer_barrier_add(packet_buf);
        else
            this_udp_info->unlock--;

        /*if(data_size)
        {
            memcpy ( data, ( char * ) ( ( unsigned char * ) udp_header + sizeof ( struct udphdr ) ), data_size );
            bn->payload.data = data;
            bn->payload.length = data_size;
            bn->payload.remain = data_size;
            bn->seq_num = this_udp_info->current_seq_target;
            bn->seq_num_next = bn->seq_num + data_size;
            bn->opt_key = get_tsval(skb);
            this_udp_info->current_seq_target = bn->seq_num_next;
            //compare_buffer_insert(bn, &this_udp_info->buffers.target_buffer);
            //do_compare(&con_info, &this_udp_info->buffers.target_buffer, &this_udp_info->buffers.mirror_buffer, NULL);
        }*/
    }
    if ( TCP_PROTO == ip_header->protocol )
    {
        struct tcphdr* tcp_header   = tcp_hdr ( skb );
        unsigned short client_port  = ntohs ( tcp_header->dest );
        struct tcp_conn_info* this_tcp_info = TCP_CONN_INFO(&conn_info_set, ip, client_port);
        size_t data_size            = ntohs ( ip_header->tot_len ) - ( ( ip_header->ihl ) <<2 ) - ( ( tcp_header->doff ) <<2 );
        unsigned char* data         = kmalloc ( sizeof ( unsigned char ) * data_size, GFP_KERNEL );
        struct connection_info con_info = {.ip = ip, .port = client_port, .proto = IPPROTO_TCP,};
        if(data_size)
        {
///			printk("[%s] skb->len: %d, skb->data_len: %d\n", __func__, skb->len, skb->data_len);
            //memcpy ( data, ( char * ) ( ( unsigned char * ) tcp_header + ( tcp_header->doff * 4 ) ), data_size );
            //memmove ( data, (void *) skb->data + (tcp_header->doff*4 + ip_header->ihl*4 + sizeof(struct ethhdr)), data_size );
			skb_copy_bits(skb, (tcp_header->doff*4 + ip_header->ihl*4 + sizeof(struct ethhdr)), data, data_size);
			bn->payload.data = data;
            bn->payload.length = data_size;
            bn->payload.remain = data_size;
            bn->seq_num = ntohl(tcp_header->seq);
            bn->seq_num_next = bn->seq_num + data_size;
            bn->opt_key = get_tsval(skb);
            compare_buffer_insert(bn, &this_tcp_info->buffers.target_buffer);
            do_compare(&con_info, &this_tcp_info->buffers.target_buffer, &this_tcp_info->buffers.mirror_buffer, NULL);
        }
        if (get_tsval(skb) > this_tcp_info->timestamp_last_from_target)
            this_tcp_info->ackseq_last_from_target = ntohl(tcp_header->ack_seq);

        if ( tcp_header->syn )
        {
            this_tcp_info->seq_server = ntohl ( tcp_header->seq );
            if ( !tcp_header->ack && tcp_state_get(&conn_info_set, ip, client_port) == TCP_STATE_LISTEN )
                tcp_state_set(&conn_info_set, ip, client_port, TCP_STATE_CLOSED);
        }
    }
    return 0;
}
