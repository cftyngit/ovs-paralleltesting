#include "packet_dispatcher.h"
#include "tcp_state.h"

//struct host_conn_info_set conn_info_set = HOST_CONN_INFO_SET_INIT;

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

static const unsigned char fake_mac[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

void build_arphdr(struct sk_buff *skb, unsigned char smac[ETH_ALEN], u32* saddr, unsigned char dmac[ETH_ALEN], u32* daddr)
{
	struct arphdr* arp_header = arp_hdr(skb);
	char* addr_base = (char*)arp_header + sizeof(struct arphdr);
	const unsigned char null_mac[ETH_ALEN] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	arp_header->ar_hrd = htons(ARPHRD_ETHER);
	arp_header->ar_pro = htons(ETH_P_IP);
	arp_header->ar_hln = ETH_ALEN;
	arp_header->ar_pln = sizeof(u32);
	arp_header->ar_op = htons(ARPOP_REPLY);

	if(memcmp(dmac, null_mac, ETH_ALEN))
		memcpy(addr_base, dmac, ETH_ALEN);
	else
		memcpy(addr_base, fake_mac, ETH_ALEN);

	memcpy(addr_base + ETH_ALEN, daddr, sizeof(u32));
	memcpy(addr_base + ETH_ALEN + sizeof(u32), smac, ETH_ALEN);
	memcpy(addr_base + ETH_ALEN + sizeof(u32) + ETH_ALEN, saddr, ETH_ALEN);
}

void response_arp(struct vport *p, struct sk_buff *skb)
{
	const unsigned char bro_mac[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	struct net_device* netdev = skb->dev;
	u32 skb_len = sizeof(u32)*2 + ETH_ALEN*2 + sizeof(struct arphdr) + LL_RESERVED_SPACE(netdev);
	struct sk_buff *skb_new = NULL;
	struct arphdr* arp_header = NULL;
	char* addr_base = NULL;
	struct ethhdr *eth_header = NULL;
	skb_new = dev_alloc_skb(skb_len);
	if (!skb_new) 
		return;

	skb_reserve(skb_new, LL_RESERVED_SPACE(netdev));
	skb_new->dev = netdev;
	skb_new->pkt_type = PACKET_OTHERHOST;
	skb_new->protocol = htons(ETH_P_ARP);
	skb_new->ip_summed = CHECKSUM_NONE;
	skb_new->priority = 0;

	skb_set_network_header(skb_new, 0);
	skb_put(skb_new, sizeof(struct arphdr) + 2*sizeof(u32) + 2*ETH_ALEN);
	arp_header = arp_hdr(skb);
	addr_base = (char*)arp_header + sizeof(struct arphdr);

	build_arphdr(skb_new, addr_base, (u32*)(addr_base + ETH_ALEN), addr_base + ETH_ALEN + sizeof(u32), (u32*)(addr_base + (ETH_ALEN*2) + sizeof(u32)));

	eth_header = (struct ethhdr *)skb_push(skb_new, sizeof(struct ethhdr));
	memset (eth_header, 0, sizeof(struct ethhdr));
	skb_set_mac_header(skb_new, 0);
	memset (eth_header, 0, sizeof(struct ethhdr));
	memcpy(eth_header->h_dest, eth_hdr(skb)->h_source, ETH_ALEN);
	if(!memcmp(eth_hdr(skb)->h_dest, bro_mac, ETH_ALEN))
		memcpy(eth_header->h_source, fake_mac, ETH_ALEN);
	else
		memcpy(eth_header->h_source, eth_hdr(skb)->h_dest, ETH_ALEN);

	eth_header->h_proto = htons(ETH_P_ARP);
	mirror.port_no = p->port_no;
	send_skbmod(p, skb_new);
	return;
}

int pd_check_action ( struct vport *p, struct sk_buff *skb )
{
    struct ethhdr* mac_header = eth_hdr ( skb );
    union my_ip_type ip_src, ip_dst;
    struct iphdr* ip_header;
    unsigned short eth_type = ntohs ( mac_header->h_proto );

    if ( ETH_P_IP != eth_type )
	{
		if(ETH_P_ARP == eth_type && !memcmp(mac_header->h_source, mirror.mac, ETH_ALEN))
		{
			response_arp(p, skb);
			return PT_ACTION_CONTINUE;
		}
		return PT_ACTION_CONTINUE;
	}

    ip_header = ip_hdr ( skb );
    if ( ip_header->protocol != IPPROTO_UDP && ip_header->protocol != IPPROTO_TCP )
        return PT_ACTION_CONTINUE;

    ip_src.i = ip_header->saddr;
    ip_dst.i = ip_header->daddr;
	//printk("[%s] input port: %hu\n", );
	if(server.port_no && server.port_no == p->port_no)
		return PT_ACTION_FROM_TARGET;
	else if(mirror.port_no && mirror.port_no == p->port_no)
		return PT_ACTION_FROM_MIRROR;
	else if(server.port_no && mirror.port_no && p->port_no != server.port_no && p->port_no != mirror.port_no)
		return PT_ACTION_FROM_RMHOST;

    if ( ip_src.i == server.ip.i )
        return PT_ACTION_FROM_TARGET;
    else if ( ip_src.i == mirror.ip.i )
        return PT_ACTION_FROM_MIRROR;
    else if ( ip_dst.i == server.ip.i )
        return PT_ACTION_FROM_RMHOST;

    return PT_ACTION_CONTINUE;
}

int pd_respond_mirror ( union my_ip_type ip, u16 client_port, unsigned char proto, u8 cause )
{
    struct sk_buff* skb_mod = NULL;
    struct list_head* packet_buf = NULL;
    struct buf_data* bd = NULL;

//    PRINT_DEBUG("into function: %s\n", __func__);

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
   // mirror.port_no = p->port_no;
///    printk("into function: %s\n", __func__);
    if ( IPPROTO_UDP == ip_header->protocol )
    {
        struct udphdr* udp_header   = udp_hdr ( skb );
        unsigned short client_port  = ntohs ( udp_header->dest );
        struct udp_conn_info* this_udp_info = UDP_CONN_INFO(&conn_info_set, ip, client_port);
        size_t data_size            = ntohs ( udp_header->len ) - sizeof ( struct udphdr );
        unsigned char* data         = kmalloc ( sizeof ( unsigned char ) * data_size + 1, GFP_KERNEL );
        struct connection_info con_info = {.ip = ip, .port = client_port, .proto = IPPROTO_UDP, .host_type = HOST_TYPE_MIRROR};

        if(data_size)
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
        }
        this_udp_info->mirror_port = ntohs ( udp_header->source );
        if(list_empty(&this_udp_info->buffers.packet_buffer))
        {
            this_udp_info->unlock++;
            return 0;
        }
        pd_respond_mirror ( ip, client_port, IPPROTO_UDP, CAUSE_BY_MIRROR );
    }
    if ( IPPROTO_TCP == ip_header->protocol )
    {
        struct tcphdr* tcp_header   = tcp_hdr ( skb );
        unsigned short client_port  = ntohs ( tcp_header->dest );
        struct tcp_conn_info* this_tcp_info = TCP_CONN_INFO(&conn_info_set, ip, client_port);
        size_t data_size            = ntohs ( ip_header->tot_len ) - ( ( ip_header->ihl ) <<2 ) - ( ( tcp_header->doff ) <<2 );
        unsigned char* data         = kmalloc ( sizeof ( unsigned char ) * data_size, GFP_KERNEL );
        struct connection_info con_info = {.ip = ip, .port = client_port, .proto = IPPROTO_TCP, .host_type = HOST_TYPE_MIRROR};
        u32 this_tsval = get_tsval(skb);
		PRINT_DEBUG("[%s] input port: %hu\n", __func__, p->port_no);
		/*
		 * if connection hasn't setup we ignore all "normal packet"
		 */
        if(TCP_STATE_LISTEN == this_tcp_info->state && !tcp_header->syn)
        {
            return 0;
        }
		/*
		 * packet has paload -> insert to compare buffer_node
		 * syn and fin packet is used to mark head and tail of compare buffer
		 */
        if(data_size || tcp_header->syn || tcp_header->fin)
        {
            //memcpy ( data, ( char * ) ( ( unsigned char * ) tcp_header + ( tcp_header->doff * 4 ) ), data_size );
			//memmove ( data, (void *) skb->data + (tcp_header->doff*4 + ip_header->ihl*4 + sizeof(struct ethhdr)), data_size );
            skb_copy_bits(skb, (tcp_header->doff*4 + ip_header->ihl*4 + sizeof(struct ethhdr)), data, data_size);
			bn->payload.data = data;
            bn->payload.length = data_size;
            bn->payload.remain = data_size;
            bn->seq_num = ntohl(tcp_header->seq);
            bn->seq_num_next = (bn->seq_num + data_size + (tcp_header->syn || tcp_header->fin)) % U32_MAX;
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
                    PRINT_DEBUG("[%s] dup ack %u < %u\n", __func__, this_ack_seq, this_tcp_info->seq_last_send);
                    if(this_ack_seq != this_tcp_info->seq_dup_ack)
                    {
                        this_tcp_info->seq_dup_ack = this_ack_seq;
                        this_tcp_info->dup_ack_counter = 1;
                    }
                    else
                    {
                        ++this_tcp_info->dup_ack_counter;
                        if(0 && this_tcp_info->dup_ack_counter >= 3)
                        {//add re transmission func here
                            playback_ptr = find_retransmit_ptr(this_ack_seq, this_tcp_info);
                            this_tcp_info->window_current = respond_window;
                            setup_playback_ptr(playback_ptr, this_tcp_info);
                            PRINT_DEBUG("[%s] 3 dup ack %u \n", __func__, this_ack_seq);
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
                        pd_respond_mirror ( ip, client_port, IPPROTO_TCP, CAUSE_BY_RETRAN );
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
        pd_respond_mirror ( ip, client_port, IPPROTO_TCP, CAUSE_BY_MIRROR );
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

//    PRINT_DEBUG("into function: %s\n", __func__);

    memcpy(this_vport, p, sizeof(struct vport));
    bd->p = this_vport;
    bd->skb = skb_mod;
    bd->retrans_times = 0;
    init_timer(&(bd->timer));
//	PRINT_DEBUG("[%s] input port: %hu\n", __func__, p->port_no);
    if ( IPPROTO_UDP == ip_header->protocol )
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
        pd_respond_mirror ( ip, client_port, IPPROTO_UDP, CAUSE_BY_RMHOST );
    }

    if ( IPPROTO_TCP == ip_header->protocol )
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
        pbn->seq_num_next = (pbn->seq_num + data_size) % U32_MAX;
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
            pd_respond_mirror ( ip, client_port, IPPROTO_TCP, CAUSE_BY_RMHOST );
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
    if ( IPPROTO_UDP == ip_header->protocol )
    {
        struct udphdr* udp_header = udp_hdr ( skb );
        u16 client_port = ntohs ( udp_header->dest );
        struct udp_conn_info* this_udp_info = UDP_CONN_INFO(&conn_info_set, ip, client_port);
        struct list_head* packet_buf = & ( this_udp_info->buffers.packet_buffer );
        size_t data_size            = ntohs ( udp_header->len ) - sizeof ( struct udphdr );
        unsigned char* data         = kmalloc ( sizeof ( unsigned char ) * data_size + 1, GFP_KERNEL );
        struct connection_info con_info = {.ip = ip, .port = client_port, .proto = IPPROTO_UDP, .host_type = HOST_TYPE_TARGET};

        if(this_udp_info->unlock == 0)
            pkt_buffer_barrier_add(packet_buf);
        else
            this_udp_info->unlock--;

        if(data_size)
        {
            memcpy ( data, ( char * ) ( ( unsigned char * ) udp_header + sizeof ( struct udphdr ) ), data_size );
            bn->payload.data = data;
            bn->payload.length = data_size;
            bn->payload.remain = data_size;
            bn->seq_num = this_udp_info->current_seq_target;
            bn->seq_num_next = bn->seq_num + data_size;
            bn->opt_key = get_tsval(skb);
            this_udp_info->current_seq_target = bn->seq_num_next;
            compare_buffer_insert(bn, &this_udp_info->buffers.target_buffer);
            do_compare(&con_info, &this_udp_info->buffers.target_buffer, &this_udp_info->buffers.mirror_buffer, NULL);
        }
    }
    if ( IPPROTO_TCP == ip_header->protocol )
    {
        struct tcphdr* tcp_header   = tcp_hdr ( skb );
        unsigned short client_port  = ntohs ( tcp_header->dest );
        struct tcp_conn_info* this_tcp_info = TCP_CONN_INFO(&conn_info_set, ip, client_port);
        size_t data_size            = ntohs ( ip_header->tot_len ) - ( ( ip_header->ihl ) <<2 ) - ( ( tcp_header->doff ) <<2 );
        unsigned char* data         = kmalloc ( sizeof ( unsigned char ) * data_size, GFP_KERNEL );
        struct connection_info con_info = {.ip = ip, .port = client_port, .proto = IPPROTO_TCP, .host_type = HOST_TYPE_TARGET};
        if(data_size || tcp_header->syn || tcp_header->fin)
        {
///			printk("[%s] skb->len: %d, skb->data_len: %d\n", __func__, skb->len, skb->data_len);
            //memcpy ( data, ( char * ) ( ( unsigned char * ) tcp_header + ( tcp_header->doff * 4 ) ), data_size );
            //memmove ( data, (void *) skb->data + (tcp_header->doff*4 + ip_header->ihl*4 + sizeof(struct ethhdr)), data_size );
			skb_copy_bits(skb, (tcp_header->doff*4 + ip_header->ihl*4 + sizeof(struct ethhdr)), data, data_size);
			bn->payload.data = data;
            bn->payload.length = data_size;
            bn->payload.remain = data_size;
            bn->seq_num = ntohl(tcp_header->seq);
            bn->seq_num_next = (bn->seq_num + data_size + (tcp_header->syn || tcp_header->fin)) % U32_MAX;
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
