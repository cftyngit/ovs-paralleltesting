#include "packet_dispatcher.h"
#include "tcp_state.h"

#define MAX_TCP_TABLE 65536

static struct tcp_seq_info
{
    unsigned int seq_server;
    unsigned int seq_mirror;
    unsigned int seq_fin;
    struct queue_list_head packet_buffer;
    int state;
} tcp_info_table[MAX_TCP_TABLE];

#define get_tcp_state(port) tcp_info_table[port].state

static struct queue_list_head udp_buffer;

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
            printk ( KERN_INFO "UDP datasize: %d\n", data_size );
            break;
        }
        case 0x06:
        {
            //TCP
            struct tcphdr* tcp_header = tcp_hdr ( skb_mod );
            size_t data_size = ntohs ( ip_header->tot_len ) - ( ( ip_header->ihl ) <<2 ) - ( ( tcp_header->doff ) <<2 );
            printk ( KERN_INFO "TCP flags: %d %d %d\n", tcp_header->syn, tcp_header->ack, tcp_header->fin );
            printk ( KERN_INFO "seq number: %u, ACK number: %u", ntohl ( tcp_header->seq ), ntohl ( tcp_header->ack_seq ) );
            printk ( KERN_INFO "TCP datasize: %d - %d = %d\n", ntohs ( ip_header->tot_len ), ( tcp_header->doff ) <<2, data_size );
            break;
        }
        default:
            break;
        }
    }
    printk ( KERN_INFO "^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^" );
    return;
}

void set_tcp_state ( struct sk_buff* skb_client, struct sk_buff* skb_mirror )
{
    struct tcphdr* tcp_header;
    unsigned short port;
    int old_state;
    if ( ! ( ( skb_client == NULL ) ^ ( skb_mirror == NULL ) ) )
        return;

    tcp_header = skb_client ? tcp_hdr ( skb_client ) : tcp_hdr ( skb_mirror );
    port = ntohs ( skb_client ? tcp_header->source : tcp_header->dest );
    old_state = get_tcp_state( port );

    switch ( get_tcp_state ( port ) )
    {
    case TCP_STATE_CLOSED:
    case TCP_STATE_LISTEN:
        if ( skb_client && tcp_header->syn )
            tcp_info_table[port].state = TCP_STATE_SYN_RCVD;

        break;
    case TCP_STATE_SYN_RCVD:
        if ( skb_mirror && tcp_header->syn && tcp_header->ack )
            tcp_info_table[port].state = TCP_STATE_ESTABLISHED;

        break;
    case TCP_STATE_ESTABLISHED:
        if ( tcp_header->fin )
        {
            if ( skb_client )
                tcp_info_table[port].state = TCP_STATE_FIN_WAIT1;
            else
                tcp_info_table[port].state = TCP_STATE_CLOSE_WAIT1;

            tcp_info_table[port].seq_fin = ntohl ( tcp_header->seq );
        }
        break;
    case TCP_STATE_FIN_WAIT1:
        if ( skb_mirror && ( ntohl ( tcp_header->ack_seq ) > tcp_info_table[port].seq_fin ) )
            tcp_info_table[port].state = TCP_STATE_FIN_WAIT2;

    case TCP_STATE_FIN_WAIT2:
        if ( skb_mirror && tcp_header->fin )
        {
            tcp_info_table[port].state = TCP_STATE_TIME_WAIT;
            tcp_info_table[port].seq_fin = ntohl ( tcp_header->seq );
        }
        break;
    case TCP_STATE_TIME_WAIT:
        if ( skb_client && ( ntohl ( tcp_header->ack_seq ) > tcp_info_table[port].seq_fin ) )
        {
            tcp_info_table[port].state = TCP_STATE_CLOSED;
            tcp_info_table[port].seq_fin = 0;
        }
        break;
    case TCP_STATE_CLOSE_WAIT1:
        if ( skb_client && ( ntohl ( tcp_header->ack_seq ) > tcp_info_table[port].seq_fin ) )
            tcp_info_table[port].state = TCP_STATE_CLOSE_WAIT2;

    case TCP_STATE_CLOSE_WAIT2:
        if ( skb_client && tcp_header->fin )
        {
            tcp_info_table[port].state = TCP_STATE_LAST_ACK;
            tcp_info_table[port].seq_fin = ntohl ( tcp_header->seq );
        }
        break;
    case TCP_STATE_LAST_ACK:
        if ( skb_mirror && ntohl ( tcp_header->ack_seq ) > tcp_info_table[port].seq_fin )
        {
            tcp_info_table[port].state = TCP_STATE_CLOSED;
            tcp_info_table[port].seq_fin = 0;
        }
        break;
    }
    if(old_state != get_tcp_state( port ) )
        printk ( KERN_INFO "set_tcp_state %s trigger from %d to %d\n", skb_client ? "client" : "server", old_state, get_tcp_state ( port ) );

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

    ovs_flow_stats_update ( OVS_CB ( skb_mod )->flow, skb_mod );
    ovs_execute_actions ( dp, skb_mod );
    stats_counter = &stats->n_hit;

mod_out:
    u64_stats_update_begin ( &stats->sync );
    ( *stats_counter ) ++;
    stats->n_mask_hit += n_mask_hit;
    u64_stats_update_end ( &stats->sync );


    return;
}

//const union ip client = {{10, 0, 0, 1},};
//const union ip server = {{10, 0, 0, 2},};
//const union ip mirror = {{10, 0, 0, 3},};
static struct host_info server;
static struct host_info mirror;

int pd_setup_hosts(struct host_info* set_server, struct host_info* set_mirror)
{
    int i = 0;
    for(i = 0; i < MAX_TCP_TABLE; ++i)
    {
        while(tcp_info_table[i].packet_buffer.count > 0)
            del_queue(&(tcp_info_table[i].packet_buffer));

        memset(&(tcp_info_table[i]), 0,sizeof(struct tcp_seq_info));
    }
    while(udp_buffer.count > 0)
        del_queue(&(udp_buffer));

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
    union ip ip_src, ip_dst;
    struct iphdr* ip_header;
    unsigned short eth_type = ntohs ( mac_header->h_proto );

    if ( 0x0800 != eth_type )
        return PT_ACTION_CONTINUE;

    ip_header = ip_hdr ( skb );
    if ( ip_header->protocol != UDP_PROTO && ip_header->protocol != TCP_PROTO )
        return PT_ACTION_CONTINUE;

    ip_src.i = ip_header->saddr;
    ip_dst.i = ip_header->daddr;

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
    struct ethhdr* mac_header = eth_hdr ( skb_mod );
    struct iphdr* ip_header = ip_hdr ( skb_mod );
    memcpy(mac_header->h_dest, mirror.mac, 6);
    /*mac_header->h_dest[0] = mirror.mac[0];
    mac_header->h_dest[1] = mirror.mac[1];
    mac_header->h_dest[2] = mirror.mac[2];
    mac_header->h_dest[3] = mirror.mac[3];
    mac_header->h_dest[4] = mirror.mac[4];
    mac_header->h_dest[5] = mirror.mac[5];*/
    ip_header->daddr = mirror.ip.i;
    ip_header->check = 0;
    ip_send_check ( ip_header );
    return 0;
}

int pd_respond_mirror ( struct vport *p, int client_port, unsigned char proto )
{
    struct sk_buff* skb_mod = NULL;
    struct queue_list_head* packet_buf = NULL;

    if ( UDP_PROTO == proto )
        packet_buf = &udp_buffer;
    else
        packet_buf = & ( tcp_info_table[client_port].packet_buffer );

    switch ( proto )
    {
    case UDP_PROTO:
        skb_mod = get_data ( packet_buf );
        while ( NULL != skb_mod )
        {
            pd_modify_ip_mac ( skb_mod );
            send_skbmod ( p, skb_mod );
            skb_mod = get_data ( packet_buf );
        }
        del_queue ( packet_buf );
        break;
    case TCP_PROTO:
        while ( 1 )
        {
            int tcp_s = get_tcp_state ( client_port );
            struct tcphdr* tcp_header;

            if ( TCP_STATE_SYN_RCVD == tcp_s || TCP_STATE_FIN_WAIT1 == tcp_s )
                break;

            skb_mod = get_data ( packet_buf );
            if ( NULL == skb_mod )
            {
                del_queue ( packet_buf );
                break;
            }

            tcp_header = tcp_hdr ( skb_mod );
            pd_modify_ip_mac ( skb_mod );
            if ( !tcp_header->syn )
            {
                unsigned int seq_server = tcp_info_table[client_port].seq_server;
                unsigned int seq_mirror = tcp_info_table[client_port].seq_mirror;
                if ( seq_mirror > seq_server )
                    tcp_header->ack_seq = htonl ( ntohl ( tcp_header->ack_seq ) + ( seq_mirror - seq_server ) );
                else
                    tcp_header->ack_seq = htonl ( ntohl ( tcp_header->ack_seq ) - ( seq_server - seq_mirror ) );
            }
            set_tcp_state ( skb_mod, NULL );
            send_skbmod ( p, skb_mod );
        }
        break;
    default:
        kfree_skb ( skb_mod );
        return -1;
        break;
    }
    return 0;
}

int pd_action_from_mirror ( struct vport *p, struct sk_buff *skb )
{
    struct iphdr* ip_header = ip_hdr ( skb );

    if ( UDP_PROTO == ip_header->protocol )
    {
        struct udphdr* udp_header   = udp_hdr ( skb );
        size_t data_size            = ntohs ( udp_header->len ) - sizeof ( struct udphdr );
        unsigned char* data         = kmalloc ( sizeof ( unsigned char ) * data_size + 1, GFP_KERNEL );

        memcpy ( data, ( char * ) ( ( unsigned char * ) udp_header + sizeof ( struct udphdr ) ), data_size );

        data[data_size] = '\0';
        if ( data_size )
            printk ( KERN_INFO "pd_action_from_mirror UDP data %d: %s\n", data_size, data );

        kfree ( data );
    }
    if ( TCP_PROTO == ip_header->protocol )
    {
        struct tcphdr* tcp_header   = tcp_hdr ( skb );
        unsigned short client_port  = ntohs ( tcp_header->dest );
        size_t data_size            = ntohs ( ip_header->tot_len ) - ( ( ip_header->ihl ) <<2 ) - ( ( tcp_header->doff ) <<2 );
        unsigned char* data         = kmalloc ( sizeof ( unsigned char ) * data_size + 1, GFP_KERNEL );

        memcpy ( data, ( char * ) ( ( unsigned char * ) tcp_header + ( tcp_header->doff * 4 ) ), data_size );
        data[data_size] = '\0';
        if ( data_size )
            printk ( KERN_INFO "pd_action_from_mirror TCP data %d: %s\n", data_size, data );

        kfree ( data );

        if ( tcp_header->syn && tcp_header->ack )
            tcp_info_table[client_port].seq_mirror = ntohl ( tcp_header->seq );

        set_tcp_state ( NULL, skb );
        pd_respond_mirror ( p, client_port, TCP_PROTO );
    }
    return 0;
}

int pd_action_from_client ( struct vport *p, struct sk_buff *skb )
{
    struct sk_buff* skb_mod = skb_copy ( skb, GFP_ATOMIC );
    struct iphdr* ip_header = ip_hdr ( skb_mod );
    struct queue_list_head* packet_buf = NULL;
    if ( UDP_PROTO == ip_header->protocol )
    {
        packet_buf = &udp_buffer;
        if ( 0 == packet_buf->count )
            add_queue ( packet_buf );

        add_data ( packet_buf, skb_mod );
        pd_respond_mirror ( p, -1, UDP_PROTO );
    }

    if ( TCP_PROTO == ip_header->protocol )
    {
        struct tcphdr* tcp_header = tcp_hdr ( skb_mod );
        unsigned short client_port = ntohs ( tcp_header->source );
        packet_buf = & ( tcp_info_table[client_port].packet_buffer );
        if ( 0 == packet_buf->count )
            add_queue ( packet_buf );

        add_data ( packet_buf, skb_mod );
        switch ( get_tcp_state ( client_port ) )
        {
        case TCP_STATE_SYN_RCVD:
        case TCP_STATE_FIN_WAIT1:
            break;
        default:
            pd_respond_mirror ( p, client_port, TCP_PROTO );
            break;
        }
    }
    return 0;
}

int pd_action_from_server ( struct vport *p, struct sk_buff *skb )
{
    struct iphdr* ip_header = ip_hdr ( skb );
    if ( UDP_PROTO == ip_header->protocol )
    {
        struct udphdr* udp_header   = udp_hdr ( skb );
        size_t data_size            = ntohs ( udp_header->len ) - sizeof ( struct udphdr );
        unsigned char* data         = kmalloc ( sizeof ( unsigned char ) * data_size + 1, GFP_KERNEL );

        memcpy ( data, ( char * ) ( ( unsigned char * ) udp_header + sizeof ( struct udphdr ) ), data_size );

        data[data_size] = '\0';
        if ( data_size )
            printk ( KERN_INFO "pd_action_from_server UDP data %d: %s\n", data_size, data );

        kfree ( data );
    }
    if ( TCP_PROTO == ip_header->protocol )
    {
        struct tcphdr* tcp_header   = tcp_hdr ( skb );
        unsigned short client_port  = ntohs ( tcp_header->dest );
        size_t data_size            = ntohs ( ip_header->tot_len ) - ( ( ip_header->ihl ) <<2 ) - ( ( tcp_header->doff ) <<2 );
        unsigned char* data         = kmalloc ( sizeof ( unsigned char ) * data_size + 1, GFP_KERNEL );

        memcpy ( data, ( char * ) ( ( unsigned char * ) tcp_header + ( tcp_header->doff * 4 ) ), data_size );
        data[data_size] = '\0';
        if ( data_size )
            printk ( KERN_INFO "pd_action_from_server TCP data %d: %s\n", data_size, data );

        kfree ( data );

        if ( tcp_header->syn && tcp_header->ack )
            tcp_info_table[client_port].seq_server = ntohl ( tcp_header->seq );
    }
    return 0;
}
