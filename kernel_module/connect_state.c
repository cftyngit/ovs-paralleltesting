#include "connect_state.h"

void* query_connect_info(struct host_conn_info_set* conn_info_set, union my_ip_type ip, u16 proto, u16 port)
{
    struct host_conn_info* get_conn_info;
    void* get_proto_state = NULL;
    if(proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return NULL;

    get_conn_info = radix_tree_lookup(&(conn_info_set->conn_info_set), ip.i);
    printk("get_conn_info = %p\n", get_conn_info);
    if(get_conn_info)
    {
        switch(proto)
        {
        case IPPROTO_TCP:
            get_proto_state = radix_tree_lookup(&(get_conn_info->tcp_info_set), port);
            if(!get_proto_state)
            {
                get_proto_state = kmalloc(sizeof(struct tcp_conn_info), GFP_KERNEL);
                memset(get_proto_state, 0, sizeof(struct tcp_conn_info));
                ((struct tcp_conn_info*)get_proto_state)->state = TCP_STATE_LISTEN;
                radix_tree_insert(&(get_conn_info->tcp_info_set), port, get_proto_state);
            }
            break;
        case IPPROTO_UDP:
            get_proto_state = radix_tree_lookup(&(get_conn_info->udp_info_set), port);
            if(!get_proto_state)
            {
                get_proto_state = kmalloc(sizeof(struct udp_conn_info), GFP_KERNEL);
                memset(get_proto_state, 0, sizeof(struct udp_conn_info));
                radix_tree_insert(&(get_conn_info->udp_info_set), port, get_proto_state);
            }
            break;
        }
    }
    else
    {
        get_conn_info = kmalloc(sizeof(struct host_conn_info), GFP_KERNEL);
        INIT_RADIX_TREE(&(get_conn_info->tcp_info_set), GFP_KERNEL);
        INIT_RADIX_TREE(&(get_conn_info->udp_info_set), GFP_KERNEL);
        switch(proto)
        {
        case IPPROTO_TCP:
            get_proto_state = kmalloc(sizeof(struct tcp_conn_info), GFP_KERNEL);
            memset(get_proto_state, 0, sizeof(struct tcp_conn_info));
            ((struct tcp_conn_info*)get_proto_state)->state = TCP_STATE_LISTEN;
            radix_tree_insert(&(get_conn_info->tcp_info_set), port, get_proto_state);
            break;
        case IPPROTO_UDP:
            get_proto_state = kmalloc(sizeof(struct udp_conn_info), GFP_KERNEL);
            memset(get_proto_state, 0, sizeof(struct udp_conn_info));
            radix_tree_insert(&(get_conn_info->udp_info_set), port, get_proto_state);
            break;
        }
        radix_tree_insert(&(conn_info_set->conn_info_set), ip.i, get_conn_info);
        conn_info_set->count++;
    }
    return get_proto_state;
}

int tcp_state_reset(struct host_conn_info_set* conn_info_set, union my_ip_type ip, u16 port)
{
    struct tcp_conn_info* get_proto_state = NULL;
    struct host_conn_info* get_conn_info = radix_tree_lookup(&(conn_info_set->conn_info_set), ip.i);
    if(!get_conn_info)
        return 1;

    get_proto_state = radix_tree_lookup(&(get_conn_info->tcp_info_set), port);
    if(get_proto_state)
    {
        clean_queue_list(&(get_proto_state->buffers.packet_buffer));
        radix_tree_delete(&(get_conn_info->tcp_info_set), port);
        get_conn_info->tcp_info_count--;
    }

    if( get_conn_info->tcp_info_count || get_conn_info->udp_info_count )
        return 1;

    radix_tree_delete(&(conn_info_set->conn_info_set), ip.i);
    conn_info_set->count--;
    return 0;
}
