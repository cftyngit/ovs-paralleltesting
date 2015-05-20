#include "connect_state.h"

struct host_conn_info_set conn_info_set = HOST_CONN_INFO_SET_INIT;

static inline void init_buffers(struct commom_buffers* bufs)
{
    pkt_buffer_init(&bufs->packet_buffer);
    INIT_LIST_HEAD(&(bufs->mirror_buffer.buffer_head));
	spin_lock_init(&(bufs->mirror_buffer.compare_lock));
    INIT_LIST_HEAD(&(bufs->target_buffer.buffer_head));
	spin_lock_init(&(bufs->target_buffer.compare_lock));
    bufs->mirror_buffer.compare_head = NULL;
    bufs->target_buffer.compare_head = NULL;
}

static inline void init_tcp_info(struct tcp_conn_info* tcp_info)
{
    memset(tcp_info, 0, sizeof(struct tcp_conn_info));
    tcp_info->state = TCP_STATE_LISTEN;
    init_buffers(&(tcp_info->buffers));
    tcp_info->playback_ptr = &(tcp_info->buffers.packet_buffer.buffer_head);
    tcp_info->send_wnd_right_dege = &(tcp_info->buffers.packet_buffer.buffer_head);
    spin_lock_init(&(tcp_info->info_lock));
	spin_lock_init(&(tcp_info->compare_lock));
	spin_lock_init(&(tcp_info->retranstimer_lock));
}

static inline void init_udp_info(struct udp_conn_info* udp_info)
{
    memset(udp_info, 0, sizeof(struct udp_conn_info));
    init_buffers(&(udp_info->buffers));
	spin_lock_init(&(udp_info->compare_lock));
}

void* query_connect_info(struct host_conn_info_set* conn_info_set, union my_ip_type ip, u16 proto, u16 port)
{
    struct host_conn_info* get_conn_info;
    void* get_proto_state = NULL;
    if(proto != IPPROTO_TCP && proto != IPPROTO_UDP)
        return NULL;

    get_conn_info = radix_tree_lookup(&(conn_info_set->conn_info_set), ip.i);
    if(get_conn_info)
    {
        switch(proto)
        {
        case IPPROTO_TCP:
            get_proto_state = radix_tree_lookup(&(get_conn_info->tcp_info_set), port);
            if(!get_proto_state)
            {
                get_proto_state = kmalloc(sizeof(struct tcp_conn_info), GFP_KERNEL);
                if(NULL == get_proto_state)
                    break;

                init_tcp_info(get_proto_state);
                radix_tree_insert(&(get_conn_info->tcp_info_set), port, get_proto_state);
            }
            break;
        case IPPROTO_UDP:
            get_proto_state = radix_tree_lookup(&(get_conn_info->udp_info_set), port);
            if(!get_proto_state)
            {
                get_proto_state = kmalloc(sizeof(struct udp_conn_info), GFP_KERNEL);
                if(NULL == get_proto_state)
                    break;

                init_udp_info(get_proto_state);
                radix_tree_insert(&(get_conn_info->udp_info_set), port, get_proto_state);
            }
            break;
        }
    }
    else
    {
        get_conn_info = kmalloc(sizeof(struct host_conn_info), GFP_KERNEL);
        if(NULL == get_conn_info)
            return NULL;

        INIT_RADIX_TREE(&(get_conn_info->tcp_info_set), GFP_KERNEL);
        INIT_RADIX_TREE(&(get_conn_info->udp_info_set), GFP_KERNEL);
        switch(proto)
        {
        case IPPROTO_TCP:
            get_proto_state = kmalloc(sizeof(struct tcp_conn_info), GFP_KERNEL);
            if(NULL == get_proto_state)
                break;

            init_tcp_info(get_proto_state);
            radix_tree_insert(&(get_conn_info->tcp_info_set), port, get_proto_state);
            break;
        case IPPROTO_UDP:
            get_proto_state = kmalloc(sizeof(struct udp_conn_info), GFP_KERNEL);
            if(NULL == get_proto_state)
                break;

            init_udp_info(get_proto_state);
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
        pkt_buffer_cleanup(&(get_proto_state->buffers.packet_buffer));
        radix_tree_delete(&(get_conn_info->tcp_info_set), port);
        kfree(get_proto_state);
        get_conn_info->tcp_info_count--;
    }
    if( get_conn_info->tcp_info_count || get_conn_info->udp_info_count )
        return 1;

    radix_tree_delete(&(conn_info_set->conn_info_set), ip.i);
    kfree(get_conn_info);
    conn_info_set->count--;
    return 0;
}

static void tcp_stat_cleanup(struct radix_tree_root* tcp_info_set)
{
	struct radix_tree_iter iter;
	void **slot = NULL;

	radix_tree_for_each_slot(slot, tcp_info_set, &iter, 0)
	{
		struct tcp_conn_info* tci = radix_tree_deref_slot(slot);
		if(tci != NULL)
		{
			PRINT_DEBUG("information about tcp: %lu\n", iter.index);
			while(pkt_buffer_cleanup(&(tci->buffers.packet_buffer)))
				ssleep(1);

			compare_buffer_cleanup(&(tci->buffers.mirror_buffer));
			compare_buffer_cleanup(&(tci->buffers.target_buffer));
			radix_tree_delete(tcp_info_set, iter.index);
			kfree(tci);
		}
	}
}

static void udp_stat_cleanup(struct radix_tree_root* udp_info_set)
{
	struct radix_tree_iter iter;
	void **slot = NULL;

	radix_tree_for_each_slot(slot, udp_info_set, &iter, 0)
	{
		struct udp_conn_info* uci = radix_tree_deref_slot(slot);
		if(uci != NULL)
		{
			PRINT_DEBUG("information about udp: %lu\n", iter.index);
			while(pkt_buffer_cleanup(&(uci->buffers.packet_buffer)))
				ssleep(1);

			compare_buffer_cleanup(&(uci->buffers.mirror_buffer));
			compare_buffer_cleanup(&(uci->buffers.target_buffer));
			radix_tree_delete(udp_info_set, iter.index);
			kfree(uci);
		}
	}
}

void connect_stat_cleanup(struct host_conn_info_set* conn_info_set)
{
	struct radix_tree_iter iter;
	void **slot = NULL;
	radix_tree_for_each_slot(slot, &conn_info_set->conn_info_set, &iter, 0)
	{
		struct host_conn_info *hci = radix_tree_deref_slot(slot);
		if(hci != NULL)
		{
			PRINT_DEBUG("information about page: %lu\n", iter.index);
			tcp_stat_cleanup(&hci->tcp_info_set);
			udp_stat_cleanup(&hci->udp_info_set);
			radix_tree_delete(&(conn_info_set->conn_info_set), iter.index);
			kfree(hci);
			conn_info_set->count--;
		}
	}
}
