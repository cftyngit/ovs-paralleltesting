#ifndef __CONNECT_STATE_H__
#define __CONNECT_STATE_H__

#include <linux/list.h>
#include <linux/spinlock.h>

#include "kernel_common.h"
#include "ovs_func.h"
#include "tcp_state.h"
#include "util/packet_buffer.h"

struct buf_packet
{
    struct sk_buff* skb;
    struct vport* p;
};

struct commom_buffers
{
    struct list_head packet_buffer;
    struct list_head target_buffer;
    struct list_head mirror_buffer;
};

struct tcp_conn_info
{
    struct commom_buffers buffers;
    struct list_head* playback_ptr;
    struct list_head* send_wnd_right_dege;
    spinlock_t playback_ptr_lock;
    u32 seq_rmhost;
    u32 seq_rmhost_fake;            //in "mirror is client" case used to determine whether OVS has respond fake SYN-ACK
    u32 seq_server;
    u32 seq_mirror;
    u32 seq_fin;
    u32 seq_current;
    u32 seq_next;                   //next seq number that we need to ack
    u32 seq_last_send;
    u32 seq_dup_ack;
    u32 timestamp_last_from_target;
    u32 ackseq_last_from_target;
    u32 ackseq_last_playback;
    int state;
    u32 window_current;             //remain window size
    size_t last_send_size;          //used in calculate remain window size from mirror ACK
    u32 tsval_current;
    u32 tsval_last_send;
    u32 seq_last_ack;               //last ack from mirror
    u16 mirror_port;
    u8 window_scale;
    u8 dup_ack_counter;
};

#define TCP_CONN_INFO_INIT \
{ \
    .seq_server = 0, \
    .seq_mirror = 0, \
    .seq_fin = 0, \
    .seq_current = 0, \
    .seq_next = 0, \
    .state = TCP_STATE_LISTEN, \
    .mirror_port = 0, \
    .buffers = {.packet_buffer = QUEUE_LIST_INIT, }, \
}

struct udp_conn_info
{
    struct commom_buffers buffers;
    u32 current_seq_mirror;
    u32 current_seq_target;
    u32 current_seq_rmhost;
    size_t unlock;
    u16 mirror_port;
};

#define UDP_CONN_INFO_INIT \
{ \
    .mirror_port = 0, \
    .unlock = 0, \
    .buffers = {.packet_buffer = QUEUE_LIST_INIT, }, \
}

struct host_conn_info
{
    struct radix_tree_root tcp_info_set;
    size_t tcp_info_count;
    struct radix_tree_root udp_info_set;
    size_t udp_info_count;
};

struct host_conn_info_set
{
    struct radix_tree_root conn_info_set;
    size_t count;
};

#define HOST_CONN_INFO_SET_INIT   {           \
    .conn_info_set = RADIX_TREE_INIT(GFP_ATOMIC), \
    .count = 0,                            \
}

void* query_connect_info(struct host_conn_info_set* conn_info_set, union my_ip_type ip, u16 proto, u16 port);
int tcp_state_reset(struct host_conn_info_set* conn_info_set, union my_ip_type ip, u16 port);

#define tcp_state_get(conn_info_set, ip, port) ({\
    int ret; \
    struct tcp_conn_info* this_tcp_info = query_connect_info(conn_info_set, ip, IPPROTO_TCP, port); \
    ret = this_tcp_info != NULL ? this_tcp_info->state : -1; \
    ret; \
})

#define tcp_state_set(conn_info_set, ip, port, value) ({\
    struct tcp_conn_info* this_tcp_info = query_connect_info(conn_info_set, ip, IPPROTO_TCP, port); \
    if(NULL != this_tcp_info) \
        this_tcp_info->state = value; \
    NULL != this_tcp_info ? value : -1; \
})

#define TCP_CONN_INFO(conn_info_set, ip, port) \
    ((struct tcp_conn_info*)query_connect_info((conn_info_set), (ip), (IPPROTO_TCP), (port)))

#define UDP_CONN_INFO(conn_info_set, ip, port) \
    ((struct udp_conn_info*)query_connect_info((conn_info_set), (ip), (IPPROTO_UDP), (port)))

#endif
