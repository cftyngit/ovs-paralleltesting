#ifndef __CONNECT_STATE_H__
#define __CONNECT_STATE_H__

#include <linux/vmalloc.h>

#include "common.h"
#include "ovs_func.h"
#include "util/queue_list.h"
#include "tcp_state.h"

struct buf_packet
{
    struct sk_buff* skb;
    struct vport* p;
};

struct commom_buffers
{
    struct queue_list_head packet_buffer;
};

struct tcp_conn_info
{
    u32 seq_server;
    u32 seq_mirror;
    u32 seq_fin;
    u32 seq_current;
    u32 seq_next;
    int state;
    u16 mirror_port;
    struct commom_buffers buffers;
};

struct udp_conn_info
{
    struct commom_buffers buffers;
};

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
    .conn_info_set = RADIX_TREE_INIT(GFP_KERNEL), \
    .count = 0,                            \
}

void* query_connect_info(struct host_conn_info_set* conn_info_set, union my_ip_type ip, u16 proto, u16 port);
int tcp_state_reset(struct host_conn_info_set* conn_info_set, union my_ip_type ip, u16 port);

#define tcp_state_get(conn_info_set, ip, port) \
    (((struct tcp_conn_info*)query_connect_info(conn_info_set, ip, IPPROTO_TCP, port))->state)

#define tcp_state_set(conn_info_set, ip, port, value) \
    (((struct tcp_conn_info*)query_connect_info(conn_info_set, ip, IPPROTO_TCP, port))->state = value)

#define TCP_CONN_INFO(conn_info_set, ip, port) \
    ((struct tcp_conn_info*)query_connect_info((conn_info_set), (ip), (IPPROTO_TCP), (port)))

#define UDP_CONN_INFO(conn_info_set, ip, port) \
    ((struct udp_conn_info*)query_connect_info((conn_info_set), (ip), (IPPROTO_UDP), (port)))

#endif