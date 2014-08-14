#ifndef __PACKET_BUFFER_H__
#define __PACKET_BUFFER_H__

#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>

#include "../common.h"

struct pkt_buffer_node
{
    struct list_head list;
    u32 seq_num;
    u32 seq_num_next;
    u32 opt_key;
    struct buf_data *bd;
    int barrier;
};

int pkt_buffer_insert(struct pkt_buffer_node* pbn, struct list_head* head);

struct buf_data* pkt_buffer_get_data(struct list_head* head);
struct buf_data* pkt_buffer_peek_data(struct list_head* head);
int pkt_buffer_cleanup(struct list_head* head);

int pkt_buffer_barrier_add(struct list_head* head);
int pkt_buffer_barrier_remove(struct list_head* head);

#define packet_buffer_remove(bn) \
    list_del(bn->list)

#define packet_buffer_foreach(iterator, head) \
    list_for_each(iterator, head)

#endif