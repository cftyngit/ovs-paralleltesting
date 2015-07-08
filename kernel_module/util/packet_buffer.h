#ifndef __PACKET_BUFFER_H__
#define __PACKET_BUFFER_H__

#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/tcp.h>

#include "../kernel_common.h"

struct buf_data
{
    int retrans_times;
	int should_delete;
    struct timer_list timer;
    struct sk_buff* skb;
    struct other_args* p;
    void* conn_info;
};

struct pkt_buffer_node
{
    struct list_head list;
    u32 seq_num;
    u32 seq_num_next;
    u32 opt_key;
    struct buf_data *bd;
    int barrier;
};

typedef struct packet_buffer_s
{
	struct list_head buffer_head;
	spinlock_t packet_lock;
	int node_count;
	unsigned long lastest_jiff;
}packet_buffer_t;

void pkt_buffer_init(packet_buffer_t* pbuf);
int pkt_buffer_insert(struct pkt_buffer_node* pbn, packet_buffer_t* pbuf);
int pkt_buffer_delete(struct list_head *iterator, packet_buffer_t* pbuf);
int pkt_buffer_isempty(packet_buffer_t* pbuf);

struct buf_data* pkt_buffer_get_data(packet_buffer_t* pbuf);
struct buf_data* pkt_buffer_peek_data(packet_buffer_t* pbuf);
/**
 * pkt_buffer_peek_data_from_ptr - peek buf_data from given pointer
 * this function must protected in spinlock_t packet_lock
 * @pbuf: packet_buffer
 * @ptr: pointer point to target buf_node, it will point to the next buf_node when this function return
 * @return pointer poin to buf_data contained in ptr pointed or NULL if some error happen
 */
struct buf_data* pkt_buffer_peek_data_from_ptr(packet_buffer_t* pbuf, struct list_head** ptr);

int pkt_buffer_cleanup(packet_buffer_t* pbuf);

int pkt_buffer_barrier_add(packet_buffer_t* pbuf);
int pkt_buffer_barrier_remove(packet_buffer_t* pbuf);

#define packet_buffer_remove(bn) \
    list_del(bn->list)

#define packet_buffer_foreach(iterator, head) \
    list_for_each(iterator, head)

#endif
