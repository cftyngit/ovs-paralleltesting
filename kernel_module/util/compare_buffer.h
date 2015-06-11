#ifndef __COMPARE_BUFFER_H__
#define __COMPARE_BUFFER_H__

#include <linux/list.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <net/tcp.h>

struct data_node
{
    size_t length;
    size_t remain;
    char* data;
};

struct buffer_node
{
    struct list_head list;
    u32 seq_num;
    u32 seq_num_next;
    u32 opt_key;
    struct data_node payload;
};

struct compare_buffer
{
    struct list_head buffer_head;
	spinlock_t compare_lock;
    struct buffer_node* compare_head;
	u32 least_seq;
};

int compare_buffer_insert(struct buffer_node* bn, struct compare_buffer* buffer);
struct data_node* compare_buffer_getblock(struct compare_buffer* buffer);
size_t compare_buffer_consume(size_t size, struct compare_buffer* buffer);
void del_buffer_node(struct buffer_node* bn);
int compare_buffer_cleanup(struct compare_buffer* buffer);
int compare_buffer_gethole(u32* seq_num, struct compare_buffer* buffer);

#define compare_buffer_remove(bn) \
    list_del(bn->list)

#define compare_buffer_foreach(iterator, head) \
    list_for_each(iterator, head)

#endif