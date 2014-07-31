#ifndef __COMPARE_BUFFER_H__
#define __COMPARE_BUFFER_H__

#include <linux/list.h>
#include <linux/kernel.h>

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

int compare_buffer_insert(struct buffer_node* bn, struct list_head* head);

#define compare_buffer_remove(bn) \
    list_del(bn->list)

#define compare_buffer_foreach(iterator, head) \
    list_for_each(iterator, head)

#endif