#include "compare_buffer.h"

int compare_buffer_insert(struct buffer_node* bn, struct list_head* head)
{
    struct list_head *iterator;
    //u32 last_seq_next = head->prev ? list_entry(head->prev, struct buffer_node, list)->seq_num_next : 0;
	struct list_head* prev = NULL;
    if(list_empty(head))
    {
        list_add(&bn->list, head);
        return 0;
    }
	list_for_each_prev(iterator, head)
	{
		if(list_entry(iterator, struct buffer_node, list)->seq_num_next <= bn->seq_num)
			break;

		prev = iterator;
	}
	if(!prev || bn->seq_num_next <= list_entry(prev, struct buffer_node, list)->seq_num)
		list_add(&bn->list, iterator);
	else
		printk("[%s] prev: %p, seq_next: %u, ite_seq_next: %u\n", __func__, prev, bn->seq_num_next, list_entry(prev, struct buffer_node, list)->seq_num);

	/*
    if(bn->seq_num > last_seq_next && bn->seq_num - last_seq_next > UINT_MAX >> 1)
    {
        struct list_head* prev = NULL;
        list_for_each(iterator, head)
        {
            if(bn->seq_num <= list_entry(iterator, struct buffer_node, list)->seq_num_next)
                break;

            prev = iterator;
        }
        if(prev && bn->seq_num > list_entry(prev, struct buffer_node, list)->seq_num)
            list_add_tail(&bn->list, iterator);
    }
    else
    {
        struct list_head* prev = NULL;
        list_for_each_prev(iterator, head)
        {
            if(list_entry(iterator, struct buffer_node, list)->seq_num_next <= bn->seq_num)
                break;

            prev = iterator;
        }
        if(prev && bn->seq_num < list_entry(prev, struct buffer_node, list)->seq_num)
            list_add(&bn->list, iterator);
    }
	*/
    return 0;
}
