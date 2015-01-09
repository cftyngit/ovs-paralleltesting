#include "compare_buffer.h"

int compare_buffer_insert(struct buffer_node* bn, struct compare_buffer* buffer)
{
    struct list_head* head = &(buffer->buffer_head);
    struct list_head *iterator;
    //u32 last_seq_next = head->prev ? list_entry(head->prev, struct buffer_node, list)->seq_num_next : 0;
	struct list_head* prev = NULL;
	spin_lock(&(buffer->compare_lock));
    if(list_empty(head))
    {
        list_add(&bn->list, head);
        goto exit;
    }
	list_for_each_prev(iterator, head)
	{
        struct buffer_node* this_node = list_entry(iterator, struct buffer_node, list);
		if(this_node->seq_num_next <= bn->seq_num || this_node->opt_key < bn->opt_key)
			break;

		prev = iterator;
	}
	if(!prev || bn->seq_num_next <= list_entry(prev, struct buffer_node, list)->seq_num)
		list_add(&bn->list, iterator);
	else
		printk(KERN_ERR "[%s] prev: %p, seq_next: %u, ite_seq_next: %u\n", __func__, prev, bn->seq_num_next, list_entry(prev, struct buffer_node, list)->seq_num);
exit:
	spin_unlock(&(buffer->compare_lock));
    return 0;
}

void del_buffer_node(struct buffer_node* bn)
{
    list_del(&bn->list);
    kfree(bn->payload.data);
    kfree(bn);
}

struct data_node* compare_buffer_getblock(struct compare_buffer* buffer)
{
	struct data_node* ret = NULL;

	if(list_empty(&(buffer->buffer_head)))
		return NULL;

	spin_lock(&(buffer->compare_lock));
	if(NULL == buffer->compare_head)
        buffer->compare_head = list_entry(buffer->buffer_head.next, struct buffer_node, list);

	if(buffer->compare_head && buffer->compare_head->payload.remain > 0)
		ret = &(buffer->compare_head->payload);
    else
	{
		struct buffer_node* next_item = buffer->compare_head->list.next != &(buffer->buffer_head) ? list_entry(buffer->compare_head->list.next, struct buffer_node, list) : NULL;
		if(next_item && next_item->seq_num == buffer->compare_head->seq_num_next)
		{
			ret = &(next_item->payload);
			del_buffer_node ( buffer->compare_head );
			buffer->compare_head = next_item;
		}
	}
	spin_unlock(&(buffer->compare_lock));
	return ret;
}

size_t compare_buffer_consume(size_t size, struct compare_buffer* buffer)
{
	size_t ret = 0;
	struct data_node* target = compare_buffer_getblock(buffer);
	spin_lock(&(buffer->compare_lock));
	if(NULL == target)
		goto exit;

	if(size > target->remain)
	{
		ret = target->remain;
		target->remain = 0;
	}
	else
	{
		ret = size;
		target->remain -= size;
	}
	/*
	 * peek next item, if next item is "THE NEXT ONE" && is tail(payload.length == 0), free both node
	 */
	if(target->remain == 0)
	{
		struct buffer_node* next_item = buffer->compare_head->list.next != &(buffer->buffer_head) ? list_entry(buffer->compare_head->list.next, struct buffer_node, list) : NULL;
		if(next_item && next_item->seq_num == buffer->compare_head->seq_num_next && next_item->payload.length == 0)
		{
			del_buffer_node(buffer->compare_head);
			del_buffer_node(next_item);
			buffer->compare_head = NULL;
		}
	}
exit:
	spin_unlock(&(buffer->compare_lock));
	return ret;
}
