#include "compare_buffer.h"
#include "../kernel_common.h"

int compare_buffer_insert(struct buffer_node* bn, struct compare_buffer* buffer)
{
    struct list_head *head = NULL, *insert_point = NULL;
    struct buffer_node *iterator, *n;
    //u32 last_seq_next = head->prev ? list_entry(head->prev, struct buffer_node, list)->seq_num_next : 0;
//	struct list_head* prev = NULL;
	struct buffer_node* bn_n = NULL;
	struct buffer_node* bn_p = NULL;
	struct buffer_node* bn_this = bn;
	u32 data_start = 0;
	u32 data_end = bn->seq_num_next - bn->seq_num;

	spin_lock_bh(&(buffer->compare_lock));
	head = &buffer->buffer_head;
	insert_point = head;
	if(after(buffer->least_seq, bn->seq_num))
	{
		PRINT_DEBUG("retrans? least_seq: %u, bn_seq_num: %u\n", buffer->least_seq, bn->seq_num);
		goto free;
	}
	if(list_empty(head))
		goto insert;
//     {
//         list_add(&bn->list, head);
//         goto exit;
//     }
	list_for_each_entry_safe_reverse(iterator, n, head, list)
	{
		insert_point = &iterator->list;
		if(iterator->seq_num_next == bn->seq_num_next || after(iterator->seq_num_next, bn->seq_num_next))
			bn_p = iterator;
		if(iterator->seq_num == bn->seq_num || before(iterator->seq_num, bn->seq_num))
		{
			bn_n = iterator;
			break;
		}
		if(bn_n != iterator && bn_p != iterator)
			del_buffer_node(iterator);
	}
	if(head == &iterator->list)
		insert_point = head;
// 	list_for_each_prev(iterator, head)
// 	{
// 		struct buffer_node* this_node = list_entry(iterator, struct buffer_node, list);
// // 		if(this_node->seq_num_next <= bn->seq_num || this_node->opt_key < bn->opt_key)
// // 			break;
// 		if(this_node->seq_num_next == bn->seq_num || before(this_node->seq_num_next, bn->seq_num))
// 			break;
// 
// 		prev = iterator;
// 	}
	if(bn_n && bn_p && bn_n == bn_p)
	{
		PRINT_DEBUG("insert data is cover by buffer data\n", __LINE__);
		goto free;
	}
// 	if(!prev || bn->seq_num_next <= list_entry(prev, struct buffer_node, list)->seq_num)
// 		list_add(&bn->list, iterator);
// 	else
// 		PRINT_ERROR("prev: %p, seq_next: %u, ite_seq_next: %u\n", prev, bn->seq_num_next, list_entry(prev, struct buffer_node, list)->seq_num);
insert:
	if(bn_n && after(bn_n->seq_num_next, bn->seq_num))
		data_start = bn_n->seq_num_next - bn->seq_num;

	if(bn_p && before(bn_p->seq_num, bn->seq_num_next))
		data_end = data_end - (u32)(bn->seq_num - bn_p->seq_num_next);

	if(data_start != 0 || data_end != bn->seq_num_next - bn->seq_num)
	{
		u32 data_size = 0;
		if(after(data_start, data_end))
			goto free;

		data_size = data_end - data_start;
		bn_this = kmalloc ( sizeof ( struct buffer_node ) , GFP_KERNEL );
		bn_this->opt_key = bn->opt_key;
		bn_this->seq_num = bn->seq_num + data_start;
		bn_this->seq_num_next = bn->seq_num_next - data_end;
		bn_this->payload.length = data_size;
		bn_this->payload.remain = data_size;
		bn_this->payload.data = kmalloc ( sizeof ( unsigned char ) * data_size + 1, GFP_KERNEL );
		memcpy ( bn_this->payload.data, bn->payload.data, data_size );
	}
	PRINT_DEBUG("insert: (%u, %u)\n", bn_this->seq_num, bn_this->seq_num_next);
	list_add(&bn_this->list, insert_point);
	if(bn == bn_this)
		goto exit;
free:
	kfree(bn->payload.data);
	kfree(bn);
exit:
	spin_unlock_bh(&(buffer->compare_lock));
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
	{
		PRINT_DEBUG("list_empty\n");
		return NULL;
	}
	spin_lock_bh(&(buffer->compare_lock));
	if(NULL == buffer->compare_head)
	{
		PRINT_DEBUG("compare_head = NULL\n");
        buffer->compare_head = list_entry(buffer->buffer_head.next, struct buffer_node, list);
	}
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
			buffer->least_seq = next_item->seq_num;
		}
	}
	spin_unlock_bh(&(buffer->compare_lock));
	return ret;
}

size_t compare_buffer_consume(size_t size, struct compare_buffer* buffer)
{
	size_t ret = 0;
	struct data_node* target = compare_buffer_getblock(buffer);
	spin_lock_bh(&(buffer->compare_lock));
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
	spin_unlock_bh(&(buffer->compare_lock));
	return ret;
}

int compare_buffer_cleanup(struct compare_buffer* buffer)
{
	struct list_head *iterator = NULL, *tmp = NULL, *head = &(buffer->buffer_head);
	struct buffer_node *bn = NULL;
	if(list_empty(head))
		return 0;

	list_for_each_safe(iterator, tmp, head)
	{
		if(iterator == NULL || iterator == LIST_POISON1 || iterator == LIST_POISON2)
			continue;

		list_del(iterator);
		bn = list_entry(iterator, struct buffer_node, list);
		kfree(bn->payload.data);
		kfree(bn);
	}
	return 0;
}

int compare_buffer_gethole(u32* seq_num, struct compare_buffer* buffer)
{
	struct list_head *head = NULL;
	struct buffer_node *iterator;
	u32 this_seq_num = 0;
	u32 seq_next = 0;

	spin_lock_bh(&(buffer->compare_lock));
	head = &buffer->buffer_head;

	if(list_empty(head))
	{
		spin_unlock_bh(&(buffer->compare_lock));
		return -1;
	}
	list_for_each_entry(iterator, head, list)
	{
		printk("(%u, %u) ", this_seq_num, seq_next);
		if((this_seq_num == 0 && seq_next == 0) || iterator->seq_num == seq_next)
		{
			this_seq_num = iterator->seq_num;
			seq_next = iterator->seq_num_next;
		}
		else
			break;
	}
	printk("(%u, %u) ", this_seq_num, seq_next);
	spin_unlock_bh(&(buffer->compare_lock));
	*seq_num = seq_next;
	return 0;
}
