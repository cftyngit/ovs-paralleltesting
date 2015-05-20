#include "packet_buffer.h"

inline void pkt_buffer_init(packet_buffer_t* pbuf)
{
	INIT_LIST_HEAD(&(pbuf->buffer_head));
	spin_lock_init(&(pbuf->packet_lock));
}

int pkt_buffer_insert(struct pkt_buffer_node* pbn, packet_buffer_t* pbuf)
{
	struct list_head* head = NULL;
	struct list_head *iterator;
	struct list_head* prev = NULL;
	struct pkt_buffer_node* pbn_i = NULL;
	struct pkt_buffer_node* pbn_p = NULL;
	u64 pbn_seq = (u64)pbn->opt_key << 32 | pbn->seq_num;
// 	u64 pbn_seq_n = (u64)pbn->opt_key << 32 | pbn->seq_num_next;
//	u64 pbn_i_seq = 0, pbn_i_seq_n = 0, pbn_p_seq = 0, pbn_p_seq_n = 0;

	spin_lock_bh(&pbuf->packet_lock);
	head = &pbuf->buffer_head;
	if(list_empty(head))
	{
		list_add(&pbn->list, head);
		goto out;
	}

	list_for_each_prev(iterator, head)
	{
		struct pkt_buffer_node* tmp = list_entry(iterator, struct pkt_buffer_node, list);
		if(abs(tmp->seq_num - pbn->seq_num) > U32_MAX>>1)
		{
			u64 iter_seq_n = (u64)tmp->opt_key << 32 | tmp->seq_num_next;
			if(iter_seq_n <= pbn_seq)
				break;
		}
		else
		{
			if(tmp->seq_num_next <= pbn->seq_num)
				break;
		}
		prev = iterator;
	}
//	printk("[%s] pbn: (%u, %u, %u)\n", __func__, pbn->opt_key, pbn->seq_num, pbn->seq_num_next);
	/**
	 *       seq_num_next     seq_num
	 *          v               v
	 * ----------               ------
	 * |iterator|               |prev|
	 * ----------               ------
	 */
	/**
	 * at tail of queue: insert
	 */
	if(!prev)
		goto insert;
	
	pbn_i = list_entry(iterator, struct pkt_buffer_node, list);
	pbn_p = list_entry(prev, struct pkt_buffer_node, list);
// 	pbn_i_seq = (u64)pbn_i->opt_key << 32 | pbn_i->seq_num;
// 	pbn_i_seq_n = (u64)pbn_i->opt_key << 32 | pbn_i->seq_num_next;
// 	pbn_p_seq = (u64)pbn_p->opt_key << 32 | pbn_p->seq_num;
// 	pbn_p_seq_n = (u64)pbn_p->opt_key << 32 | pbn_p->seq_num_next;
	/**
	 * no spaces between inerator and prev: free
	 */
	if(abs(pbn_p->seq_num - pbn_i->seq_num_next) < U32_MAX>>1 && pbn_i->seq_num_next >= pbn_p->seq_num)
		goto free;
	/**
	 * pbn overlap with iterator or prev: free
	 */
	if(abs(pbn->seq_num_next - pbn_i->seq_num_next) < U32_MAX>>1 && pbn_i->seq_num_next >= pbn->seq_num_next)
		goto free;
	if(abs(pbn_p->seq_num - pbn->seq_num) < U32_MAX>>1 && pbn_p->seq_num <= pbn->seq_num)
		goto free;
	/*
	if(!prev || pbn->seq_num_next <= list_entry(prev, struct pkt_buffer_node, list)->seq_num || pbn->seq_num_next < list_entry(prev, struct pkt_buffer_node, list)->seq_num_next)
	{
		list_add(&pbn->list, iterator);
	}
	else
	{
		struct pkt_buffer_node* tmp = list_entry(prev, struct pkt_buffer_node, list);
		printk("[%s] prev: %p (%u, %u), pbn: (%u, %u)\n", __func__, prev, tmp->seq_num, tmp->seq_num_next, pbn->seq_num, pbn->seq_num_next);

		kfree(pbn->bd->p);
		kfree_skb(pbn->bd->skb);
		kfree(pbn->bd);
		kfree(pbn);
	}*/
//	list_add(&pbn->list, iterator);
	
insert:
//	printk("[%s] insert: iter: (%llu, %llu), pbn: (%llu, %llu), prev: (%llu, %llu)\n", __func__, pbn_i_seq, pbn_i_seq_n, pbn_seq, pbn_seq_n, pbn_p_seq, pbn_p_seq_n);
	list_add(&pbn->list, iterator);
	goto out;
free:
	printk("[%s] free: iter: (%u, %u), pbn: (%u, %u), prev: (%u, %u)\n", __func__, pbn_i->seq_num, pbn_i->seq_num_next, pbn->seq_num, pbn->seq_num_next, pbn_p->seq_num, pbn_p->seq_num_next);
	kfree(pbn->bd->p);
	kfree_skb(pbn->bd->skb);
	kfree(pbn->bd);
	kfree(pbn);
	goto out;
out:
	spin_unlock_bh(&pbuf->packet_lock);
	return 0;
}

struct buf_data* pkt_buffer_get_data(packet_buffer_t* pbuf)
{
	struct list_head* head = NULL;
	struct list_head* pos = NULL;
	struct buf_data *bd = NULL;

	spin_lock_bh(&pbuf->packet_lock);
	head = &pbuf->buffer_head;
	if(list_empty(head))
		goto out;

	pos = (head)->next;
	if(list_entry(pos, struct pkt_buffer_node, list)->barrier)
		goto out;

	bd = list_entry(pos, struct pkt_buffer_node, list)->bd;
	list_del(pos);
out:
	spin_unlock_bh(&pbuf->packet_lock);
	return bd;
}

struct buf_data* pkt_buffer_peek_data(packet_buffer_t* pbuf)
{
	struct list_head* head = NULL;
	struct list_head* pos = NULL;
	struct buf_data *bd = NULL;

	spin_lock_bh(&pbuf->packet_lock);
	head = &pbuf->buffer_head;
	if(list_empty(head))
		goto out;

	pos = (head)->next;
	if(list_entry(pos, struct pkt_buffer_node, list)->barrier)
		goto out;

	bd = list_entry(pos, struct pkt_buffer_node, list)->bd;
out:
	spin_unlock_bh(&pbuf->packet_lock);
	return bd;
}

int pkt_buffer_barrier_add(packet_buffer_t* pbuf)
{
	struct list_head* head = NULL;
	struct list_head* pos = NULL;
	struct pkt_buffer_node* pbn = NULL;
	int ret = -1;

	spin_lock_bh(&pbuf->packet_lock);
	head = &pbuf->buffer_head;
	if(list_empty(head))
		goto out;

	pos = (head)->next;
	pbn = list_entry(pos, struct pkt_buffer_node, list);
	ret = ++pbn->barrier;
out:
	spin_unlock_bh(&pbuf->packet_lock);
	return ret;
}

int pkt_buffer_barrier_remove(packet_buffer_t* pbuf)
{
	struct list_head* head = NULL;
	struct list_head* pos = NULL;
	struct pkt_buffer_node* pbn = NULL;
	int ret = -1;

	spin_lock_bh(&pbuf->packet_lock);
	head = &pbuf->buffer_head;
	if(list_empty(head))
		goto out;

	pos = (head)->next;
	pbn = list_entry(pos, struct pkt_buffer_node, list);
	if(pbn->barrier)
		ret = --pbn->barrier;
	else
		ret = pbn->barrier;
out:
	spin_unlock_bh(&pbuf->packet_lock);
	return ret;    
}

int pkt_buffer_cleanup(packet_buffer_t* pbuf)
{
	struct list_head* head = NULL;
	struct list_head *iterator = NULL, *tmp = NULL;
	struct pkt_buffer_node *pbn = NULL;
	int ret = 0;

	if(!spin_trylock_bh(&pbuf->packet_lock))
		return -1;

	head = &pbuf->buffer_head;
	if(list_empty(head))
		goto out;

	list_for_each_safe(iterator, tmp, head)
	{
		if(iterator == NULL || iterator == LIST_POISON1 || iterator == LIST_POISON2)
			continue;
        
		pbn = list_entry(iterator, struct pkt_buffer_node, list);
		if((ret = try_to_del_timer_sync(&pbn->bd->timer)) < 0)
			continue;

		list_del(iterator);
		kfree(pbn->bd->p);
		pbn->bd->p = NULL;
		kfree_skb(pbn->bd->skb);
		pbn->bd->skb = NULL;
		kfree(pbn->bd);
		pbn->bd = NULL;
		kfree(pbn);
	}
out:
	spin_unlock_bh(&pbuf->packet_lock);
	return ret;
}

struct buf_data* pkt_buffer_peek_data_from_ptr(packet_buffer_t* pbuf, struct list_head** ptr)
{
	struct list_head* head = &pbuf->buffer_head;
	struct pkt_buffer_node* pbn = NULL;
	struct list_head* this_ptr = *ptr;

	if(this_ptr == NULL || this_ptr == LIST_POISON1 || this_ptr == LIST_POISON2)
		return NULL;

	if(this_ptr->next == NULL || this_ptr->next == head || this_ptr->next == LIST_POISON1 || this_ptr->next == LIST_POISON2)
		return NULL;

	pbn = list_entry(this_ptr->next, struct pkt_buffer_node, list);
	if(pbn && pbn->barrier == 0)
	{
		if(pbn && pbn->bd != NULL)
		{
			*ptr = this_ptr->next;
			return pbn->bd;
		}
	}
	return NULL;
}

inline int pkt_buffer_isempty(packet_buffer_t* pbuf)
{
	return list_empty(&pbuf->buffer_head);
}
