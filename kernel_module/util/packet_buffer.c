#include "packet_buffer.h"

inline void pkt_buffer_init(packet_buffer_t* pbuf)
{
	pbuf->node_count = 0;
	pbuf->lastest_jiff = 0;
	INIT_LIST_HEAD(&(pbuf->buffer_head));
	spin_lock_init(&(pbuf->packet_lock));
}

int pkt_buffer_insert(struct pkt_buffer_node* pbn, packet_buffer_t* pbuf)
{
	struct list_head *head = NULL, *insert_point = NULL;
	struct pkt_buffer_node *iterator, *n;
	struct pkt_buffer_node* pbn_n = NULL;
	struct pkt_buffer_node* pbn_p = NULL;
	struct pkt_buffer_node* pbn_this = pbn;

	spin_lock_bh(&(pbuf->packet_lock));
	head = &pbuf->buffer_head;
	insert_point = head;
	/*
	 * currently, the least_seq in packet buffer is not used, it should be setup when playback packet
	 * 
	 * before this function called by pd_action_from_client in packet_dispatcher.c, pd_action_from_client will check 
	 * "!before(ntohl(tcp_header->ack_seq), seq_to_target(this_tcp_info->ackseq_last_playback, this_tcp_info))"
	 * to prevent insert ald packets
	 */
// 	if(after(pbuf->least_seq, pbn->seq_num))
// 	{
// 		PRINT_DEBUG("retrans? least_seq: %u, bn_seq_num: %u\n", pbuf->least_seq, bn->seq_num);
// 		goto free;
// 	}
	if(list_empty(head))
		goto insert;

	list_for_each_entry_safe_reverse(iterator, n, head, list)
	{
		insert_point = &iterator->list;
		if(!before(iterator->seq_num_next, pbn->seq_num_next))
			pbn_p = iterator;
		if(!after(iterator->seq_num, pbn->seq_num))
		{
			pbn_n = iterator;
			break;
		}
		if(pbn_n != iterator && pbn_p != iterator)
			pkt_buffer_delete(&iterator->list, pbuf);
	}
	if(head == &iterator->list)
		insert_point = head;

	if(pbn_n && pbn_p && !before(pbn_n->seq_num_next, pbn_p->seq_num))
	{
		PRINT_DEBUG("insert data is cover by buffer data\n");
		goto free;
	}
insert:
	PRINT_DEBUG("insert: (%u, %u)\n", pbn_this->seq_num, pbn_this->seq_num_next);
	list_add(&pbn_this->list, insert_point);
	goto exit;
free:
	dbg_kfree(pbn->bd->p);
	dbg_kfree_skb(pbn->bd->skb);
	dbg_kfree(pbn->bd);
	dbg_kfree(pbn);
exit:
	spin_unlock_bh(&(pbuf->packet_lock));
	return 0;
}

int pkt_buffer_insert2(struct pkt_buffer_node* pbn, packet_buffer_t* pbuf)
{
	struct list_head* head = NULL;
	struct list_head *iterator;
	struct list_head* prev = NULL;
	struct pkt_buffer_node* pbn_i = NULL;
	struct pkt_buffer_node* pbn_p = NULL;

	spin_lock_bh(&pbuf->packet_lock);
	head = &pbuf->buffer_head;
	iterator = head;
	if(list_empty(head))
		goto insert;

	list_for_each_prev(iterator, head)
	{
		struct pkt_buffer_node* tmp = list_entry(iterator, struct pkt_buffer_node, list);
		if(tmp->seq_num_next == pbn->seq_num || before(tmp->seq_num_next, pbn->seq_num))
			break;

		prev = iterator;
	}
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
	pbn_p = list_entry(prev, struct pkt_buffer_node, list);
	if(head == iterator)
		goto insert;
	pbn_i = list_entry(iterator, struct pkt_buffer_node, list);
	/**
	 * no spaces between inerator and prev
	 */
	if(pbn_i->seq_num_next == pbn_p->seq_num || after(pbn_i->seq_num_next, pbn_p->seq_num))
	{
		/**
		 * in this case prev should free and pbn should insert
		 * |--iterator--|
		 *              |---pbn---|
		 *          |--prev--|
		 */
		if(between(pbn->seq_num, pbn_p->seq_num, pbn_i->seq_num_next) && after(pbn->seq_num_next, pbn_p->seq_num_next))
		{
			PRINT_DEBUG("del prev: iter: (%u, %u), pbn: (%u, %u), prev: (%u, %u)\n", pbn_i->seq_num, pbn_i->seq_num_next, pbn->seq_num, pbn->seq_num_next, pbn_p->seq_num, pbn_p->seq_num_next);
			pkt_buffer_delete(prev, pbuf);
			pbn_p = NULL;
			goto insert;
		}
		else
			goto free;
	}
	/**
	 * pbn overlap with iterator or prev: free
	 */
	if(pbn_i->seq_num_next == pbn->seq_num_next || after(pbn_i->seq_num_next, pbn->seq_num_next))
		goto free;
	if((pbn_p->seq_num == pbn->seq_num || before(pbn_p->seq_num, pbn->seq_num))
		&& (pbn_p->seq_num_next == pbn->seq_num_next || after(pbn_p->seq_num_next, pbn->seq_num_next)))
		goto free;
insert:
	if(pbn_p && before(pbn_p->seq_num_next, pbn->seq_num_next))
	{
		PRINT_DEBUG("del prev: pbn: (%u, %u), prev: (%u, %u)\n", pbn->seq_num, pbn->seq_num_next, pbn_p->seq_num, pbn_p->seq_num_next);
		pkt_buffer_delete(prev, pbuf);
	}
	list_add(&pbn->list, iterator);
	pbuf->node_count++;
	goto out;
free:
	PRINT_DEBUG("free: iter: (%u, %u), pbn: (%u, %u), prev: (%u, %u)\n", pbn_i->seq_num, pbn_i->seq_num_next, pbn->seq_num, pbn->seq_num_next, pbn_p->seq_num, pbn_p->seq_num_next);
	dbg_kfree(pbn->bd->p);
	dbg_kfree_skb(pbn->bd->skb);
	dbg_kfree(pbn->bd);
	dbg_kfree(pbn);
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
	struct pkt_buffer_node* pbn;

	spin_lock_bh(&pbuf->packet_lock);
	head = &pbuf->buffer_head;
	if(list_empty(head))
		goto out;

	pos = (head)->next;
	pbn = list_entry(pos, struct pkt_buffer_node, list);
	if(pbn->barrier)
		goto out;

	bd = pbn->bd;
	list_del(pos);
	dbg_kfree(pbn);
	pbuf->node_count--;
out:
	spin_unlock_bh(&pbuf->packet_lock);
	return bd;
}

struct buf_data* pkt_buffer_peek_data(packet_buffer_t* pbuf)
{
	struct list_head* head = NULL;
// 	struct list_head* pos = NULL;
	struct buf_data *bd = NULL;
	struct pkt_buffer_node *pbn = NULL;
	struct list_head *iterator = NULL, *tmp = NULL;

	spin_lock_bh(&pbuf->packet_lock);
	head = &pbuf->buffer_head;
	if(list_empty(head))
		goto out;

// 	pos = (head)->next;
// 	if(list_entry(pos, struct pkt_buffer_node, list)->barrier)
// 		goto out;
//
// 	bd = list_entry(pos, struct pkt_buffer_node, list)->bd;
	list_for_each_safe(iterator, tmp, head)
	{
		if(iterator == NULL || iterator == LIST_POISON1 || iterator == LIST_POISON2)
			continue;

		pbn = list_entry(iterator, struct pkt_buffer_node, list);
		if(pbn->bd->should_delete)
			pkt_buffer_delete(iterator, pbuf);
		else
		{
			if(pbn->barrier == 0)
				bd =pbn->bd;

			goto out;
		}
	}
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
		if((ret = pkt_buffer_delete(iterator, pbuf)) < 0)
			continue;
	}
out:
	spin_unlock_bh(&pbuf->packet_lock);
	return ret;
}

struct buf_data* pkt_buffer_peek_data_from_ptr(packet_buffer_t* pbuf, struct list_head** ptr)
{
	struct list_head* head = NULL;
	struct pkt_buffer_node* pbn = NULL;
	struct list_head* this_ptr = *ptr;

	if(pbuf == NULL)
		return NULL;

	head = &pbuf->buffer_head;
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
			if(pbn->bd->should_delete)
			{
				PRINT_INFO("access a deleted packet\n");
				return NULL;
			}
			return pbn->bd;
		}
	}
	return NULL;
}

inline int pkt_buffer_isempty(packet_buffer_t* pbuf)
{
	return list_empty(&pbuf->buffer_head);
}

inline int pkt_buffer_delete(struct list_head *iterator, packet_buffer_t* pbuf)
{
	struct pkt_buffer_node *pbn = NULL;

	if(pbuf == NULL || iterator == NULL || iterator == LIST_POISON1 || iterator == LIST_POISON2 || iterator == &pbuf->buffer_head)
		return -1;

	pbn = list_entry(iterator, struct pkt_buffer_node, list);
	print_packet_buffer_usage(pbuf);

// 	if(pbn->bd->should_delete == 0 && try_to_del_timer_sync(&pbn->bd->timer) < 0)
// 	{
// 		pbn->bd->should_delete = 1;
// 		return -1;
// 	}
	if(timer_pending(&pbn->bd->timer))
	{
		if(try_to_del_timer_sync(&pbn->bd->timer) < 0)
		{
			pbn->bd->should_delete = 1;
			return -1;
		}
		else
			dbg_kfree((void*)pbn->bd->timer.data);
	}
	list_del(iterator);
	dbg_kfree(pbn->bd->p);
	dbg_kfree_skb(pbn->bd->skb);
	dbg_kfree(pbn->bd);
	dbg_kfree(pbn);
	pbuf->node_count--;

	return 0;
}
