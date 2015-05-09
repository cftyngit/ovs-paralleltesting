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

	spin_lock(&pbuf->packet_lock);
	head = &pbuf->buffer_head;
	if(list_empty(head))
	{
		list_add(&pbn->list, head);
		goto out;
	}

	list_for_each_prev(iterator, head)
	{
		if(list_entry(iterator, struct pkt_buffer_node, list)->seq_num_next <= pbn->seq_num)
			break;

		prev = iterator;
	}
	if(!prev || pbn->seq_num_next <= list_entry(prev, struct pkt_buffer_node, list)->seq_num)
		list_add(&pbn->list, iterator);
	else
		printk("[%s] prev: %p, seq_next: %u, ite_seq_next: %u\n", __func__, prev, pbn->seq_num_next, list_entry(prev, struct pkt_buffer_node, list)->seq_num);
out:
	spin_unlock(&pbuf->packet_lock);
	return 0;
}

struct buf_data* pkt_buffer_get_data(packet_buffer_t* pbuf)
{
	struct list_head* head = NULL;
	struct list_head* pos = NULL;
	struct buf_data *bd = NULL;

	spin_lock(&pbuf->packet_lock);
	head = &pbuf->buffer_head;
	if(list_empty(head))
		return NULL;

	pos = (head)->next;
	if(list_entry(pos, struct pkt_buffer_node, list)->barrier)
		return NULL;

	bd = list_entry(pos, struct pkt_buffer_node, list)->bd;
	list_del(pos);
	spin_unlock(&pbuf->packet_lock);
	return bd;
}

struct buf_data* pkt_buffer_peek_data(packet_buffer_t* pbuf)
{
	struct list_head* head = NULL;
	struct list_head* pos = NULL;
	struct buf_data *bd = NULL;

	spin_lock(&pbuf->packet_lock);
	head = &pbuf->buffer_head;
	if(list_empty(head))
		goto out;

	pos = (head)->next;
	if(list_entry(pos, struct pkt_buffer_node, list)->barrier)
		goto out;

	bd = list_entry(pos, struct pkt_buffer_node, list)->bd;
out:
	spin_unlock(&pbuf->packet_lock);
	return bd;
}

int pkt_buffer_barrier_add(packet_buffer_t* pbuf)
{
	struct list_head* head = NULL;
	struct list_head* pos = NULL;
	struct pkt_buffer_node* pbn = NULL;
	int ret = -1;

	spin_lock(&pbuf->packet_lock);
	head = &pbuf->buffer_head;
	if(list_empty(head))
		goto out;

	pos = (head)->next;
	pbn = list_entry(pos, struct pkt_buffer_node, list);
	ret = ++pbn->barrier;
out:
	spin_unlock(&pbuf->packet_lock);
	return ret;
}

int pkt_buffer_barrier_remove(packet_buffer_t* pbuf)
{
	struct list_head* head = NULL;
	struct list_head* pos = NULL;
	struct pkt_buffer_node* pbn = NULL;
	int ret = -1;

	spin_lock(&pbuf->packet_lock);
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
	spin_unlock(&pbuf->packet_lock);
	return ret;    
}

int pkt_buffer_cleanup(packet_buffer_t* pbuf)
{
	struct list_head* head = NULL;
	struct list_head *iterator = NULL, *tmp = NULL;
	struct pkt_buffer_node *pbn = NULL;
	int ret = 0, ret2 = 0;

	if(!spin_trylock(&pbuf->packet_lock))
		return -1;

	head = &pbuf->buffer_head;
	if(list_empty(head))
		goto out;

	list_for_each_safe(iterator, tmp, head)
	{
		if(iterator == NULL || iterator == LIST_POISON1 || iterator == LIST_POISON2)
			continue;
        
		pbn = list_entry(iterator, struct pkt_buffer_node, list);
		
		ret2 = timer_pending(&pbn->bd->timer);
		ret = try_to_del_timer_sync(&pbn->bd->timer);
		printk(KERN_EMERG "[%s] bd: %p, pending: %d, try_del: %d\n", __func__, pbn->bd, ret2, ret);
		if(ret < 0)
			goto out;

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
	spin_unlock(&pbuf->packet_lock);
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
//			struct buf_data* ret_bd = kmalloc(sizeof(struct buf_data), GFP_ATOMIC);
//			memmove(ret_bd, pbn->bd, sizeof(struct buf_data));
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
