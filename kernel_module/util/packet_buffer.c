#include "packet_buffer.h"

int pkt_buffer_insert(struct pkt_buffer_node* pbn, struct list_head* head)
{
    struct list_head *iterator;
    struct list_head* prev = NULL;

    if(list_empty(head))
    {
        list_add(&pbn->list, head);
        return 0;
    }

    list_for_each_prev(iterator, head)
    {
        if(list_entry(iterator, struct pkt_buffer_node, list)->seq_num_next <= pbn->seq_num)
            break;

        prev = iterator;
    }
    if(!prev || pbn->seq_num_next < list_entry(prev, struct pkt_buffer_node, list)->seq_num)
        list_add(&pbn->list, iterator);
    else
        printk("[%s] prev: %p, seq_next: %u, ite_seq_next: %u\n", __func__, prev, pbn->seq_num_next, list_entry(prev, struct pkt_buffer_node, list)->seq_num);

    return 0;
}

struct buf_data* pkt_buffer_get_data(struct list_head* head)
{
    struct list_head* pos = NULL;
    struct buf_data *bd = NULL;
    if(list_empty(head))
        return NULL;

    pos = (head)->next;
    if(list_entry(pos, struct pkt_buffer_node, list)->barrier)
        return NULL;

    bd = list_entry(pos, struct pkt_buffer_node, list)->bd;
    list_del(pos);
    return bd;
}

struct buf_data* pkt_buffer_peek_data(struct list_head* head)
{
    struct list_head* pos = NULL;
    struct buf_data *bd = NULL;
    if(list_empty(head))
        return NULL;

    pos = (head)->next;
    if(list_entry(pos, struct pkt_buffer_node, list)->barrier)
        return NULL;

    bd = list_entry(pos, struct pkt_buffer_node, list)->bd;
    return bd;
}

int pkt_buffer_barrier_add(struct list_head* head)
{
    struct list_head* pos = NULL;
    struct pkt_buffer_node* pbn = NULL;
    if(list_empty(head))
        return -1;

    pos = (head)->next;
    pbn = list_entry(pos, struct pkt_buffer_node, list);
    pbn->barrier++;

    return pbn->barrier;
}

int pkt_buffer_barrier_remove(struct list_head* head)
{
    struct list_head* pos = NULL;
    struct pkt_buffer_node* pbn = NULL;
    if(list_empty(head))
        return -1;

    pos = (head)->next;
    pbn = list_entry(pos, struct pkt_buffer_node, list);
    if(pbn->barrier)
        pbn->barrier--;

    return pbn->barrier;    
}

int pkt_buffer_cleanup(struct list_head* head)
{
    struct list_head *iterator = NULL, *tmp = NULL;
    struct pkt_buffer_node *pbn = NULL;
    if(list_empty(head))
        return 0;

    list_for_each_safe(iterator, tmp, head)
    {
        if(iterator == NULL || iterator == LIST_POISON1 || iterator == LIST_POISON2)
            continue;

        list_del(iterator);
        pbn = list_entry(iterator, struct pkt_buffer_node, list);
        kfree(pbn->bd->p);
        kfree_skb(pbn->bd->skb);
        kfree(pbn->bd);
        kfree(pbn);
    }
    return 0;
}

struct buf_data* pkt_buffer_peek_data_from_ptr(struct list_head* head, struct list_head** ptr)
{
    struct list_head* this_ptr = *ptr;
    if(this_ptr != NULL && this_ptr->next != head && this_ptr->next != LIST_POISON1 && this_ptr->next != LIST_POISON2
        && list_entry(this_ptr->next, struct pkt_buffer_node, list)->barrier == 0)
    {
        *ptr = this_ptr->next;
        return list_entry(this_ptr->next, struct pkt_buffer_node, list)->bd;
    }
    return NULL;
}
