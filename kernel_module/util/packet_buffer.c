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
    struct list_head *iterator, *tmp;
    struct pkt_buffer_node *pbn;
    if(list_empty(head))
        return 0;

    list_for_each_prev_safe(iterator, tmp, head)
    {
        pbn = list_entry(iterator, struct pkt_buffer_node, list);
        list_del(iterator);
        kfree(pbn->bd->p);
        kfree_skb(pbn->bd->skb);
        kfree(pbn->bd);
        kfree(pbn);
    }
    return 0;
}
