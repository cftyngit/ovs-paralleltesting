#include "queue_list.h"

struct queue_node
{
    void* data;
    struct queue_node* next;
};

struct queue_list
{
    struct queue_node* head;
    struct queue_node* tail;
    struct queue_list* next;
    unsigned int count;
};

int add_queue(struct queue_list_head *h)
{
    struct queue_list *new_node = kmalloc(sizeof(struct queue_list), GFP_KERNEL);

    new_node->count = 0;
    new_node->head = NULL;
    new_node->tail = NULL;
    new_node->next = NULL;

    if(0 == h->count)
        h->head = new_node;
    else
        h->tail->next = new_node;

    h->tail = new_node;
    h->count++;
    return 0;
}

static int __add_data__(struct queue_list *q, void *data)
{
    struct queue_node *new_node = kmalloc(sizeof(struct queue_node), GFP_KERNEL);

    new_node->data = data;
    new_node->next = NULL;

    if(0 == q->count)
        q->head = new_node;
    else
        q->tail->next = new_node;

    q->tail = new_node;
    q->count++;
    return 0;
}

int add_data(struct queue_list_head *h, void *data)
{
    if(0 == h->count)
        return -1;

    return __add_data__(h->tail, data);
}


void* get_data(struct queue_list_head *h)
{
    struct queue_list *ql = h->head;
    void* ret = NULL;
    struct queue_node* tmp = NULL;
    if(NULL == ql || 0 >= ql->count)
        return NULL;

    ret = ql->head->data;
    tmp = ql->head;
    ql->head = ql->head->next;
    kfree(tmp);
    ql->count--;
    return ret;
}

void* peek_data(struct queue_list_head *h)
{
    struct queue_list *ql = h->head;
    void* ret = NULL;

    if(NULL == ql || 0 >= ql->count)
        return NULL;

    ret = ql->head->data;
    return ret;
}

int del_queue(struct queue_list_head *h)
{
    unsigned int i = 0;
    struct queue_list* qtmp = h->head;
    if(0 == h->count)
        return -1;

    for(; i < h->head->count; ++i)
    {
        struct queue_node* tmp = h->head->head;
        h->head = h->head->next;
        kfree(tmp);
    }
    h->head=h->head->next;
    kfree(qtmp);
    h->count--;
    return 0;
}
