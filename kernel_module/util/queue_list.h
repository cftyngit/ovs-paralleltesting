#ifndef QUEUE_LIST_H
#define QUEUE_LIST_H

#include <linux/slab.h>
#include <linux/slub_def.h>

struct queue_list_head
{
    struct queue_list* head;
    struct queue_list* tail;
    unsigned int count;
};

int add_queue(struct queue_list_head* h);
int add_data(struct queue_list_head* h, void* data);
int del_queue(struct queue_list_head* h);

void* get_data(struct queue_list_head* h);
void* peek_data(struct queue_list_head* h);

#define clean_queue_list(h) \
do  \
{   \
    while((h)->count) \
        del_queue(h);   \
}while(0)

#define QUEUE_LIST_INIT \
{ \
    .count = 0, \
}

#endif // QUEUE_LIST_H
