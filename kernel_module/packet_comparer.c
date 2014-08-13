#include "packet_comparer.h"

int simple_comparer(char* data1, char* data2, size_t length)
{
    return memcmp(data1, data2, length);
}

void del_buffer_node(struct buffer_node* bn)
{
    list_del(&bn->list);
    kfree(bn->payload.data);
    kfree(bn);
}

int do_compare(struct connection_info* con_info, struct list_head* buffer1, struct list_head* buffer2, compare_func compare)
{
    struct list_head *iterator1, *iterator2;
    struct list_head *tmp1, *tmp2;
    int should_break = 0;
    if(list_empty(buffer1) || list_empty(buffer2))
        return -1;

    if(compare == NULL)
        compare = simple_comparer;

    while(!should_break)
    {
        struct buffer_node* compare_target1 = NULL;
        struct buffer_node* compare_target2 = NULL;
        /*
         * get one compare item from buffer 1
         */
        for(iterator1 = (buffer1)->next, tmp1 = iterator1->next; iterator1 != (buffer1); iterator1 = tmp1, tmp1 = iterator1->next)
        {
            struct buffer_node* this_item1 = list_entry(iterator1, struct buffer_node, list);
            struct buffer_node* next_item1 = iterator1->next != buffer1 ? list_entry(iterator1->next, struct buffer_node, list) : NULL;
            if(this_item1->payload.length == 0)
                del_buffer_node(this_item1);
            else
                compare_target1 = this_item1;

            if(next_item1 == NULL || this_item1->seq_num_next != next_item1->seq_num)
                should_break = 1;

            if(should_break == 1 || compare_target1 != NULL)
                break;
        }

        for ( iterator2 = ( buffer2 )->next, tmp2 = iterator2->next; iterator2 != ( buffer2 ); iterator2 = tmp2, tmp2 = iterator2->next )
        {
            struct buffer_node* this_item2 = list_entry ( iterator2, struct buffer_node, list );
            struct buffer_node* next_item2 = iterator2->next != buffer2 ? list_entry ( iterator2->next, struct buffer_node, list ) : NULL;
            if ( this_item2->payload.length == 0 )
                del_buffer_node ( this_item2 );
            else
                compare_target2 = this_item2;

            if ( next_item2 == NULL || this_item2->seq_num_next != next_item2->seq_num )
                should_break = 1;

            if ( should_break == 1 || compare_target2 != NULL )
                break;
        }
        printk("compare_target1: %p | compare_target2: %p\n", compare_target1, compare_target2);
        if ( compare_target1 != NULL && compare_target2 != NULL )
        {
            size_t compare_size = 0;
            unsigned char *cmp_data1, *cmp_data2;
            if (compare_target1->payload.remain < compare_target2->payload.remain)
            {
                cmp_data1 = compare_target1->payload.data + (compare_target1->payload.length - compare_target1->payload.remain);
                cmp_data2 = compare_target2->payload.data;
                compare_size = compare_target1->payload.remain;
            }
            else
            {
                cmp_data1 = compare_target1->payload.data;
                cmp_data2 = compare_target2->payload.data + (compare_target2->payload.length - compare_target2->payload.remain);
                compare_size = compare_target2->payload.remain;
            }
            if ( !compare ( cmp_data1, cmp_data2, compare_size ) )
            {
                //printk ( KERN_INFO "compare result: the same >>>> %s <<<<\n", compare_target1->payload.data );
                
            }
            else
            {
                //printk ( KERN_INFO "compare result: different %s <===> %s\n", compare_target1->payload.data, compare_target2->payload.data );
            }

            compare_target1->payload.remain -= compare_size;
            compare_target2->payload.remain -= compare_size;
            if(compare_target1->payload.remain == 0)
            {
                del_buffer_node ( compare_target1 );
                compare_target1 = NULL;
            }
            if(compare_target2->payload.remain == 0)
            {
                del_buffer_node ( compare_target2 );
                compare_target2 = NULL;
            }
        }
        else
            break;
    }
    return 0;
}