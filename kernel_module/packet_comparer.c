#include "packet_comparer.h"

int simple_comparer(char* data1, char* data2, size_t length)
{
	int result = memcmp(data1, data2, length);
	if(result)
	{
		int i = 0;
		size_t remain = length;
		printk("different:\n");
		for(i = 0; i < length; i+=16)
		{
			int j = 0;
			int print_len = min((size_t)16, remain);
			printk("%05u: ", i);
			for(j = 0; j < print_len; ++j)
			{
				printk("%02X", (unsigned char)data1[i+j]);
				if( (i+j) % 2 )
					printk(" ");
			}
			if(remain < 16)
			{
				int need_space = 40 - ((remain << 1) + (remain >> 1));
				int k = 0;
				for (k = 0; k < need_space; ++k)
					printk(" ");
			}

			printk("\t\t");
			for(j = 0; j < print_len; ++j)
			{
				printk("%02X", (unsigned char)data2[i+j]);
				if( (i+j) % 2 )
					printk(" ");
			}
			printk("\n");
			remain -= print_len;
		}
	}
	else
	{
		int i = 0;
		size_t remain = length;
		printk("the same:\n");
		for(i = 0; i < length; i+=16)
		{
			int j = 0;
			int print_len = min((size_t)16, remain);
			printk("%05u: ", i);
			for(j = 0; j < print_len; ++j)
			{
				printk("%02X", (unsigned char)data1[i+j]);
				if( (i+j) % 2 )
					printk(" ");
			}
			printk("\n");
			remain -= print_len;
		}

	}
    return result;
}

void del_buffer_node(struct buffer_node* bn)
{
    list_del(&bn->list);
    kfree(bn->payload.data);
    kfree(bn);
}

int do_compare(struct connection_info* con_info, struct compare_buffer* buffer1, struct compare_buffer* buffer2, compare_func compare)
{
    struct list_head *buf_head1 = &(buffer1->buffer_head), *buf_head2 = &(buffer2->buffer_head);
    int should_break = 10;
    if(list_empty(buf_head1) || list_empty(buf_head2))
        return -1;

    if(compare == NULL)
        compare = simple_comparer;

    if(NULL == buffer1->compare_head)
        buffer1->compare_head = list_entry(buf_head1->next, struct buffer_node, list);

    if(NULL == buffer2->compare_head)
        buffer2->compare_head = list_entry(buf_head2->next, struct buffer_node, list);
    
    while(should_break--)
    {
        struct buffer_node* compare_target1 = NULL;
        struct buffer_node* compare_target2 = NULL;

        if(buffer1->compare_head->payload.remain > 0)
            compare_target1 = buffer1->compare_head;
        else
        {
            struct buffer_node* next_item1 = buffer1->compare_head->list.next != buf_head1 ? list_entry(buffer1->compare_head->list.next, struct buffer_node, list) : NULL;
            if(next_item1 && next_item1->seq_num == buffer1->compare_head->seq_num_next)
            {
                compare_target1 = next_item1;
                del_buffer_node ( buffer1->compare_head );
                buffer1->compare_head = next_item1;
            }
            else
                break;
        }
        if(buffer2->compare_head->payload.remain > 0)
            compare_target2 = buffer2->compare_head;
        else
        {
            struct buffer_node* next_item2 = buffer2->compare_head->list.next != buf_head2 ? list_entry(buffer2->compare_head->list.next, struct buffer_node, list) : NULL;
            if(next_item2 && next_item2->seq_num == buffer2->compare_head->seq_num_next)
            {
                compare_target2 = next_item2;
                del_buffer_node ( buffer2->compare_head );
                buffer2->compare_head = next_item2;
            }
            else
                break;
        }
        if ( compare_target1 != NULL && compare_target2 != NULL )
        {
            unsigned char* cmp_data1 = compare_target1->payload.data + (compare_target1->payload.length - compare_target1->payload.remain);
            unsigned char* cmp_data2 = compare_target2->payload.data + (compare_target2->payload.length - compare_target2->payload.remain);
            size_t compare_size = min(compare_target1->payload.remain, compare_target2->payload.remain);
            if(compare_size > 0)
            {
                compare ( cmp_data1, cmp_data2, compare_size );
                compare_target1->payload.remain -= compare_size;
                compare_target2->payload.remain -= compare_size;
            }
            
            if(compare_target1->payload.remain == 0)
            {
                struct buffer_node* next_item1 = buffer1->compare_head->list.next != buf_head1 ? list_entry(buffer1->compare_head->list.next, struct buffer_node, list) : NULL;
                if(next_item1 && next_item1->payload.length == 0)
                {
                    buffer1->compare_head = NULL;
                    del_buffer_node(next_item1);
                    break;
                }
            }
            if(compare_target2->payload.remain == 0)
            {
                struct buffer_node* next_item2 = buffer2->compare_head->list.next != buf_head2 ? list_entry(buffer2->compare_head->list.next, struct buffer_node, list) : NULL;
                if(next_item2 && next_item2->payload.length == 0)
                {
                    buffer2->compare_head = NULL;
                    del_buffer_node(next_item2);
                    break;
                }
            }
            
        }
        else
            break;
    }
        return 0;
}

