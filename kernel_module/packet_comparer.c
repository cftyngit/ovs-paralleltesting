#include "packet_comparer.h"

int simple_comparer(char* data1, char* data2, size_t length)
{
	int result = memcmp(data1, data2, length);
	if(result)
	{
		int i = 0;
		size_t remain = length;
		PRINT_INFO("different:\n");
		for(i = 0; i < length; i+=16)
		{
			int j = 0;
			int print_len = min((size_t)16, remain);
			PRINT_INFO("%05u: ", i);
			for(j = 0; j < print_len; ++j)
			{
				PRINT_INFO("%02X", (unsigned char)data1[i+j]);
				if( (i+j) % 2 )
					PRINT_INFO(" ");
			}
			if(remain < 16)
			{
				int need_space = 40 - ((remain << 1) + (remain >> 1));
				int k = 0;
				for (k = 0; k < need_space; ++k)
					PRINT_INFO(" ");
			}

			PRINT_INFO("\t\t");
			for(j = 0; j < print_len; ++j)
			{
				PRINT_INFO("%02X", (unsigned char)data2[i+j]);
				if( (i+j) % 2 )
					PRINT_INFO(" ");
			}
			PRINT_INFO("\n");
			remain -= print_len;
		}
	}
	else
	{
		int i = 0;
		size_t remain = length;
		PRINT_INFO("the same:\n");
		for(i = 0; i < length; i+=16)
		{
			int j = 0;
			int print_len = min((size_t)16, remain);
			PRINT_INFO("%05u: ", i);
			for(j = 0; j < print_len; ++j)
			{
				PRINT_INFO("%02X", (unsigned char)data1[i+j]);
				if( (i+j) % 2 )
					PRINT_INFO(" ");
			}
			PRINT_INFO("\n");
			remain -= print_len;
		}

	}
    return result;
}



int debug_comparer(char* data1, char* data2, size_t length)
{
	int result = memcmp(data1, data2, length);
	if(result)
		printk("[%s] %p comapre with %p, size: %zu is different\n", __func__, data1, data2, length);
	else
		printk("[%s] %p comapre with %p, size: %zu is the same\n", __func__, data1, data2, length);

	return result;
}

int do_compare(struct connection_info* con_info, struct compare_buffer* buffer1, struct compare_buffer* buffer2, compare_func compare)
{
    int should_break = INT_MAX;
    if(compare == NULL)
        compare = debug_comparer;
    
    while(should_break--)
    {
        struct data_node* compare_target1 = compare_buffer_getblock(buffer1);
        struct data_node* compare_target2 = compare_buffer_getblock(buffer2);

        if ( compare_target1 != NULL && compare_target2 != NULL )
        {
            unsigned char* cmp_data1 = compare_target1->data + (compare_target1->length - compare_target1->remain);
            unsigned char* cmp_data2 = compare_target2->data + (compare_target2->length - compare_target2->remain);
            size_t compare_size = min(compare_target1->remain, compare_target2->remain);
            if(compare_size > 0)
            {
                compare ( cmp_data1, cmp_data2, compare_size );
                compare_buffer_consume(compare_size, buffer1);
				compare_buffer_consume(compare_size, buffer2);
            }
        }
        else
            break;
    }
	return 0;
}

