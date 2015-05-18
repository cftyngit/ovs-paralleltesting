#include "packet_comparer.h"
int simple_comparer(char* data1, char* data2, size_t length)
{
	int result = memcmp(data1, data2, length);
	if(result)
	{
		int i = 0;
		size_t remain = length;
		PRINT_INFO("different: remain %zu\n", remain);
		for(i = 0; i < length; i+=16)
		{
			char print_buf[128] = {0};
			char tmp_buf[10];
			int j = 0;
			int print_len = min((size_t)16, remain);
			memset(print_buf, 0, sizeof(print_buf));
			sprintf(tmp_buf, "%05u: ", i);
			strcat(print_buf, tmp_buf);
			for(j = 0; j < print_len; ++j)
			{
				sprintf(tmp_buf, "%02X", (unsigned char)data1[i+j]);
				strcat(print_buf, tmp_buf);
				if( (i+j) % 2 )
				{
					sprintf(tmp_buf, " ");
					strcat(print_buf, tmp_buf);
				}
			}
			if(remain < 16)
			{
				int need_space = 40 - ((remain << 1) + (remain >> 1));
				int k = 0;
				for (k = 0; k < need_space; ++k)
				{
					sprintf(tmp_buf, " ");
					strcat(print_buf, tmp_buf);
				}
			}
			sprintf(tmp_buf, "\t\t");
			strcat(print_buf, tmp_buf);
			for(j = 0; j < print_len; ++j)
			{
				sprintf(tmp_buf, "%02X", (unsigned char)data2[i+j]);
				strcat(print_buf, tmp_buf);
				if( (i+j) % 2 )
				{
					sprintf(tmp_buf, " ");
					strcat(print_buf, tmp_buf);
				}
			}
			PRINT_INFO("%s\n", print_buf);
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
			char print_buf[64] = {0};
			char tmp_buf[10] = {0};
			int j = 0;
			int print_len = min((size_t)16, remain);
			memset(print_buf, 0, sizeof(print_buf));
			sprintf(tmp_buf, "%05u: ", i);
			strcat(print_buf, tmp_buf);
			for(j = 0; j < print_len; ++j)
			{
				sprintf(tmp_buf, "%02X", (unsigned char)data1[i+j]);
				strcat(print_buf, tmp_buf);
				if( (i+j) % 2 )
				{
					sprintf(tmp_buf, " ");
					strcat(print_buf, tmp_buf);
				}
			}
			PRINT_INFO("%s\n", print_buf);
			remain -= print_len;
		}

	}
    return result;
}

int debug_comparer(char* data1, char* data2, size_t length)
{
	int result = memcmp(data1, data2, length);
	if(result)
		PRINT_DEBUG("[%s] %p comapre with %p, size: %zu is different\n", __func__, data1, data2, length);
	else
		PRINT_DEBUG("[%s] %p comapre with %p, size: %zu is the same\n", __func__, data1, data2, length);

	return result;
}
extern int send_to_user;
int do_compare(struct connection_info* conn_info, struct compare_buffer* buffer1, struct compare_buffer* buffer2, compare_func compare)
{
	spinlock_t* lock;
	int should_break = INT_MAX;

	if(compare == NULL)
		compare = simple_comparer;

	switch(conn_info->proto)
	{
	case IPPROTO_UDP:
		lock = &(TCP_CONN_INFO(&conn_info_set, conn_info->ip, conn_info->port)->compare_lock);
		break;
	case IPPROTO_TCP:
		lock = &(UDP_CONN_INFO(&conn_info_set, conn_info->ip, conn_info->port)->compare_lock);
		break;
	default:
		return -1;
	}
	spin_lock_bh(lock);
	/*
	 * compare at kernel
	 */
	if(!send_to_user)
	{
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
	}
	else
	{
	/*
	 * send to user space
	 */
		struct compare_buffer* buffer = NULL;
		struct data_node* ct = NULL;
		if(HOST_TYPE_TARGET == conn_info->host_type)
			buffer = buffer1;
		else
			buffer = buffer2;

		while((should_break--) && (ct = compare_buffer_getblock(buffer)))
		{
			unsigned char* send_data = ct->data + (ct->length - ct->remain);
			int send_size = 0;
			send_size = netlink_send_data(conn_info, send_data, ct->remain);
			compare_buffer_consume(send_size, buffer);
		}
		
	}
	spin_unlock_bh(lock);
	return 0;
}

