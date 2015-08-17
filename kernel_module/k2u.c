#include "k2u.h"

static struct sock *netlink_sock;
static int daemon_pid;
static spinlock_t send_lock;

static void udp_receive(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    void *payload;
    struct sk_buff *out_skb;
    void *out_payload;
    struct nlmsghdr *out_nlh;
    int payload_len; // with padding, but ok for echo 
    //struct k2u_message data;
    nlh = nlmsg_hdr(skb);

	switch(nlh->nlmsg_type)
	{
	case NLMSG_DAEMON_UNREG:
		out_skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL); //分配足以存放默认大小的sk_buff
		if (!out_skb) 
			goto failure;

		if(!daemon_pid || daemon_pid == nlh->nlmsg_pid)
		{
			daemon_pid = 0;
			out_nlh = nlmsg_put(out_skb, 0, 0, NLMSG_SUCCESS, 0, 0); //填充协议头数据
			if (!out_nlh) 
				goto failure;

			PRINT_INFO("unreg daemon success\n");
		}
		else
		{
			out_nlh = nlmsg_put(out_skb, 0, 0, NLMSG_FAIL, 0, 0); //填充协议头数据
			if (!out_nlh) 
				goto failure;

			PRINT_ERROR("unreg daemon fail\n");
		}
		nlmsg_unicast(netlink_sock, out_skb, nlh->nlmsg_pid);
		break;
	case NLMSG_DAEMON_REG:
	{
		int ret = 0;
		if(daemon_pid)
		{
			PRINT_ERROR("reg daemon fail\n");
			ret = NLMSG_FAIL;
		}
		else
		{
			PRINT_INFO("reg daemon success\n");
			ret = NLMSG_SUCCESS;
		}
		daemon_pid = nlh->nlmsg_pid;
		out_skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL); //分配足以存放默认大小的sk_buff
		if (!out_skb) 
			goto failure;
		out_nlh = nlmsg_put(out_skb, 0, 0, ret, 0, 0); //填充协议头数据
		nlmsg_unicast(netlink_sock, out_skb, nlh->nlmsg_pid);
		break;
	}
	case NLMSG_SETECHO:
		break;
	case NLMSG_GETECHO:
		payload = nlmsg_data(nlh);
		payload_len = nlmsg_len(nlh);
		PRINT_INFO("payload_len = %d\n", payload_len);
		PRINT_INFO("Recievid: %s, From: %d\n", (char *)payload, nlh->nlmsg_pid);
		out_skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL); //分配足以存放默认大小的sk_buff
		if (!out_skb) goto failure;
			out_nlh = nlmsg_put(out_skb, 0, 0, NLMSG_SETECHO, payload_len, 0); //填充协议头数据
		if (!out_nlh) goto failure;
			out_payload = nlmsg_data(out_nlh);
		strcpy(out_payload, "[from kernel]:"); // 在响应中加入字符串，以示区别
		strcat(out_payload, payload);
		nlmsg_unicast(netlink_sock, out_skb, nlh->nlmsg_pid);
		break;
	case NLMSG_SETUP_MIRROR:
		payload = nlmsg_data(nlh);
		payload_len = nlmsg_len(nlh);
		PRINT_INFO("payload_len = %d\n", payload_len);
		PRINT_INFO("setup mirror IP = %hhu.%hhu.%hhu.%hhu\n", ((struct host_info *)payload)->ip.c[0], 
				((struct host_info *)payload)->ip.c[1], ((struct host_info *)payload)->ip.c[2], ((struct host_info *)payload)->ip.c[3]);
		PRINT_INFO("setup mirror MAC = %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", ((struct host_info *)payload)->mac[0], ((struct host_info *)payload)->mac[1],
				((struct host_info *)payload)->mac[2], ((struct host_info *)payload)->mac[3], 
				((struct host_info *)payload)->mac[4], ((struct host_info *)payload)->mac[5]);

		pd_setup_hosts(NULL, ((struct host_info *)payload));
		break;
	case NLMSG_SETUP_SERVER:
		payload = nlmsg_data(nlh);
		payload_len = nlmsg_len(nlh);
		PRINT_INFO("payload_len = %d\n", payload_len);
		PRINT_INFO("setup server IP = %hhu.%hhu.%hhu.%hhu\n", ((struct host_info *)payload)->ip.c[0], ((struct host_info *)payload)->ip.c[1],
				((struct host_info *)payload)->ip.c[2], ((struct host_info *)payload)->ip.c[3]);
		PRINT_INFO("setup server MAC = %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", ((struct host_info *)payload)->mac[0], ((struct host_info *)payload)->mac[1],
				((struct host_info *)payload)->mac[2], ((struct host_info *)payload)->mac[3], 
				((struct host_info *)payload)->mac[4], ((struct host_info *)payload)->mac[5]);

		pd_setup_hosts(((struct host_info *)payload), NULL);
		break;
	default:
		PRINT_INFO("Unknow msgtype recieved!\n");
	}
	return;
failure:
	PRINT_INFO(" failed in fun dataready!\n");
}

int netlink_init(void)
{
    #if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22))
    netlink_sock = netlink_kernel_create( NLNUM, 0, udp_receive, THIS_MODULE);
    #elif (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24))
    netlink_sock = netlink_kernel_create( NLNUM, 0, udp_receive, NULL, THIS_MODULE);
    #elif(LINUX_VERSION_CODE  < KERNEL_VERSION(3,6,0))
    netlink_sock = netlink_kernel_create(&init_net, NLNUM, 0, udp_receive, NULL, THIS_MODULE);
    #else
    {
        struct netlink_kernel_cfg cfg ={
            .input = udp_receive,
        };
        #if(LINUX_VERSION_CODE  < KERNEL_VERSION(3,7,0))
        netlink_sock = netlink_kernel_create(&init_net, NLNUM,THIS_MODULE, &cfg);
        #else
        netlink_sock = netlink_kernel_create(&init_net, NLNUM, &cfg);

        #endif
    }
    #endif
    spin_lock_init(&(send_lock));
    return netlink_sock ? 0 : -1;
}

void netlink_release(void)
{
    if(netlink_sock)
        sock_release(netlink_sock->sk_socket);
    PRINT_INFO("netlink driver remove successfully\n");
}

int pd_setup_hosts(struct host_info* set_server, struct host_info* set_mirror)
{
    //int i = 0;
    //for(i = 0; i < MAX_TCP_TABLE; ++i)
    {
        /*while(tcp_info_table[i].packet_buffer.count > 0)
            del_queue(&(tcp_info_table[i].packet_buffer));

        memset(&(tcp_info_table[i]), 0,sizeof(struct tcp_seq_info));*/
    }
    /*while(udp_buffer.count > 0)
        del_queue(&(udp_buffer));*/

    PRINT_INFO("old server ip = %d\n", server.ip.i);
    PRINT_INFO("old mirror ip = %d\n", mirror.ip.i);
    if(set_server != NULL)
    {
		server.port_no = set_server->port_no;
        server.ip.i = set_server->ip.i;
        memcpy(server.mac, set_server->mac, 6);
        PRINT_INFO("set server ip = %hhu.%hhu.%hhu.%hhu\n", server.ip.c[0], server.ip.c[1], server.ip.c[2], server.ip.c[3]);
        PRINT_INFO("set server MAC = %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", server.mac[0], server.mac[1], server.mac[2], server.mac[3], server.mac[4], server.mac[5]);
    }
    if(set_mirror != NULL)
    {
		mirror.port_no = set_mirror->port_no;
        mirror.ip.i = set_mirror->ip.i;
        memcpy(mirror.mac, set_mirror->mac, 6);
        PRINT_INFO("set mirror ip = %hhu.%hhu.%hhu.%hhu\n", mirror.ip.c[0], mirror.ip.c[1], mirror.ip.c[2], mirror.ip.c[3]);
        PRINT_INFO("set mirror MAC = %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", mirror.mac[0], mirror.mac[1], mirror.mac[2], mirror.mac[3], mirror.mac[4], mirror.mac[5]);
    }
    return 0;
}

int netlink_sendmes(UINT16 type, char* data, int length)
{
	int should_break = INT_MAX;
	struct nlmsghdr *out_nlh;
	char *out_payload;
	int remain = length;
	int send_size = 0;
	spin_lock_bh(&(send_lock));
	do
	{
		struct sk_buff *out_skb = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL); //分配足以存放默认大小的sk_buff;
		int send_block = min((unsigned long)remain, NL_MAXPAYLOAD);
		if (!out_skb)
		{
			PRINT_ERROR("[%s] nlmsg_new fail\n", __func__);
			goto failure;
		}
		out_nlh = nlmsg_put(out_skb, 0, 0, type, send_block, 0); //填充协议头数据
		if (!out_nlh) 
		{
			PRINT_ERROR("[%s] nlmsg_put fail at\n", __func__);
			goto failure;
		}
		out_payload = nlmsg_data(out_nlh);
		if(0 < remain)
			memmove(out_payload, data + (length - remain), send_block);

		nlmsg_unicast(netlink_sock, out_skb, daemon_pid);
// 		PRINT_DEBUG("[%s] send block: %d\n", __func__, send_block);
// 		PRINT_DEBUG("[%s] remain: %d\n", __func__, remain);
		remain -= send_block;
		send_size += send_block;
	}while(0 < remain && should_break--);
	spin_unlock_bh(&(send_lock));
	return send_size;

failure:
	spin_unlock_bh(&(send_lock));
	return -1;
}

int netlink_send_data(struct connection_info* info, char* data, int length)
{
	const int data_capacity = NL_MAXPAYLOAD - sizeof(struct connection_info);
	int should_break = INT_MAX;
	int remain = length;
	int send_size = 0;
	char* buffer = dbg_kmalloc(NL_MAXPAYLOAD, GFP_KERNEL); //NL_MAXPAYLOAD is too large to alloc in stack
	char* data_begin = buffer + sizeof(struct connection_info);

	if(!buffer)
		return -1;

	memmove(buffer, info, sizeof(struct connection_info));
	while(remain > 0 && should_break--)
	{
		int send_block = min(data_capacity, remain);
		int actual_send = 0;
		PRINT_DEBUG("send block: %d to host: %d\n", send_block, info->host_type);
// 		PRINT_DEBUG("[%s] remain: %d\n", __func__, remain);
		memmove(data_begin, data + (length - remain), send_block);
		actual_send = netlink_sendmes(NLMSG_DATA_SEND, buffer, send_block + sizeof(struct connection_info));
		if(actual_send < 0)
			break;

		if(actual_send > sizeof(struct connection_info))
		{
			remain -= (actual_send - sizeof(struct connection_info));
			send_size += (actual_send - sizeof(struct connection_info));
		}
	}
	dbg_kfree(buffer);
	return send_size;
}