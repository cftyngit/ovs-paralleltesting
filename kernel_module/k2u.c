#include "k2u.h"

static struct sock *netlink_sock;

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
    case NLMSG_SETECHO:
        break;
    case NLMSG_GETECHO:
        payload = nlmsg_data(nlh);
        payload_len = nlmsg_len(nlh);
        printk(KERN_INFO "payload_len = %d\n", payload_len);
        printk(KERN_INFO "Recievid: %s, From: %d\n", (char *)payload, nlh->nlmsg_pid);
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
        printk(KERN_INFO "payload_len = %d\n", payload_len);
        printk(KERN_INFO "setup mirror IP = %hhu.%hhu.%hhu.%hhu\n", ((struct host_info *)payload)->ip.c[0], ((struct host_info *)payload)->ip.c[1],
               ((struct host_info *)payload)->ip.c[2], ((struct host_info *)payload)->ip.c[3]);
        printk(KERN_INFO "setup mirror MAC = %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", ((struct host_info *)payload)->mac[0], ((struct host_info *)payload)->mac[1],
               ((struct host_info *)payload)->mac[2], ((struct host_info *)payload)->mac[3], 
               ((struct host_info *)payload)->mac[4], ((struct host_info *)payload)->mac[5]);

        pd_setup_hosts(NULL, ((struct host_info *)payload));
        break;
    case NLMSG_SETUP_SERVER:
        payload = nlmsg_data(nlh);
        payload_len = nlmsg_len(nlh);
        printk(KERN_INFO "payload_len = %d\n", payload_len);
        printk(KERN_INFO "setup server IP = %hhu.%hhu.%hhu.%hhu\n", ((struct host_info *)payload)->ip.c[0], ((struct host_info *)payload)->ip.c[1],
               ((struct host_info *)payload)->ip.c[2], ((struct host_info *)payload)->ip.c[3]);
        printk(KERN_INFO "setup server MAC = %hhx:%hhx:%hhx:%hhx:%hhx:%hhx\n", ((struct host_info *)payload)->mac[0], ((struct host_info *)payload)->mac[1],
               ((struct host_info *)payload)->mac[2], ((struct host_info *)payload)->mac[3], 
               ((struct host_info *)payload)->mac[4], ((struct host_info *)payload)->mac[5]);

        pd_setup_hosts(((struct host_info *)payload), NULL);
        break;
    default:
        printk(KERN_INFO "Unknow msgtype recieved!\n");
    }
    return;
failure:
    printk(KERN_INFO " failed in fun dataready!\n");
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
    //struct netlink_kernel_cfg cfg = {.input = udp_receive, };
    //netlink_sock = netlink_kernel_create(&init_net, 24, &cfg);
    return netlink_sock ? 0 : -1;
}

void netlink_release(void)
{
    if(netlink_sock)
        sock_release(netlink_sock->sk_socket);
    printk("netlink driver remove successfully\n");
}
