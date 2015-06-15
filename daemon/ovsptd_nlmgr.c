#include "ovsptd_nlmgr.h"
#include <stdio.h>
static int nl_sockfd;

int nl_init()
{
	int ret = 0;
	UINT16 ret_type = 0;
	char data[NL_MAXPAYLOAD];

	if(nl_sockfd)
		return 0;

	ret = get_nl_socket();
	if(0 > ret)
		return -1;

	if(0 > send_nl_message(ret, NLMSG_DAEMON_REG, NULL, 0))
		return -1;

	nl_sockfd = ret;
	while(0 >  recv_nl_message(&ret_type, (void*)&data))
	{
		printf("ret: %d\n", errno);
		if(errno == EAGAIN || errno == EWOULDBLOCK)
		{
			usleep(100);
			continue;
		}
		nl_sockfd = 0;
		return -1;
	}
	nl_sockfd = ret;
	return 0;
}

int nl_uninit()
{
	if(!nl_sockfd)
		return 0;

	if(0 > send_nl_message(nl_sockfd, NLMSG_DAEMON_UNREG, NULL, 0))
		return -1;
	close(nl_sockfd);
// 	while(0 > recv_nl_message(&ret_type, (void*)&data))
// 	{
// 		if(errno == EAGAIN || errno == EWOULDBLOCK)
// 		{
// 			usleep(100);
// 			continue;
// 		}
// 		return -1;
// 	}
	
	nl_sockfd = 0;
	return 0;
}

int nl_setup_host(struct setup_message setup_m)
{
	int message_type = 0;
	switch(setup_m.host_type)
	{
	case SETUP_TARGET:
		message_type = NLMSG_SETUP_SERVER;
		break;
	case SETUP_MIRROR:
		message_type = NLMSG_SETUP_MIRROR;
		break;
	default:
		return -1;
	}
	if( 0 > send_nl_message(nl_sockfd, message_type, &(setup_m.host), sizeof(struct host_info)))
		return -1;

	return 0;
}

int get_nl_socket()
{
	int sock = socket(PF_NETLINK, SOCK_DGRAM, NLNUM);
	if(0 > sock)
		return -1;

// 	int flags = fcntl(sock, F_GETFL, 0);
// 	fcntl(sock, F_SETFL, flags|O_NONBLOCK);
	struct sockaddr_nl src_addr;
	bzero(&src_addr, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = 0;
	if(0 > bind(sock, (struct sockaddr*)&src_addr, sizeof(src_addr)))
		return -2;

	return sock;
}

int send_nl_message(int fd, int type, void* data, size_t length)
{
    struct sockaddr_nl dst_addr;
    struct iovec iov;
    struct msghdr msg;
    struct nlmsghdr *nlh = NULL;

    bzero(&dst_addr, sizeof(dst_addr));
    dst_addr.nl_family = AF_NETLINK;
    dst_addr.nl_pid = 0; // 表示内核
    dst_addr.nl_groups = 0; //未指定接收多播组

    nlh = (struct nlmsghdr*)malloc(NLMSG_SPACE(length + sizeof(struct nlmsghdr)));

    nlh->nlmsg_len = NLMSG_SPACE(length + sizeof(struct nlmsghdr)); //保证对齐
    nlh->nlmsg_pid = getpid();  /* self pid */
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_type = type;

    memcpy(NLMSG_DATA(nlh), data, length);
    bzero(&msg, sizeof(msg));
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dst_addr;
    msg.msg_namelen = sizeof(dst_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    return sendmsg(fd, &msg, 0);
}

int recv_nl_message(UINT16* type, void* data)
{
	char buf[NL_MAXPAYLOAD + NLMSG_HDRLEN] = {0};
	int len;
	struct iovec iov = { buf, NLMSG_SPACE(sizeof(buf)) };
	struct sockaddr_nl sa;
	struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
	struct nlmsghdr *nh;

	if(0 == nl_sockfd)
		return -EBADF;

	len = recvmsg(nl_sockfd, &msg, 0);
	if(len < 0)
		return len;

	nh = (struct nlmsghdr *) buf;
	*type = nh->nlmsg_type;
	memmove(data, NLMSG_DATA(nh), nh->nlmsg_len);

	return nh->nlmsg_len - NLMSG_HDRLEN;
}