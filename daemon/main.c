#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <strings.h>
#include <string.h>
#include <netinet/in.h>
#include <signal.h>
#include <netinet/ip.h> /* superset of previous */
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include "network.h"
#include "../commom.h"

#ifdef NDEBUG
# define DEBUG_PRINT(fmt, ...)
# ifndef DAEMONIZE
#  define DAEMONIZE
# endif
#else
# ifdef DAEMONIZE
#  define DEBUG_PRINT(fmt, ...) syslog(LOG_DEBUG, fmt, ##__VA_ARGS__)
# else
#  define DEBUG_PRINT(fmt, ...) printf(fmt, ##__VA_ARGS__)
# endif
#endif

# ifdef DAEMONIZE
#  define MSG_PRINT(fmt, ...) syslog(LOG_INFO, fmt, ##__VA_ARGS__)
# else
#  define MSG_PRINT(fmt, ...) printf(fmt, ##__VA_ARGS__)
# endif

#define TCP_PORT 18591
#define NETLINK_TEST 24
/** 消息类型 **/
#define NLMSG_SETECHO 0x01
#define NLMSG_GETECHO 0x02
#define NLMSG_SETUP_MIRROR 0x10
#define NLMSG_SETUP_SERVER 0x11

#define HOST_SERVER 1
#define HOST_MIRROR 2

struct setup_message
{
    char host_type;
    char padding[3];
    struct host_info host;
};

int get_nl_socket();
int send_nl_message(int fd, int type, void* data, size_t length);
static void skeleton_daemon();

int main()
{
    int nl_sockfd = get_nl_socket();
    struct setup_message setup_m;
    int udp_sockfd = get_udp_sock(htonl(INADDR_ANY), TCP_PORT);

#ifdef DAEMONIZE
    skeleton_daemon();
#endif

    if(nl_sockfd < 0)
    {
        printf("get nl_sockfd error\n");
        return -1;
    }

    if(udp_sockfd < 0)
    {
        printf("get udp sockfd error\n");
        return -1;
    }

    while(1)
    {
        struct sockaddr_in thisSockIn;
        bzero (&thisSockIn, sizeof(struct sockaddr_in));
        socklen_t thisAddrSize = sizeof(thisSockIn);
        //int tmpSock = accept(tcp_sockfd, (struct sockaddr *)&thisSockIn, (socklen_t*)&thisAddrSize);
        int message_type = 0;
        int nbytes = 0;

        bzero(&setup_m, sizeof(setup_m));
        //read(tmpSock, &setup_m, sizeof(struct setup_message));
        nbytes = recvfrom(udp_sockfd, &setup_m, sizeof(setup_m), 0, (struct sockaddr *)&thisSockIn, (socklen_t*)&thisAddrSize);
        if (nbytes < 0)
        {
            perror ("could not read datagram!!");
            continue;
        }

        switch(setup_m.host_type)
        {
        case HOST_SERVER:
            MSG_PRINT("get server config ip = %hhu.%hhu.%hhu.%hhu\n", setup_m.host.ip.c[0],
                    setup_m.host.ip.c[1], setup_m.host.ip.c[2], setup_m.host.ip.c[3]);
            MSG_PRINT("get server config mac = %hhx:%hhx:%hhx:%hhx:%hhx:%x\n",
                        setup_m.host.mac[0], setup_m.host.mac[1], setup_m.host.mac[2],
                    setup_m.host.mac[3], setup_m.host.mac[4], setup_m.host.mac[5]);
            message_type = NLMSG_SETUP_SERVER;
            break;
        case HOST_MIRROR:
            MSG_PRINT("get mirror config ip = %hhu.%hhu.%hhu.%hhu\n", setup_m.host.ip.c[0],
                    setup_m.host.ip.c[1], setup_m.host.ip.c[2], setup_m.host.ip.c[3]);
            MSG_PRINT("get mirror config mac = %hhx:%hhx:%hhx:%hhx:%hhx:%x\n",
                        setup_m.host.mac[0], setup_m.host.mac[1], setup_m.host.mac[2],
                    setup_m.host.mac[3], setup_m.host.mac[4], setup_m.host.mac[5]);
            message_type = NLMSG_SETUP_MIRROR;
            break;
        }
        if( 0 > send_nl_message(nl_sockfd, message_type, &(setup_m.host), sizeof(struct host_info)))
        {
            MSG_PRINT("send fail\n");
            DEBUG_PRINT("fail message: %s\n", strerror(errno));
        }
        else
            MSG_PRINT("send success\n");
    }

    return 0;
}

int get_nl_socket()
{
    int sock = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_TEST);
    struct sockaddr_nl src_addr;
    bzero(&src_addr, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid();
    src_addr.nl_groups = 0;
    bind(sock, (struct sockaddr*)&src_addr, sizeof(src_addr));
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

    nlh = malloc(NLMSG_SPACE(length));

    nlh->nlmsg_len = NLMSG_SPACE(length); //保证对齐
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

static void skeleton_daemon()
{
    pid_t pid;

    /* Fork off the parent process */
    pid = fork();

    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);

    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* On success: The child process becomes session leader */
    if (setsid() < 0)
        exit(EXIT_FAILURE);

    /* Catch, ignore and handle signals */
    //TODO: Implement a working signal handler */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    /* Fork off for the second time*/
    pid = fork();

    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);

    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* Set new file permissions */
    umask(0);

    /* Change the working directory to the root directory */
    /* or another appropriated directory */
    chdir("/");

    /* Close all open file descriptors */
    /*int x;
    for (x = sysconf(_SC_OPEN_MAX); x>0; x--)
    {
        close (x);
    }*/

    /* Open the log file */
    openlog ("ovsp-netlinkd", LOG_PID, LOG_DAEMON);
}
