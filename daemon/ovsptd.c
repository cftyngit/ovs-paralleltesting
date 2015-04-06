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
#include "ovsptd_nlmgr.h"
#include "../commom.h"

#define TCP_PORT 18591

#define HOST_SERVER 1
#define HOST_MIRROR 2

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
