#ifndef __K2U_H__
#define __K2U_H__

#include <net/netlink.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/version.h>

#include "common.h"
#include "packet_dispatcher.h"

#define NLMSG_SETECHO 0x01
#define NLMSG_GETECHO 0x02
#define NLMSG_SETUP_MIRROR 0x10
#define NLMSG_SETUP_SERVER 0x11

#define NLNUM 24
/*
struct setup_host
{
    unsigned char   host_mac[6];
    union ip        ip_addr;
};
*/
int netlink_init(void);
void netlink_release(void);

#endif