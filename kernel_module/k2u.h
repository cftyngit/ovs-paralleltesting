#ifndef __K2U_H__
#define __K2U_H__

#include <net/netlink.h>
#include <net/sock.h>
#include <linux/skbuff.h>

#include "kernel_common.h"
/*
struct setup_host
{
    unsigned char   host_mac[6];
    union ip        ip_addr;
};
*/
int netlink_init(void);
void netlink_release(void);

int pd_setup_hosts(struct host_info* set_server, struct host_info* set_mirror);
#endif
