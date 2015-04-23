#ifndef __K2U_H__
#define __K2U_H__

#include <net/netlink.h>
#include <net/sock.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>

#include "kernel_common.h"

int netlink_init(void);
void netlink_release(void);
/**
 * netlink_sendmes - send message to user space daemon
 * @type: netlink message type, defined in ../common.h
 * @data: data that want to send
 * @length: data length that want to send
 * @return bytes that acturally send
 */
int netlink_sendmes(UINT16 type, char* data, int length);
int pd_setup_hosts(struct host_info* set_server, struct host_info* set_mirror);
/**
 * netlink_send_data - send data and data info to user space daemon
 * @info: connection info of this data
 * @data: data that want to send
 * @length: data length that want to send
 * @return bytes that acturally send
 */
int netlink_send_data(struct connection_info* info, char* data, int length);
#endif
