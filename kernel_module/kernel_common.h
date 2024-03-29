#ifndef __KERNEL_COMMON_H__
#define __KERNEL_COMMON_H__

#include <linux/version.h>
#include <linux/etherdevice.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>

#include "ovs/ovs_func.h"
#include "util/packet_buffer.h"
#include "util/mem_dbg.h"

#include "../commom.h"

#if DEBUG==1
#define PRINT_DEBUG(str, ...)	do {printk(KERN_DEBUG "[%s]: " str, __func__, ##__VA_ARGS__);} while (0)
#else
#define PRINT_DEBUG(str, ...)	do {} while (0)
#endif

#if INFO==1
#define PRINT_INFO(str, ...)	do {net_info_ratelimited("[%s]: " str, __func__, ##__VA_ARGS__);} while (0)
#else
#define PRINT_INFO(str, ...)	do {} while (0)
#endif

#if NOERR==1
#define PRINT_ERROR(str, ...)	do {} while (0)
#else
#define PRINT_ERROR(str, ...)	do {net_err_ratelimited("[%s]: " str, __func__, ##__VA_ARGS__);} while (0)
#endif

extern struct host_info server;
extern struct host_info mirror;
struct other_args;

int pd_modify_ip_mac ( struct sk_buff* skb_mod );
void send_skbmod ( struct sk_buff *skb_mod, struct other_args* arg );
void print_skb(struct sk_buff *skb);
void print_packet_buffer_usage(packet_buffer_t* packet_buf);

#define CAUSE_BY_RMHOST 0
#define CAUSE_BY_MIRROR 1
#define CAUSE_BY_RETRAN 2

#endif
