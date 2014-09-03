#ifndef __L4PROTO_TCP_H__
#define __L4PROTO_TCP_H__

#include <linux/skbuff.h>
#include <net/tcp.h>
#include <asm-generic/unaligned.h>
#include <linux/kthread.h>
#include "../common.h"
#include "../connect_state.h"
#include "../util/packet_buffer.h"

#define FAKE_SEQ 4321
#define FAKE_TSVAL 123

int modify_tcp_header( struct sk_buff* skb_mod, union my_ip_type ip, u16 client_port );
int respond_tcp_syn_ack(const struct sk_buff* skb, const struct tcp_conn_info* tcp_info);
void setup_options(struct sk_buff* skb_mod, const struct tcp_conn_info* tcp_info);
u32 __get_timestamp(const struct sk_buff* skb, int off);
u8 get_window_scaling(const struct sk_buff* skb);
int tcp_playback_packet(union my_ip_type ip, u16 client_port, u8 cause);
int set_tcp_state ( struct sk_buff* skb_client, struct sk_buff* skb_mirror );
void slide_send_window(struct tcp_conn_info* this_tcp_info);
int ack_this_packet(const struct sk_buff* skb);

u32 seq_to_target(const u32 seq_mirror, const struct tcp_conn_info* tcp_info);
u32 seq_to_mirror(const u32 seq_target, const struct tcp_conn_info* tcp_info);
//u32 ackseq_to_target(const u32 ackseq_mirror, const struct tcp_conn_info* tcp_info);
//u32 ackseq_to_mirror(const u32 ackseq_target, const struct tcp_conn_info* tcp_info);

#define get_tsval(skb) \
    (__get_timestamp(skb, 0))
#define get_tsecr(skb) \
    (__get_timestamp(skb, 4))

#endif