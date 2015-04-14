#ifndef __OVS_FUNC_H__
#define __OVS_FUNC_H__

#include <linux/kallsyms.h>
#include <linux/skbuff.h>

struct other_args;
extern const size_t sizeof_other_args;
extern const char* ovs_hook_sym_name;
extern void* ovs_hook_func;

int ovs_init_func(void);
int ovs_get_port_no(struct other_args* args);
void ovs_normal_output(struct sk_buff *skb, struct other_args *args);
void ovs_vport_output(struct sk_buff *skb, int port_no, struct other_args *args);

#endif
