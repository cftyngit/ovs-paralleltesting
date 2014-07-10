#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <linux/skbuff.h>

#include "hook.h"
#include "ovs_func.h"
#include "k2u.h"

#include "packet_dispatcher.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("OVS parallel testing");
MODULE_AUTHOR("cftyn");

static unsigned long target;

static int __init lkm_init(void)
{
    char *sym_name = "ovs_dp_process_received_packet";
    unsigned long sym_addr = 0;
    request_module("openvswitch.ko");
    sym_addr = kallsyms_lookup_name(sym_name);
    //char filename[256];
	if(0 > init_ovs_func())
		return -1;

    target = sym_addr;
    if(sym_addr == 0)
    {
		printk(KERN_INFO "can't find kernel function: %s\n", sym_name);
		return 0;
    }
    //strncpy(filename, (char *)sym_addr, 255);

    printk(KERN_INFO "[%s] %s (0x%lx)\n", __this_module.name, sym_name, sym_addr);
    hijack_start((void*)sym_addr, &ovs_dp_process_received_packet_hi);
    if(!netlink_init())
        printk(KERN_INFO "netlink init success\n");
    else
        printk(KERN_INFO "netlink init fail\n");

    init_tcp_state();
    return 0;
}

static void __exit lkm_exit(void)
{
    netlink_release();
    hijack_stop((void*)target);
}

module_init(lkm_init);
module_exit(lkm_exit);