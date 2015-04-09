#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <linux/skbuff.h>

#include "hook.h"
#include "ovs_func.h"
#include "k2u.h"
#include "l4proto/tcp.h"

#include "packet_dispatcher.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("OVS parallel testing");
MODULE_AUTHOR("cftyn, <cftyn1@gmail.com>");

int send_to_user = 1;
module_param(send_to_user, int, S_IRUGO|S_IWUSR);

static unsigned long target;

static int __init lkm_init(void)
{
    char *sym_name = "ovs_dp_process_received_packet";
    request_module("openvswitch.ko");
    target = kallsyms_lookup_name(sym_name);

    if(target == 0)
    {
		PRINT_ERROR("can't find kernel function: %s\n", sym_name);
		return -1;
    }

    init_packet_dispatcher();
    if(0 > init_ovs_func())
        return -1;

    PRINT_INFO("[%s] %s (0x%lx)\n", __this_module.name, sym_name, target);
    hijack_start((void*)target, &ovs_dp_process_received_packet_hi);

    if(!netlink_init())
        PRINT_INFO("netlink init success\n");
    else
        PRINT_INFO("netlink init fail\n");

    return 0;
}

static void __exit lkm_exit(void)
{
    netlink_release();
    hijack_stop((void*)target);
}

module_init(lkm_init);
module_exit(lkm_exit);