#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/string.h>
#include <linux/skbuff.h>

#include "hook.h"
#include "ovs/ovs_func.h"
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
    request_module("openvswitch.ko");
    target = kallsyms_lookup_name(ovs_hook_sym_name);

    if(target == 0)
    {
		PRINT_ERROR("can't find kernel function: %s\n", ovs_hook_sym_name);
		return -1;
    }
	mem_dbg_start();
    init_packet_dispatcher();
    
    if(!netlink_init())
        PRINT_INFO("netlink init success\n");
    else
        PRINT_INFO("netlink init fail\n");

	if(0 > ovs_init_func())
		return -1;

	PRINT_INFO("[%s] %s (0x%lx)\n", __this_module.name, ovs_hook_sym_name, target);
	hijack_start((void*)target, ovs_hook_func);

    return 0;
}

static void __exit lkm_exit(void)
{
	hijack_stop((void*)target);
	netlink_release();
	connect_stat_cleanup(&conn_info_set);
	mem_dbg_finish();
}

module_init(lkm_init);
module_exit(lkm_exit);