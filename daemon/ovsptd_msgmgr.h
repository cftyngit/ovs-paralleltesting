#ifndef __OVSPTD_MSGMGR_H__
#define __OVSPTD_MSGMGR_H__

#include <thread>
#include <mutex>
#include <istream>
#include <algorithm>
#include <vector>

#include "ovsptd_nlmgr.h"
#include "ovsptd_buffer.h"

using std::istream;
using std::thread;
using std::mutex;
using std::try_lock;
using std::min;
using std::vector;

typedef int (*compare_func)(istream& target, istream& mirror);
struct compare_info;

class ovsptd_msgmgr
{
	int reg;
	int should_exit;
	all_compares compare_buffer;
	compare_func compare_function;
	thread msg_thread;
	mutex read_lock;
	static void thread_func(ovsptd_msgmgr* msgmgr);
	int setup_host(my_ip_type ip, unsigned char mac[6], UINT16 port, int host_type);
public:
	ovsptd_msgmgr(compare_func func)
		:reg(0), should_exit(0), compare_function(func)
	{}
	~ovsptd_msgmgr(){stop();}
	int start()
	{
		int ret = 0;
		read_lock.lock();
		nl_init();
		read_lock.unlock();
		if(ret == 0)
		{
			reg = 1;
			should_exit = 0;
			msg_thread = thread(thread_func, this);
		}
		return ret;
	}
	void stop()
	{
		should_exit = 1;
		if(msg_thread.joinable())
			msg_thread.join();
		read_lock.lock();
		int ret = nl_uninit();
		read_lock.unlock();
		if(ret == 0)
			reg = 0;
	}
	vector<compare_info> query_all_info() {return compare_buffer.query_all_compares();}
	int compare_by_info(compare_info info);
	int setup_target(my_ip_type ip, unsigned char mac[6], UINT16 port){return setup_host(ip, mac, port, HOST_TYPE_TARGET);}
	int setup_mirror(my_ip_type ip, unsigned char mac[6], UINT16 port){return setup_host(ip, mac, port, HOST_TYPE_MIRROR);}
};

#endif
