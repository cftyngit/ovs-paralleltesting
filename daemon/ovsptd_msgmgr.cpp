#include "ovsptd_msgmgr.h"

void ovsptd_msgmgr::thread_func ( ovsptd_msgmgr* msgmgr )
{
	UINT16 type = 0;
	char data[NL_MAXPAYLOAD];
	int size = 0;

	while(!msgmgr->should_exit)
	{
		if(!msgmgr->read_lock.try_lock())
		{
			std::this_thread::sleep_for (std::chrono::milliseconds(1));
			continue;
		}
		size = recv_nl_message(&type, (void*)&data);
		if(size > 0 && type == NLMSG_DATA_SEND)
		{
			struct connection_info* inf = (struct connection_info*)data;
			const char* payload_data = (char*)(inf + 1);
			size_t payload_length = size - sizeof(connection_info);
			msgmgr->compare_buffer.add_data(string(payload_data, payload_length), *inf);
		}
		msgmgr->read_lock.unlock();
// 		std::this_thread::sleep_for (std::chrono::milliseconds(1));
	}
}

int ovsptd_msgmgr::compare_by_info ( compare_info info )
{
	compare_key key = {info.rmhost.ip, info.rmhost.port_no, info.proto};
	compare_obj* cmp_obj = compare_buffer.get_compare(key);

	if(!cmp_obj)
		return -1;

	return compare_function(cmp_obj->target_data(), cmp_obj->mirror_data());
}

int ovsptd_msgmgr::setup_host ( my_ip_type ip, unsigned char mac[6], uint16_t port, int host_type )
{
	struct setup_message setup_m;
// 	std::lock_guard<std::mutex> lck (read_lock);
	setup_m.host_type = host_type;
	setup_m.host.ip.i = ip.i;
	memmove(setup_m.host.mac, mac, 6);
	setup_m.host.port_no = port;
	nl_setup_host(setup_m);
	return 0;
}
