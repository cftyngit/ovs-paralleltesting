#include <iostream>
#include <cstdio>
#include <vector>

#include "ovsptd_msgmgr.h"
#include "../commom.h"
#include "user_common.h"

using std::cerr;
using std::endl;
using std::cout;
using std::cin;

int null_compare(istream& target, istream& mirror)
{
	cout << "this compare method do nothing" <<endl;
	return 0;
}

int simple_compare(istream& target, istream& mirror)
{
	bool target_avail = true;
	bool mirror_avail = true;
	unsigned int cmp_count = 0;
	int retry_times = 0;
	while(1)
	{
		unsigned char byte_m;
		unsigned char byte_t;
		if(!target.rdbuf()->in_avail())
		{
			cout<<endl<<"target is finish"<<endl;
			target_avail = false;
		}
		if(!mirror.rdbuf()->in_avail())
		{
			cout<<endl<<"mirror is finish"<<endl;
			mirror_avail = false;
		}
		if(!(target_avail && mirror_avail))
		{
			if(++retry_times > 10)
				break;
			std::this_thread::sleep_for (std::chrono::milliseconds(500 * retry_times));
			target_avail = true;
			mirror_avail = true;
			continue;
		}
		retry_times = 0;
		if(!(cmp_count % 16))
			printf("%08X: ", cmp_count);

		target >> byte_t;
		mirror >> byte_m;
		if(byte_m == byte_t)
			printf("%02X    ", byte_t);
		else
			printf("%02X|%02X ", byte_t, byte_m);

		if(!(++cmp_count % 16))
			cout<<endl;
	}
	return 0;
}

typedef enum
{
	setup_mirror,
	setup_target,
	query_compares,
	do_compare,
	option_exit
}option;

int main()
{
	int exit = 0;
	ovsptd_msgmgr msgmgr(simple_compare);
	vector<compare_info> all_info;
	if(msgmgr.start() != 0)
	{
		cerr << "init fail" << endl;
		return -1;
	}
	while(!exit)
	{
		int opt;
		cout <<'('<<setup_mirror<<") setup mirror, ("<<setup_target<<") setup target, ("<<query_compares<<") query compares, ("<<do_compare<<") do compare ("
		<<option_exit<<") exit"<<endl;
		cin >> opt;
		switch(opt)
		{
		case setup_mirror:
		case setup_target:
		{
			my_ip_type ip;
			UINT16 port;
			unsigned char mac[6];
			cout << "input IP (XXX.XXX.XXX.XXX): ";
			scanf("%hhu.%hhu.%hhu.%hhu", &(ip.c[0]), &(ip.c[1]), &(ip.c[2]), &(ip.c[3]));
			cout << "input MAC (XX:XX:XX:XX:XX:XX): ";
			scanf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &(mac[0]), &(mac[1]), &(mac[2]), &(mac[3]), &(mac[4]), &(mac[5]));
			cout << "input phy port: ";
			scanf("%hd", &(port));
			if(SETUP_MIRROR == opt)
				msgmgr.setup_mirror(ip, mac, port);
			else
				msgmgr.setup_target(ip, mac, port);

			break;
		}
		case query_compares:
			all_info = msgmgr.query_all_info();
			for(unsigned int i = 0; i < all_info.size(); ++i)
			{
				my_ip_type ip = all_info[i].rmhost.ip;
				UINT16 port = all_info[i].rmhost.port_no;
				switch(all_info[i].proto)
				{
				case IPPROTO_TCP:
					cout<<"("<<i<<") "<<"TCP: "<<(int)ip.c[0]<<'.'<<(int)ip.c[1]<<'.'<<(int)ip.c[2]<<'.'<<(int)ip.c[3]<<':'<<port<<endl;
					break;
				case IPPROTO_UDP:
					cout<<"("<<i<<") "<<"UDP: "<<(int)ip.c[0]<<'.'<<(int)ip.c[1]<<'.'<<(int)ip.c[2]<<'.'<<(int)ip.c[3]<<':'<<port<<endl;
					break;
				}
			}
			break;
		case do_compare:
		{
			unsigned int cmp_i;
			cout << "compare index: ";
			cin >> cmp_i;
			if(cmp_i > all_info.size())
			{
				cout << "invalid index: "<< cmp_i <<endl;
				break;
			}
			else
				msgmgr.compare_by_info(all_info[cmp_i]);
			break;
		}
		case option_exit:
			exit = 1; 
			break;
		default:
			cout<<"unknow option!"<<endl;
			break;
		}
	}
	return 0;
}
