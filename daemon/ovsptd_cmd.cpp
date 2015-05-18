#include <iostream>
#include <cstdlib>
#include <cstdio>
#include <map>
#include <string>

#include "ovsptd_nlmgr.h"
#include "../commom.h"

using std::map;
using std::cerr;
using std::endl;
using std::cout;
using std::cin;
using std::pair;
using std::string;

map<connection_info, pair<string, string> > cmp_buffer;

void fnExit (void)
{
	nl_uninit();
}
int main_menu();
int setup_host(int host_type);
int receive_packet();

int main()
{
	atexit(fnExit);
	if (nl_init() < 0)
	{
		cerr << "init netlink fail " << endl;
		return -1;
	}
	for(int option = main_menu(); option > 0; option = main_menu())
	{
		struct setup_message setup_m;
		char data[MAX_ECHO + 1];
		switch(option)
		{
		case SETUP_MIRROR:
		case SETUP_TARGET:
			cout << "input IP (XXX.XXX.XXX.XXX): ";
			scanf("%hhu.%hhu.%hhu.%hhu", &(setup_m.host.ip.c[0]), &(setup_m.host.ip.c[1]), &(setup_m.host.ip.c[2]), &(setup_m.host.ip.c[3]));
			cout << "input MAC (XX:XX:XX:XX:XX:XX): ";
			scanf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &(setup_m.host.mac[0]), &(setup_m.host.mac[1]), &(setup_m.host.mac[2]), 
				  &(setup_m.host.mac[3]), &(setup_m.host.mac[4]), &(setup_m.host.mac[5]));
			cout << "input phy port: ";
			scanf("%hd", &(setup_m.host.port_no));
			if(SETUP_MIRROR == option)
				setup_m.host_type = HOST_TYPE_MIRROR;
			else
				setup_m.host_type = HOST_TYPE_TARGET;

			nl_setup_host(setup_m);
			break;
		case ECHO:
			cout << "input echo data: ";
			scanf("%"XSTR(MAX_ECHO)"s", data);
			break;
		case RECV_PACKET:
			receive_packet();
			break;
		}
	}
}

int main_menu()
{
	unsigned int option = 0;
	while(true)
	{
		cout <<'('<<SETUP_MIRROR<<") setup target, ("<<SETUP_TARGET<<") setup mirror, ("<<ECHO<<") echo, ("<<RECV_PACKET<<") recv packet" <<endl;
		cin >> option;
		switch(option)
		{
		case SETUP_MIRROR:
		case SETUP_TARGET:
		case ECHO:
		case RECV_PACKET:
			return option;
		default:
			if(cin.eof())
				goto exit;
			else
				cerr << "unknow option" << endl;
		}
	}
exit:
	return 0;
}

int receive_packet()
{
	UINT16 type = 0;
	char* data;
	int size = 0;
	while(size = recv_nl_message(&type, (void**)&data))
	{
		printf("receive mes type: %x, length: %d\n", type, size);
		if(type == NLMSG_DATA_SEND)
		{
			struct connection_info* inf = (struct connection_info*)data;
			connection_info inf_index = {inf->ip, inf->port, inf->proto, 0};
			printf("host type: %d\n", inf->host_type);
			printf("IP: %hhu.%hhu.%hhu.%hhu:%hu\n", inf->ip.c[0], 
				inf->ip.c[1], inf->ip.c[2], inf->ip.c[3], inf->port);

			if(cmp_buffer.find(inf_index) == cmp_buffer.end())
			{
				string target;
				string mirror;
				switch(inf->host_type)
				{
				case HOST_TYPE_TARGET:
					
					break;
				case HOST_TYPE_MIRROR:
					break;
				default:
					continue;
				}
				pair<string, string> buffer(target, mirror);
				
			}
		}
	}
	return 0;
}