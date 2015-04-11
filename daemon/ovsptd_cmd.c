#include <stdlib.h>
#include <stdio.h>

#include "ovsptd_nlmgr.h"
#include "../commom.h"

#define TCP_PORT 18591

#define HOST_TARGET 1
#define HOST_MIRROR 2

#define XSTR(A) STR(A)
#define STR(A) #A
#define MAX_ECHO 1000

int main()
{
	if(nl_init() < 0)
	{
		printf("netlink init error\n");
		return -1;
	}
	while(1)
	{
		int option = 0;
		printf("(1) setup target, (2) setup mirror, (3) echo, (4) recv packet\n");
		scanf("%d", &option);
		switch(option)
		{
		case 1:
		{
			struct setup_message setup_m;
			char ip[4];
			char mac[6];
			short port = 0;
			printf("input IP (XXX.XXX.XXX.XXX): ");
			scanf("%hhu.%hhu.%hhu.%hhu", &ip[0], &ip[1], &ip[2], &ip[3]);
			printf("input MAC (XX:XX:XX:XX:XX:XX): ");
			scanf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
			printf("input phy port: ");
			scanf("%hd", &port);
			setup_m.host_type = HOST_TARGET;
			setup_m.host.ip.c[0] = ip[0];
			setup_m.host.ip.c[1] = ip[1];
			setup_m.host.ip.c[2] = ip[2];
			setup_m.host.ip.c[3] = ip[3];
			setup_m.host.mac[0] = mac[0];
			setup_m.host.mac[1] = mac[1];
			setup_m.host.mac[2] = mac[2];
			setup_m.host.mac[3] = mac[3];
			setup_m.host.mac[4] = mac[4];
			setup_m.host.mac[5] = mac[5];
			setup_m.host.port_no = port;
			nl_setup_host(setup_m);
			break;
		}
		case 2:
		{
			struct setup_message setup_m;
			char ip[4];
			char mac[6];
			short port = 0;
			printf("input IP (XXX.XXX.XXX.XXX): ");
			scanf("%hhu.%hhu.%hhu.%hhu", &ip[0], &ip[1], &ip[2], &ip[3]);
			printf("input MAC (XX:XX:XX:XX:XX:XX): ");
			scanf("%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
			printf("input phy port: ");
			scanf("%hd", &port);
			setup_m.host_type = HOST_MIRROR;
			setup_m.host.ip.c[0] = ip[0];
			setup_m.host.ip.c[1] = ip[1];
			setup_m.host.ip.c[2] = ip[2];
			setup_m.host.ip.c[3] = ip[3];
			setup_m.host.mac[0] = mac[0];
			setup_m.host.mac[1] = mac[1];
			setup_m.host.mac[2] = mac[2];
			setup_m.host.mac[3] = mac[3];
			setup_m.host.mac[4] = mac[4];
			setup_m.host.mac[5] = mac[5];
			setup_m.host.port_no = port;
			nl_setup_host(setup_m);
			break;
		}
		case 3:
		{
			char data[MAX_ECHO + 1];
			printf("input echo data: ");
			scanf("%"XSTR(MAX_ECHO)"s", data);
			break;
		}
		case 4:
			while(1)
			{
				UINT16 type = 0;
				char* data;
				int size = 0;
				printf("waiting packet\n");
				size = recv_nl_message(&type, (void**)&data);
				printf("receive mes type: %x, length: %d\n", type, size);
				if(type == NLMSG_DATA_SEND)
				{
					struct connection_info* inf = (struct connection_info*)data;
					printf("host type: %d\n", inf->host_type);
					printf("IP: %hhu.%hhu.%hhu.%hhu:%hu\n", inf->ip.c[0], 
						inf->ip.c[1], inf->ip.c[2], inf->ip.c[3], inf->port
					);
				}
			}
		default:
			continue;
		}
	}

	return 0;
}
