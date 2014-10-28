#ifndef __COMMON_H__
#define __COMMON_H__

#ifndef __KERNEL__
#include <stdint.h>
#endif

union my_ip_type
{
	unsigned char c[4];
#ifndef __KERNEL__
	uint32_t i;
#else
	u32 i;
#endif
};

struct host_info
{
	union my_ip_type ip;
	unsigned char mac[6];
#ifndef __KERNEL__
	uint16_t port_no;
#else
	u16 port_no;
#endif
};

struct connection_info
{
	union my_ip_type ip;
#ifndef __KERNEL__
	uint16_t port;
	uint8_t proto;
#else
	u16 port;
	u8 proto;
#endif
};

#endif
