#ifndef __COMMON_H__
#define __COMMON_H__

#ifndef __KERNEL__
#include <stdint.h>
#endif

#ifndef __KERNEL__
#define UINT8	uint8_t
#define UINT16	uint16_t
#define UINT32	uint32_t
#else
#define UINT8	u8
#define UINT16	u16
#define UINT32	u32
#endif

union my_ip_type
{
	unsigned char c[4];
	UINT32 i;
};

struct host_info
{
	union my_ip_type ip;
	unsigned char mac[6];
	UINT16 port_no;
};

struct connection_info
{
	union my_ip_type ip;
	UINT16 port;
	UINT8 proto;
};

#endif
