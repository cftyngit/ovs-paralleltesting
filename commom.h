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

//=============netlink config==============
#define NLNUM 24
#ifndef __KERNEL__
#define NL_MAXPAYLOAD		4096
#else
#define NL_MAXPAYLOAD		NLMSG_DEFAULT_SIZE
#endif
//type lower than 0x10 is reserved for control messages, which is defined in uapi/linux/netlink.h
//control managenent messages
#define NLMSG_SUCCESS		0xf0
#define NLMSG_FAIL			0xff
#define	NLMSG_SETECHO		0x11
#define	NLMSG_GETECHO		0x12
#define	NLMSG_DAEMON_REG	0x13
#define NLMSG_DAEMON_UNREG	0x14

//setup message
#define	NLMSG_SETUP_MIRROR	0x20
#define	NLMSG_SETUP_SERVER	0x21

//data transfer message
#define NLMSG_DATA_SEND		0x30
#define NLMSG_DATA_ACK		0x31
#define NLMSG_DATA_INFO		0x32
//=============netlink config end==============

#define HOST_TYPE_TARGET	1
#define HOST_TYPE_MIRROR	2

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
	UINT8 host_type;
};

#endif
