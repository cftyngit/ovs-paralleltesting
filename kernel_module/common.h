#ifndef __COMMON_H__
#define __COMMON_H__

union my_ip_type
{
    unsigned char c[4];
    unsigned int i;
};

struct host_info
{
    union my_ip_type ip;
    unsigned char mac[6];
};
#endif