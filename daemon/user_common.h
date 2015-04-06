#ifndef __USER_COMMON_H__
#define __USER_COMMON_H__

#include "../commom.h"

#ifdef NDEBUG
# define DEBUG_PRINT(fmt, ...)
# ifndef DAEMONIZE
#  define DAEMONIZE
# endif
#else
# ifdef DAEMONIZE
#  define DEBUG_PRINT(fmt, ...) syslog(LOG_DEBUG, fmt, ##__VA_ARGS__)
# else
#  define DEBUG_PRINT(fmt, ...) printf(fmt, ##__VA_ARGS__)
# endif
#endif

# ifdef DAEMONIZE
#  define MSG_PRINT(fmt, ...) syslog(LOG_INFO, fmt, ##__VA_ARGS__)
# else
#  define MSG_PRINT(fmt, ...) printf(fmt, ##__VA_ARGS__)
# endif

#define SETUP_TARGET 1
#define SETUP_MIRROR 2

struct setup_message
{
    char host_type;
    char padding[3];
    struct host_info host;
};

#endif // __KERNEL_COMMON_H__