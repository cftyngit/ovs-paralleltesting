#ifndef OVSPTD_NLMGR_H
#define OVSPTD_NLMGR_H

#include <strings.h>
#include <stdlib.h>
#include <string.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "user_common.h"

int nl_init();
int nl_uninit();
int get_nl_socket();
int send_nl_message(int fd, int type, void* data, size_t length);
int nl_setup_host(struct setup_message setup_m);
int nl_echo(char* mes);
int recv_nl_message(UINT16* type, void* data);

#endif // OVSPTD_NLMGR_H