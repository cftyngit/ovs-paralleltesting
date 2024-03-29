#ifndef __PACKET_COMPARER_H__
#define __PACKET_COMPARER_H__

#include <linux/slab.h>

#include "util/compare_buffer.h"
#include "connect_state.h"
#include "kernel_common.h"
#include "k2u.h"

typedef int (*compare_func)(char*, char*, size_t);

int do_compare(struct connection_info* con_info, struct compare_buffer* buffer1, struct compare_buffer* buffer2, compare_func compare);

#endif
