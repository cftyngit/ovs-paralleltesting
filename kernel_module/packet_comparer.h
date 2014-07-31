#ifndef __PACKET_COMPARER_H__
#define __PACKET_COMPARER_H__

#include <linux/slab.h>

#include "util/compare_buffer.h"

typedef int (*compare_func)(char*, char*, size_t);

int do_compare(struct list_head* buffer1, struct list_head* buffer2, compare_func compare);

#endif