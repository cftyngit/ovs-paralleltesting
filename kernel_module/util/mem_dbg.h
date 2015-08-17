#ifndef __MEM_DBG_H__
#define __MEM_DBG_H__

#include <linux/radix-tree.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>

#define MAX_PATH_LENGTH 256

#if DEBUG_MEM == 1
// alloc memory
#define dbg_kmalloc(size, flags) _dbg_kmalloc(size, flags, __FILE__, __LINE__)
#define dbg_skb_copy(skb, priority) _dbg_skb_copy(skb, priority, __FILE__, __LINE__)
#define dbg_skb_clone(skb, priority) _dbg_skb_clone(skb, priority, __FILE__, __LINE__)
// free memory
#define dbg_kfree(ptr) _dbg_kfree(ptr)
#define dbg_kfree_skb(skb) _dbg_kfree_skb(skb) 
#define dbg_kfree_skb_list(segs) _dbg_kfree_skb_list(segs)

#define dbg_send(skb) _dbg_send(skb)
#else
// alloc memory
#define dbg_kmalloc(size, flags) kmalloc(size, flags)
#define dbg_skb_copy(skb, priority) skb_copy(skb, priority)
#define dbg_skb_clone(skb, priority) skb_clone(skb, priority)
// free memory
#define dbg_kfree(ptr) kfree(ptr)
#define dbg_kfree_skb(skb) kfree_skb(skb) 
#define dbg_kfree_skb_list(segs) kfree_skb_list(segs)

#define dbg_send(skb) do{}while(0)
#endif

void* _dbg_kmalloc(size_t size, int flags, char file[MAX_PATH_LENGTH], int line_num);
struct sk_buff* _dbg_skb_copy(const struct sk_buff *skb, gfp_t priority, char file[MAX_PATH_LENGTH], int line_num);
struct sk_buff* _dbg_skb_clone(struct sk_buff *skb, gfp_t priority, char file[MAX_PATH_LENGTH], int line_num);

void _dbg_kfree(const void *);
void _dbg_kfree_skb(struct sk_buff *skb);
void _dbg_kfree_skb_list(struct sk_buff *segs);

void _dbg_send(struct sk_buff *skb);

void mem_dbg_start(void);
void mem_dbg_finish(void);

#endif
