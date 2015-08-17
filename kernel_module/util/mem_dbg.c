#include "mem_dbg.h"

// static const unsigned char alloc_by_kmalloc = 1;
// static const unsigned char alloc_by_skb_copy = 2;
// static const unsigned char alloc_by_skb_clone = 3;
typedef enum
{
	kmalloc_func,
	skb_copy_func,
	skb_clone_func
} alloc_func;

static struct _alloced_memories
{
	struct radix_tree_root tree;
	int init;
	spinlock_t lock;
} alloced_memories = {.tree = RADIX_TREE_INIT(GFP_KERNEL), .init = 0};

struct block_info_s
{
	void* address;
	char file[MAX_PATH_LENGTH];
	unsigned int line_number;
// 	unsigned char alloc_func;
	alloc_func func;
};

typedef struct block_info_s block_info_t;

void mem_dbg_start()
{
	if(alloced_memories.init)
		return;

	spin_lock_init(&alloced_memories.lock);
	alloced_memories.init = 1;
	return;
}

void mem_dbg_finish()
{
	struct radix_tree_iter iter;
	void **slot = NULL;

	printk(KERN_DEBUG "[%s]: unfree memories:\n", __func__);
	radix_tree_for_each_slot(slot, &alloced_memories.tree, &iter, 0)
	{
		block_info_t *bi = radix_tree_deref_slot(slot);
		if(bi != NULL)
		{
			switch(bi->func)
			{
			case skb_copy_func:
				printk(KERN_DEBUG "[%s]: %p skb_copy alloc at %s: %d\n", __func__, bi->address, bi->file, bi->line_number);
				break;
			case skb_clone_func:
				printk(KERN_DEBUG "[%s]: %p skb_clone alloc at %s: %d\n", __func__, bi->address, bi->file, bi->line_number);
				break;
			case kmalloc_func:
				printk(KERN_DEBUG "[%s]: %p kmalloc alloc at %s: %d\n", __func__, bi->address, bi->file, bi->line_number);
// 				kfree(bi->address);
				break;
			}
			radix_tree_delete(&alloced_memories.tree, iter.index);
			kfree(bi);
		}
	}
}

void* _dbg_kmalloc(size_t size, int flags, char file[MAX_PATH_LENGTH], int line_num)
{
	void* alloc_addr = NULL;
	block_info_t* bi = NULL;
	block_info_t* get_bi = NULL;
	unsigned long reg_flags = 0;

	if(unlikely(!alloced_memories.init))
		return NULL;

	alloc_addr = kmalloc(size, flags);
	if(unlikely(!alloc_addr))
		return NULL;

	bi = kmalloc(sizeof(block_info_t), flags);
	if(unlikely(!bi))
	{
		kfree(alloc_addr);
		return NULL;
	}
	bi->address = alloc_addr;
	bi->func = kmalloc_func;
	bi->line_number = line_num;
	strncpy(bi->file, file, MAX_PATH_LENGTH);

	spin_lock_irqsave(&alloced_memories.lock, reg_flags);
	get_bi = radix_tree_lookup(&alloced_memories.tree, (unsigned long)alloc_addr);
	if(unlikely(!get_bi))
	{
		radix_tree_delete(&alloced_memories.tree, (unsigned long)alloc_addr);
		kfree(get_bi);
	}
	radix_tree_insert(&alloced_memories.tree, (unsigned long)alloc_addr, bi);
	spin_unlock_irqrestore(&alloced_memories.lock, reg_flags);

	return alloc_addr;
}

struct sk_buff* _dbg_skb_copy ( const struct sk_buff* skb, gfp_t priority, char file[256], int line_num )
{
	struct sk_buff* alloc_addr = NULL;
	block_info_t* bi = NULL;
	block_info_t* get_bi = NULL;
	unsigned long reg_flags = 0;

	if(unlikely(!alloced_memories.init))
		return NULL;

	alloc_addr = skb_copy(skb, priority);
	if(unlikely(!alloc_addr))
		return NULL;

	bi = kmalloc(sizeof(block_info_t), priority);
	if(unlikely(!bi))
	{
		kfree_skb_list(alloc_addr);
		return NULL;
	}
	bi->address = alloc_addr;
	bi->func = skb_copy_func;
	bi->line_number = line_num;
	strncpy(bi->file, file, MAX_PATH_LENGTH);

	spin_lock_irqsave(&alloced_memories.lock, reg_flags);
	get_bi = radix_tree_lookup(&alloced_memories.tree, (unsigned long)alloc_addr);
	if(unlikely(!get_bi))
	{
		radix_tree_delete(&alloced_memories.tree, (unsigned long)alloc_addr);
		kfree(get_bi);
	}
	radix_tree_insert(&alloced_memories.tree, (unsigned long)alloc_addr, bi);
	spin_unlock_irqrestore(&alloced_memories.lock, reg_flags);

	return alloc_addr;
}

struct sk_buff* _dbg_skb_clone ( struct sk_buff* skb, gfp_t priority, char file[256], int line_num )
{
	struct sk_buff* alloc_addr = NULL;
	block_info_t* bi = NULL;
	block_info_t* get_bi = NULL;
	unsigned long reg_flags = 0;

	if(unlikely(!alloced_memories.init))
		return NULL;

	alloc_addr = skb_clone(skb, priority);
	if(unlikely(!alloc_addr))
		return NULL;

	bi = kmalloc(sizeof(block_info_t), priority);
	if(unlikely(!bi))
	{
		kfree_skb_list(alloc_addr);
		return NULL;
	}
	bi->address = alloc_addr;
	bi->func = skb_clone_func;
	bi->line_number = line_num;
	strncpy(bi->file, file, MAX_PATH_LENGTH);

	spin_lock_irqsave(&alloced_memories.lock, reg_flags);
	get_bi = radix_tree_lookup(&alloced_memories.tree, (unsigned long)alloc_addr);
	if(unlikely(!get_bi))
	{
		radix_tree_delete(&alloced_memories.tree, (unsigned long)alloc_addr);
		kfree(get_bi);
	}
	radix_tree_insert(&alloced_memories.tree, (unsigned long)alloc_addr, bi);
	spin_unlock_irqrestore(&alloced_memories.lock, reg_flags);

	return alloc_addr;
}

void _dbg_kfree ( const void* free_addr )
{
	unsigned long reg_flags = 0;
	block_info_t* get_bi = NULL;

	if(unlikely(!alloced_memories.init))
		return;

	spin_lock_irqsave(&alloced_memories.lock, reg_flags);
	get_bi = radix_tree_delete(&alloced_memories.tree, (unsigned long)free_addr);
	if(likely(get_bi))
		kfree(get_bi);

	spin_unlock_irqrestore(&alloced_memories.lock, reg_flags);
	kfree(free_addr);
}

void _dbg_kfree_skb ( struct sk_buff* skb )
{
	unsigned long reg_flags = 0;
	block_info_t* get_bi = NULL;

	if(unlikely(!alloced_memories.init))
		return;

	spin_lock_irqsave(&alloced_memories.lock, reg_flags);
	get_bi = radix_tree_delete(&alloced_memories.tree, (unsigned long)skb);
	if(likely(get_bi))
		kfree(get_bi);

	spin_unlock_irqrestore(&alloced_memories.lock, reg_flags);
	kfree_skb(skb);
}

void _dbg_kfree_skb_list ( struct sk_buff* segs )
{
	unsigned long reg_flags = 0;
	block_info_t* get_bi = NULL;

	if(unlikely(!alloced_memories.init))
		return;

	spin_lock_irqsave(&alloced_memories.lock, reg_flags);
	get_bi = radix_tree_delete(&alloced_memories.tree, (unsigned long)segs);
	if(likely(get_bi))
		kfree(get_bi);

	spin_unlock_irqrestore(&alloced_memories.lock, reg_flags);
	kfree_skb_list(segs);
}

void _dbg_send ( struct sk_buff* skb )
{
	unsigned long reg_flags = 0;
	block_info_t* get_bi = NULL;

	if(unlikely(!alloced_memories.init))
		return;

	spin_lock_irqsave(&alloced_memories.lock, reg_flags);
	get_bi = radix_tree_delete(&alloced_memories.tree, (unsigned long)skb);
	if(likely(get_bi))
		kfree(get_bi);

	spin_unlock_irqrestore(&alloced_memories.lock, reg_flags);
}
