#include "hook.h"

#include <linux/slab.h>

#if defined(__i386__)
    #define HIJACK_SIZE 6
#elif defined(__x86_64__)
    #define HIJACK_SIZE 12
#else // ARM
    #define HIJACK_SIZE 12
#endif

LIST_HEAD(hooked_syms);

struct sym_hook {
    void *addr;
    unsigned char o_code[HIJACK_SIZE];
    unsigned char n_code[HIJACK_SIZE];
    struct list_head list;
};

#if defined(__i386__) || defined(__x86_64__)
// Thanks Dan
inline unsigned long disable_wp ( void )
{
	unsigned long cr0;
	
	preempt_disable();
	barrier();
	
	cr0 = read_cr0();
	write_cr0(cr0 & ~X86_CR0_WP);
	return cr0;
}

inline void restore_wp ( unsigned long cr0 )
{
	write_cr0(cr0);
	
	barrier();
	//preempt_enable_no_resched();
	preempt_enable();
}
#else // ARM
void cacheflush ( void *begin, unsigned long size )
{
	flush_icache_range((unsigned long)begin, (unsigned long)begin + size);
}

# if defined(CONFIG_STRICT_MEMORY_RWX)
inline void arm_write_hook ( void *target, char *code )
{
	unsigned long *target_arm = (unsigned long *)target;
	unsigned long *code_arm = (unsigned long *)code;
	
	// We should have something more generalized here, but we'll
	// get away with it since the ARM hook is always 12 bytes
	mem_text_write_kernel_word(target_arm, *code_arm);
	mem_text_write_kernel_word(target_arm + 1, *(code_arm + 1));
	mem_text_write_kernel_word(target_arm + 2, *(code_arm + 2));
}
# else
inline void arm_write_hook ( void *target, char *code )
{
	memcpy(target, code, HIJACK_SIZE);
	cacheflush(target, HIJACK_SIZE);
}
# endif
#endif

void hijack_start ( void *target, void *new )
{
	struct sym_hook *sa;
	unsigned char o_code[HIJACK_SIZE], n_code[HIJACK_SIZE];
	
	#if defined(__i386__)
	unsigned long o_cr0;
	
	// push $addr; ret
	memcpy(n_code, "\x68\x00\x00\x00\x00\xc3", HIJACK_SIZE);
	*(unsigned long *)&n_code[1] = (unsigned long)new;
	#elif defined(__x86_64__)
	unsigned long o_cr0;
	
	// mov rax, $addr; jmp rax
	memcpy(n_code, "\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0", HIJACK_SIZE);
	*(unsigned long *)&n_code[2] = (unsigned long)new;
	#else // ARM
	if ( (unsigned long)target % 4 == 0 )
	{
		// ldr pc, [pc, #0]; .long addr; .long addr
		memcpy(n_code, "\x00\xf0\x9f\xe5\x00\x00\x00\x00\x00\x00\x00\x00", HIJACK_SIZE);
		*(unsigned long *)&n_code[4] = (unsigned long)new;
		*(unsigned long *)&n_code[8] = (unsigned long)new;
	}
    else // Thumb
	{
		// add r0, pc, #4; ldr r0, [r0, #0]; mov pc, r0; mov pc, r0; .long addr
		memcpy(n_code, "\x01\xa0\x00\x68\x87\x46\x87\x46\x00\x00\x00\x00", HIJACK_SIZE);
		*(unsigned long *)&n_code[8] = (unsigned long)new;
		target--;
	}
    #endif

    printk("Hooking function 0x%p with 0x%p\n", target, new);

	memcpy(o_code, target, HIJACK_SIZE);

	#if defined(__i386__) || defined(__x86_64__)
	o_cr0 = disable_wp();
	memcpy(target, n_code, HIJACK_SIZE);
	restore_wp(o_cr0);
	#else // ARM
	arm_write_hook(target, n_code);
	#endif

	sa = kmalloc(sizeof(*sa), GFP_KERNEL);
	if ( ! sa )
		return;

	sa->addr = target;
	memcpy(sa->o_code, o_code, HIJACK_SIZE);
	memcpy(sa->n_code, n_code, HIJACK_SIZE);

	list_add(&sa->list, &hooked_syms);
}

void hijack_pause ( void *target )
{
    struct sym_hook *sa;

    printk("Pausing function hook 0x%p\n", target);

    list_for_each_entry ( sa, &hooked_syms, list )
		if ( target == sa->addr )
		{
			#if defined(__i386__) || defined(__x86_64__)
			unsigned long o_cr0 = disable_wp();
			memcpy(target, sa->o_code, HIJACK_SIZE);
			restore_wp(o_cr0);
			#else // ARM
			arm_write_hook(target, sa->o_code);
			#endif
		}
}

void hijack_resume ( void *target )
{
    struct sym_hook *sa;

    printk("Resuming function hook 0x%p\n", target);

    list_for_each_entry ( sa, &hooked_syms, list )
		if ( target == sa->addr )
		{
			#if defined(__i386__) || defined(__x86_64__)
			unsigned long o_cr0 = disable_wp();
			memcpy(target, sa->n_code, HIJACK_SIZE);
			restore_wp(o_cr0);
			#else // ARM
			arm_write_hook(target, sa->n_code);
			#endif
		}
}

void hijack_stop ( void *target )
{
    struct sym_hook *sa;

    printk("Unhooking function 0x%p\n", target);

    list_for_each_entry ( sa, &hooked_syms, list )
		if ( target == sa->addr )
		{
			#if defined(__i386__) || defined(__x86_64__)
			unsigned long o_cr0 = disable_wp();
			memcpy(target, sa->o_code, HIJACK_SIZE);
			restore_wp(o_cr0);
			#else // ARM
			arm_write_hook(target, sa->o_code);
			#endif
			
			list_del(&sa->list);
			kfree(sa);
			break;
		}
}
EXPORT_SYMBOL(hijack_start);
EXPORT_SYMBOL(hijack_pause);
EXPORT_SYMBOL(hijack_resume);
EXPORT_SYMBOL(hijack_stop);
