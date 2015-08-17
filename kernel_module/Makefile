obj-m += find_k_func.o
#find_k_func-objs := main.o hook.o ovs_func.o packet_dispatcher.o k2u.o connect_state.o l4proto/tcp.o util/compare_buffer.o packet_comparer.o util/packet_buffer.o kernel_common.o
find_k_func-objs := main.o hook.o packet_dispatcher.o k2u.o connect_state.o l4proto/tcp.o util/compare_buffer.o packet_comparer.o util/packet_buffer.o kernel_common.o util/mem_dbg.o

INFO_ON = 1
DEBUG_ON = 0
ERROR_OFF = 0

PPBUSAGE_ON = 0
DEBUG_MEM_ALLOC_ON = 1

KERNELVERSION=$(shell uname -r | cut -f1-2 -d.)
find_k_func-objs += ovs/$(KERNELVERSION)/ovs_func.o

ifeq ($(KERNELDIR),)
KERNELDIR=/lib/modules/$(shell uname -r)/build
endif

PRINT_LEVEL = -DINFO=$(INFO_ON) -DDEBUG=$(DEBUG_ON) -DNOERR=$(ERROR_OFF) -DPKTBUFF_USAGE=$(PPBUSAGE_ON) -DDEBUG_MEM=$(DEBUG_MEM_ALLOC_ON)

all:
	KCPPFLAGS="$(PRINT_LEVEL)" make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
