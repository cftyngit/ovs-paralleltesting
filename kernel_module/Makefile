obj-m += find_k_func.o
find_k_func-objs := main.o hook.o ovs_func.o packet_dispatcher.o util/queue_list.o k2u.o connect_state.o

ifeq ($(KERNELDIR),)
KERNELDIR=/lib/modules/$(shell uname -r)/build
endif

ARCH=x86 EXTRA_CFLAGS="-D_CONFIG_X86_

all:
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
