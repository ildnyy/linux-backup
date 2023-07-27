CONFIG_MODULE_SIG=n

ifeq ($(KERNELRELEASE),)

ROOTS_DIR = /root/
#内核源码路径，不同环境可能会不一样，内核源码一定要先编译
KERNEL_DIR = /lib/modules/$(shell uname -r)/build
CUR_DIR = $(shell pwd)

all: 
	make -C $(KERNEL_DIR) M=$(CUR_DIR) modules
clean :
	make -C $(KERNEL_DIR) M=$(CUR_DIR) clean
install:
	insmod pro_stopio.ko
uninstall:
	rmmod pro_stopio
    
else
#用于指定到底编译的是哪个代码--hello.c
obj-m += pro_stopio.o
#obj-m += math.o
endif

