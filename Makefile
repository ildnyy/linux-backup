CONFIG_MODULE_SIG=n

ifeq ($(KERNELRELEASE),)

ROOTS_DIR = /root/
KERNEL_DIR = /lib/modules/$(shell uname -r)/build
CUR_DIR = $(shell pwd)

all: 
	make -C $(KERNEL_DIR) M=$(CUR_DIR) modules
clean :
	make -C $(KERNEL_DIR) M=$(CUR_DIR) clean
install:
	sudo insmod pro_stopio.ko
uninstall:
	sudo rmmod pro_stopio
    
else
obj-m += pro_stopio.o
endif
