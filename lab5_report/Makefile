obj-m += LKM.o

#KDIR  := /lib/modules/$(shell uname -r)/build

#obj-m += $(mname).o
#all: 
#	$(MAKE) -C $(KDIR) M=$(shall pwd) modules
#    $(MAKE) -C $(KDIR) M=$(PWD) modules


all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules
	
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	
# sudo insmod mymod.ko   (inserting a module)
# lsmod
# sudo rmmod mymod.ko     (remove the module)
