ifeq ($(KERNELRELEASE),)  

KERNELDIR ?= /lib/modules/$(shell uname -r)/build 
PWD := $(shell pwd)  

.PHONY: build clean  

build: ser_process
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules  

clean:
	rm -rf *.o *~ core .depend .*.cmd *.order *.symvers *.ko *.mod.c sneaky_process

sneaky_process:
	gcc -o ser_process ser_process.c -O3

else  

$(info Building with KERNELRELEASE = ${KERNELRELEASE}) 
obj-m :=    ser_mod.o  

endif
