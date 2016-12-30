
SHELL = /bin/bash

DMTX := dm-tx
TX := $(shell basename `pwd`)
DMTX_MODNAME := $(DMTX)_mod

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)


ifeq ($(KERNELRELEASE),)
all:	#user-space
all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
else
  obj-m += $(DMTX_MODNAME).o
  $(DMTX_MODNAME)-objs := $(DMTX).o lru-cache.o
endif

CC	:= gcc -O2 -Wall -g
LFLAGS	:= -lpthread

clean: 
	rm -fr *.tmp *~ .tmp_versions *.o *.ko *.mod.c .*.cmd \
		Modules.symvers Module.symvers Module.markers modules.order
