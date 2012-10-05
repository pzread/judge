ifneq ($(KERNELRELEASE),)
	judgm-objs := judge_mod.o
	obj-m := judgm.o
else
	KERNEL_SOURCE := /usr/lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)
default:
	${MAKE} -C ${KERNEL_SOURCE} SUBDIRS=${PWD} modules
	gcc judge_app.c judge_server.c judge_proc.c judge_ini.c -lcap -ldl -lpthread -lmysqlclient -o judge
clean:
	${MAKE} -C ${KERNEL_SOURCE} SUBDIRS=${PWD} clean
endif
