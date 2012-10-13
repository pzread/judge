ifneq ($(KERNELRELEASE),)
	judgm-objs := judgm_mod.o judgm_proc.o judgm_syscall.o judgm_syscall_asm.o judgm_security.o
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
