ifneq ($(KERNELRELEASE),)
	judgm-objs := judgm_mod.o judgm_proc.o judgm_syscall.o judgm_syscall_asm.o judgm_security.o
	obj-m := judgm.o
else
	KERNEL_SOURCE := /usr/lib/modules/$(shell uname -r)/build
	PWD := $(shell pwd)
default:
	${MAKE} -C ${KERNEL_SOURCE} SUBDIRS=${PWD} modules
	gcc judge_app.c judge_server.c -lcap -ldl -lpthread -lpq -o judge
	gcc -shared -fPIC judgx_lib.c -o libjudgx.so
	gcc -shared -fPIC -fvisibility=hidden line.c -Wl,-rpath,'$$ORIGIN' -L. -ljudgx -o line.so
	gcc -shared -fPIC -fvisibility=hidden check.c -Wl,-rpath,'$$ORIGIN' -L. -ljudgx -o check.so
clean:
	${MAKE} -C ${KERNEL_SOURCE} SUBDIRS=${PWD} clean
endif
