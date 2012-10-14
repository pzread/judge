#include<linux/fs.h>
#include<linux/sched.h>
#include<linux/slab.h>
#include<linux/sort.h>
#include<asm/msr.h>
#include<asm/unistd.h>
#include<asm/uaccess.h>

#include"judgm_syscall.h"
#include"judgm.h"
#include"judge_com.h"

int judgm_syscall_hook(){
    int i;
    int j;
    
    syscall_init_hook();

    __asm(
	"cli\n"
	"push %rax\n"
	"mov %cr0,%rax\n"
	"and $0xfffffffffffeffff,%rax\n"
	"mov %rax,%cr0\n"
	"pop %rax\n"
    );

    for(i = 0,j = 0;i < syscall_max;i++){
	if(i == syscall_whitelist[j]){
	    j++;
	    continue;
	}
	syscall_table[i] = (unsigned long)hook_sys_block;
    }

    __asm(
	"push %rax\n"
	"mov %cr0,%rax\n"
	"or $0x10000,%rax\n"
	"mov %rax,%cr0\n"
	"pop %rax\n"
	"sti\n"
    );

    pr_alert("%p\n",syscall_table);
    pr_alert("%p\n",hook_sys_block);

    return 0;
}
int judgm_syscall_unhook(){
    __asm(
	"cli\n"
	"push %rax\n"
	"mov %cr0,%rax\n"
	"and $0xfffffffffffeffff,%rax\n"
	"mov %rax,%cr0\n"
	"pop %rax\n"
    );

    memcpy(syscall_table,judgm_syscall_ori_table,sizeof(unsigned long) * syscall_max);

    __asm(
	"push %rax\n"
	"mov %cr0,%rax\n"
	"or $0x10000,%rax\n"
	"mov %rax,%cr0\n"
	"pop %rax\n"
	"sti\n"
    );

    schedule_timeout_interruptible(3 * HZ);

    return 0;
}
static int syscall_init_hook(){
    int i;

    unsigned char code[3] = {0xff,0x14,0xc5};
    unsigned long addr;

    addr = native_read_msr(MSR_LSTAR);
    while(true){
	for(i = 0;i < 3;i++){
	    if(*(unsigned char*)addr != code[i]){
		addr++;
		break;
	    }
	    addr++;
	}
	if(i == 3){
	    break;
	}
    }
    syscall_table = (unsigned long*)(0xffffffff00000000 + *((unsigned int*)addr));
    
    addr -= 4L;
    while(true){
	if(*(unsigned char*)addr == 0x3d){
	    addr++;
	    break;
	}
	addr--;
    }
    syscall_max = *(unsigned int*)addr;

    judgm_syscall_ori_table = kmalloc(sizeof(unsigned long) * (syscall_max + 1),GFP_KERNEL);
    memcpy(judgm_syscall_ori_table,syscall_table,sizeof(unsigned long) * syscall_max);

    sort(syscall_whitelist,SYSCALL_WHITELIST_SIZE,sizeof(unsigned int),syscall_whitelist_cmp,NULL);

    return 0;
}
static int syscall_whitelist_cmp(const void *a,const void *b){
    if(*(unsigned int*)a < *(unsigned int*)b){
	return -1;
    }else if(*(unsigned int*)a == *(unsigned int*)b){
	return 0;
    }else{
	return 1;
    }
}

int judgm_syscall_check(){
    if(judgm_proc_task_lookup(current)){
	return 1;
    }
    return 0;
}
int judgm_syscall_block(){
    struct judgm_proc_info *info;

    if((info = judgm_proc_task_lookup(current)) == NULL){
	return 0;
    }

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return 0;
}

/*asmlinkage long hook_sys_nanosleep(struct timespec __user *rqtp,struct timespec __user *rmtp){
    long ret;

    struct judgm_proc_info *info;

    atomic64_inc(&syscall_pending);

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	ret = ori_sys_nanosleep(rqtp,rmtp);
	atomic64_dec(&syscall_pending);
	return ret;
    }

    pr_alert("judgm:PID %d  nanosleep\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);

    atomic64_dec(&syscall_pending);
    return -EACCES;
}*/
