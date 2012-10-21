#include<linux/fs.h>
#include<linux/sched.h>
#include<linux/slab.h>
#include<linux/sort.h>
#include<asm/msr.h>
#include<asm/unistd.h>
#include<asm/uaccess.h>

#include"judge_def.h"
#include"judgm.h"
#include"judgx_com.h"
#include"judgm_syscall.h"

int judgm_syscall_hook(){
    int i;
    int j;

    unsigned int size;
    unsigned int restore;

    syscall_init_hook();
   
    syscall_addr_write((unsigned long)syscall_table,&size,&restore);
    for(i = 0,j = 0;i < syscall_max;i++){
	if(size == 0){
	    syscall_addr_restore((unsigned long)(syscall_table + i - 1),restore);
	    syscall_addr_write((unsigned long)(syscall_table + i),&size,&restore);
	}
	size -= sizeof(unsigned long);

	if(i == syscall_whitelist[j]){
	    j++;
	    continue;
	}
	syscall_table[i] = (unsigned long)hook_sys_block;
    }
    syscall_addr_restore((unsigned long)(&syscall_table[i - 1]),restore);

    return 0;
}
int judgm_syscall_unhook(){
    int i;

    unsigned int size;
    unsigned int restore;

    syscall_addr_write((unsigned long)syscall_table,&size,&restore);
    for(i = 0;i < syscall_max;i++){
	if(size == 0){
	    syscall_addr_restore((unsigned long)(&syscall_table[i - 1]),restore);
	    syscall_addr_write((unsigned long)(&syscall_table[i]),&size,&restore);
	}
	size -= sizeof(unsigned long);

	syscall_table[i] = (unsigned long)judgm_syscall_ori_table[i];
    }
    syscall_addr_restore((unsigned long)(&syscall_table[i - 1]),restore);

    schedule_timeout_interruptible(3 * HZ);
    return 0;
}
static int syscall_init_hook(){
    ssize_t ret;
    int i;
    int j;

    struct file *f;
    char line[128];
    unsigned char code[3] = {0xff,0x14,0xc5};
    unsigned long addr;

    f = filp_open("/proc/kallsyms",O_RDONLY,0);
    set_fs(KERNEL_DS);

    i = 0;
    addr = 0;
    while(true){
	ret = f->f_op->read(f,&line[i],1,&f->f_pos);

	if(line[i] == '\n' || ret <= 0){
	    line[i] = '\0';

	    addr = 0;
	    for(j = 0;j < i;j++){
		if(line[j] == ' '){
		    j++;
		    break;
		}

		addr *= 16UL;
		if(line[j] >= '0' && line[j] <= '9'){
		    addr += (unsigned long)(line[j] - '0');
		}else{
		    addr += (unsigned long)(line[j] - 'a' + 10);
		}
	    }
	    for(;j < i;j++){
		if(line[j] == ' '){
		    j++;
		    break;
		}
	    }
	    if(j < i){
		if(strcmp("system_call",line + j) == 0){
		    break;
		}
	    }

	    i = 0;
	}else{
	    i++;
	}

	if(ret <= 0){
	    break;
	}
    }

    set_fs(USER_DS);
    filp_close(f,NULL);

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
static int syscall_addr_write(unsigned long addr,unsigned int *size,int *restore){
    unsigned int level;
    pte_t *pte;

    pte = lookup_address(addr,&level);
    if(pte->pte & _PAGE_RW){
	*restore = 0;
    }else{
	pte->pte |= _PAGE_RW;
	*restore = 1;
    }

    switch(level){
	case PG_LEVEL_4K:
	    *size = 4096;
	    break;
	case PG_LEVEL_2M:
	    *size = 2097152 ;
	    break;
	case PG_LEVEL_1G:
	    *size = 1073741824;
	    break;
    }
    *size -= (((unsigned int)addr) & (*size - 1));

    return 0;
}
static int syscall_addr_restore(unsigned long addr,int restore){
    unsigned int level;
    pte_t *pte;

    if(restore){
	pte = lookup_address(addr,&level);
	pte->pte ^= _PAGE_RW;
    }

    return 0;
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
