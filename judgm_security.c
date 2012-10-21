#include<linux/fs.h>
#include<linux/security.h>
#include<linux/sched.h>
#include<asm/uaccess.h>

#include"judge_def.h"
#include"judgm.h"
#include"judgx_com.h"
#include"judgm_security.h"

int judgm_security_hook(){

    security_hook_addr = security_get_addr();

    ori_sops = (struct security_operations*)*security_hook_addr;
    memcpy(&hook_sops,ori_sops,sizeof(struct security_operations));

    hook_sops.ptrace_access_check = hook_ptrace_access_check;
    hook_sops.ptrace_traceme = hook_ptrace_traceme;
    hook_sops.capget = hook_capget;
    hook_sops.capset = hook_capset;
    //hook_sops.capable = hook_capable;
    hook_sops.quotactl = hook_quotactl;
    hook_sops.quota_on = hook_quota_on;
    hook_sops.syslog = hook_syslog;
    hook_sops.settime = hook_settime;
    hook_sops.vm_enough_memory = hook_vm_enough_memory;
    //hook_sops.bprm_set_creds = hook_bprm_set_creds;
    //hook_sops.bprm_check_security = hook_bprm_check_security;
    //hook_sops.bprm_secureexec = hook_bprm_secureexec;
    hook_sops.sb_alloc_security = hook_sb_alloc_security;
    hook_sops.sb_copy_data = hook_sb_copy_data;
    hook_sops.sb_remount = hook_sb_remount;
    hook_sops.sb_kern_mount = hook_sb_kern_mount;
    hook_sops.sb_show_options = hook_sb_show_options;
    hook_sops.sb_statfs = hook_sb_statfs;
    hook_sops.sb_mount = hook_sb_mount;
    hook_sops.sb_umount = hook_sb_umount;
    hook_sops.sb_pivotroot = hook_sb_pivotroot;
    hook_sops.sb_set_mnt_opts = hook_sb_set_mnt_opts;
    hook_sops.sb_parse_opts_str = hook_sb_parse_opts_str;
    hook_sops.path_unlink = hook_path_unlink;
    hook_sops.path_mkdir = hook_path_mkdir;
    hook_sops.path_rmdir = hook_path_rmdir;
    hook_sops.path_mknod = hook_path_mknod;
    hook_sops.path_truncate = hook_path_truncate;
    hook_sops.path_symlink = hook_path_symlink;
    hook_sops.path_link = hook_path_link;
    hook_sops.path_rename = hook_path_rename;
    hook_sops.path_chmod = hook_path_chmod;
    hook_sops.path_chown = hook_path_chown;
    hook_sops.path_chroot = hook_path_chroot;
    //hook_sops.inode_alloc_security = hook_inode_alloc_security;
    hook_sops.inode_init_security = hook_inode_init_security;
    hook_sops.inode_create = hook_inode_create;
    hook_sops.inode_link = hook_inode_link;
    hook_sops.inode_unlink = hook_inode_unlink;
    hook_sops.inode_symlink = hook_inode_symlink;
    hook_sops.inode_mkdir = hook_inode_mkdir;
    hook_sops.inode_rmdir = hook_inode_rmdir;
    hook_sops.inode_mknod = hook_inode_mknod;
    hook_sops.inode_rename = hook_inode_rename;
    hook_sops.inode_readlink = hook_inode_readlink;
    //hook_sops.inode_follow_link = hook_inode_follow_link;
    hook_sops.inode_permission = hook_inode_permission;
    hook_sops.inode_setattr = hook_inode_setattr;
    //hook_sops.inode_getattr = hook_inode_getattr;
    hook_sops.inode_setxattr = hook_inode_setxattr;
    hook_sops.inode_getxattr = hook_inode_getxattr;
    hook_sops.inode_listxattr = hook_inode_listxattr;
    hook_sops.inode_removexattr = hook_inode_removexattr;
    hook_sops.inode_need_killpriv = hook_inode_need_killpriv;
    hook_sops.inode_killpriv = hook_inode_killpriv;
    hook_sops.inode_getsecurity = hook_inode_getsecurity;
    hook_sops.inode_setsecurity = hook_inode_setsecurity;
    hook_sops.inode_listsecurity = hook_inode_listsecurity;
    hook_sops.file_permission = hook_file_permission;
    //hook_sops.file_alloc_security = hook_file_alloc_security;
    hook_sops.file_ioctl = hook_file_ioctl;
    //hook_sops.mmap_addr = hook_mmap_addr;
    //hook_sops.mmap_file = hook_mmap_file;
    //hook_sops.file_mprotect = hook_file_mprotect;
    hook_sops.file_lock = hook_file_lock;
    hook_sops.file_fcntl = hook_file_fcntl;
    hook_sops.file_set_fowner = hook_file_set_fowner;
    hook_sops.file_send_sigiotask = hook_file_send_sigiotask;
    hook_sops.file_receive = hook_file_receive;
    hook_sops.file_open = hook_file_open;
    hook_sops.task_create = hook_task_create;
    hook_sops.cred_alloc_blank = hook_cred_alloc_blank;
    //hook_sops.cred_prepare = hook_cred_prepare;
    hook_sops.kernel_act_as = hook_kernel_act_as;
    hook_sops.kernel_create_files_as = hook_kernel_create_files_as;
    hook_sops.kernel_module_request = hook_kernel_module_request;
    hook_sops.task_fix_setuid = hook_task_fix_setuid;
    hook_sops.task_setpgid = hook_task_setpgid;
    hook_sops.task_getpgid = hook_task_getpgid;
    hook_sops.task_getsid = hook_task_getsid;
    hook_sops.task_setnice = hook_task_setnice;
    hook_sops.task_setioprio = hook_task_setioprio;
    hook_sops.task_getioprio = hook_task_getioprio;
    hook_sops.task_setrlimit = hook_task_setrlimit;
    hook_sops.task_setscheduler = hook_task_setscheduler;
    hook_sops.task_getscheduler = hook_task_getscheduler;
    hook_sops.task_movememory = hook_task_movememory;
    hook_sops.task_kill = hook_task_kill;
    hook_sops.task_wait = hook_task_wait;
    hook_sops.task_prctl = hook_task_prctl;
    hook_sops.ipc_permission = hook_ipc_permission;
    hook_sops.msg_msg_alloc_security = hook_msg_msg_alloc_security;
    hook_sops.msg_queue_alloc_security = hook_msg_queue_alloc_security;
    hook_sops.msg_queue_associate = hook_msg_queue_associate;
    hook_sops.msg_queue_msgctl = hook_msg_queue_msgctl;
    hook_sops.msg_queue_msgsnd = hook_msg_queue_msgsnd;
    hook_sops.msg_queue_msgrcv = hook_msg_queue_msgrcv;
    hook_sops.shm_alloc_security = hook_shm_alloc_security;
    hook_sops.shm_associate = hook_shm_associate;
    hook_sops.shm_shmctl = hook_shm_shmctl;
    hook_sops.shm_shmat = hook_shm_shmat;
    hook_sops.sem_alloc_security = hook_sem_alloc_security;
    hook_sops.sem_associate = hook_sem_associate;
    hook_sops.sem_semctl = hook_sem_semctl;
    hook_sops.sem_semop = hook_sem_semop;
    hook_sops.netlink_send = hook_netlink_send;
    hook_sops.getprocattr = hook_getprocattr;
    hook_sops.setprocattr = hook_setprocattr;
    hook_sops.secid_to_secctx = hook_secid_to_secctx;
    hook_sops.secctx_to_secid = hook_secctx_to_secid;
    hook_sops.inode_notifysecctx = hook_inode_notifysecctx;
    hook_sops.inode_setsecctx = hook_inode_setsecctx;
    hook_sops.inode_getsecctx = hook_inode_getsecctx;
    hook_sops.unix_stream_connect = hook_unix_stream_connect;
    hook_sops.unix_may_send = hook_unix_may_send;
    hook_sops.socket_create = hook_socket_create;
    hook_sops.socket_post_create = hook_socket_post_create;
    hook_sops.socket_bind = hook_socket_bind;
    hook_sops.socket_connect = hook_socket_connect;
    hook_sops.socket_listen = hook_socket_listen;
    hook_sops.socket_accept = hook_socket_accept;
    hook_sops.socket_sendmsg = hook_socket_sendmsg;
    hook_sops.socket_recvmsg = hook_socket_recvmsg;
    hook_sops.socket_getsockname = hook_socket_getsockname;
    hook_sops.socket_getpeername = hook_socket_getpeername;
    hook_sops.socket_getsockopt = hook_socket_getsockopt;
    hook_sops.socket_setsockopt = hook_socket_setsockopt;
    hook_sops.socket_shutdown = hook_socket_shutdown;
    //hook_sops.socket_sock_rcv_skb = hook_socket_sock_rcv_skb;
    hook_sops.socket_getpeersec_stream = hook_socket_getpeersec_stream;
    hook_sops.socket_getpeersec_dgram = hook_socket_getpeersec_dgram;
    //hook_sops.sk_alloc_security = hook_sk_alloc_security;
    //hook_sops.inet_conn_request = hook_inet_conn_request;
    hook_sops.secmark_relabel_packet = hook_secmark_relabel_packet;
    hook_sops.tun_dev_create = hook_tun_dev_create;
    hook_sops.tun_dev_attach = hook_tun_dev_attach;
    hook_sops.key_alloc = hook_key_alloc;
    hook_sops.key_permission = hook_key_permission;
    hook_sops.key_getsecurity = hook_key_getsecurity;
    hook_sops.audit_rule_init = hook_audit_rule_init;
    hook_sops.audit_rule_known = hook_audit_rule_known;
    hook_sops.audit_rule_match = hook_audit_rule_match;

    *security_hook_addr = (unsigned long)&hook_sops;

    return 0;
}
int judgm_security_unhook(){
    *security_hook_addr = (unsigned long)ori_sops;
    return 0;
}

static unsigned long* security_get_addr(){
    ssize_t ret;
    int i;
    int j;

    struct file *f;
    char line[128];
    unsigned char code[3] = {0x48,0xc7,0x05};
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
		if(strcmp("reset_security_ops",line + j) == 0){
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

    i = 0;    
    while(i < 3){
	if(*(unsigned char*)addr != code[i]){
	    i = 0;
	}else{
	    i++;
	}
	addr++;
    }
    
    return (unsigned long*)(addr + (unsigned long)*(u32*)addr + 8UL);
}

static int hook_inode_permission(struct inode *inode,int mask){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_permission(inode,mask);
    }

    pr_alert("judgm:PID %d  inode_permission %08x\n",current->tgid,mask);

    if((mask & ~(MAY_EXEC | MAY_READ | MAY_OPEN | MAY_CHDIR | MAY_NOT_BLOCK)) != 0){
	info->status = JUDGE_RF;
	send_sig(SIGKILL,current,0);
	return -EACCES;
    }
    return ori_sops->inode_permission(inode,mask);
}
static int hook_file_open(struct file *file, const struct cred *cred){
    int ret;

    struct judgm_proc_info *info;
    char *buf_path,*path;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->file_open(file,cred);
    }

    ret = 0;

    buf_path = kmalloc(sizeof(char) * (PATH_MAX + 1),GFP_KERNEL);
    path = d_path(&file->f_path,buf_path,PATH_MAX + 1);

    pr_alert("judgm:PID %d  file_open %s %08x\n",current->tgid,path,file->f_mode);

    if((file->f_mode & !(FMODE_READ | FMODE_LSEEK | FMODE_PREAD | FMODE_EXEC)) != 0){
	ret = -EACCES;
    }else if(strcmp(path,info->path) != 0){
	ret = -EACCES;
    }

    kfree(buf_path);

    if(ret != 0){
	info->status = JUDGE_RF;
	send_sig(SIGKILL,current,0);
	return ret;
    }
    return ori_sops->file_open(file,cred);
}
static int hook_file_permission(struct file *file,int mask){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->file_permission(file,mask);
    }

    /*buf_path = kmalloc(sizeof(char) * (PATH_MAX + 1),GFP_KERNEL);
    path = d_path(&file->f_path,buf_path,PATH_MAX + 1);

    pr_alert("judgm:PID %d  file_permission %s %08x\n",current->tgid,path,mask);

    kfree(buf_path);*/

    if((mask & ~(MAY_READ | MAY_WRITE)) != 0){
	info->status = JUDGE_RF;
	send_sig(SIGKILL,current,0);
	return -EACCES;
    }else if((mask & MAY_WRITE) != 0 && file != info->pout){
	info->status = JUDGE_RF;
	send_sig(SIGKILL,current,0);
	return -EACCES;
    }
    return ori_sops->file_permission(file,mask);
}
static int hook_vm_enough_memory(struct mm_struct *mm,long pages){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->vm_enough_memory(mm,pages);
    }

    info->peakmem = (mm->total_vm + pages) << PAGE_SHIFT;
    pr_alert("judgm:PID %d  vm_enough_memory %lu\n",current->tgid,info->peakmem);

    if(info->peakmem > info->memlimit){
	info->status = JUDGE_MLE;
	send_sig(SIGKILL,current,0);
	return -EACCES;
    }
    return ori_sops->vm_enough_memory(mm,pages);
}




static int hook_ptrace_access_check(struct task_struct *child,unsigned int mode){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->ptrace_access_check(child,mode);
    }

    pr_alert("judgm:PID %d  ptrace_access_check\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_ptrace_traceme(struct task_struct *parent){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->ptrace_traceme(parent);
    }

    pr_alert("judgm:PID %d  ptrace_traceme\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_capget(struct task_struct *target,kernel_cap_t *effective,kernel_cap_t *inheritable,kernel_cap_t *permitted){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->capget(target,effective,inheritable,permitted);
    }

    pr_alert("judgm:PID %d  capget\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_capset(struct cred *new,const struct cred *old,const kernel_cap_t *effective,const kernel_cap_t *inheritable,const kernel_cap_t *permitted){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->capset(new,old,effective,inheritable,permitted);
    }

    pr_alert("judgm:PID %d  capset\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
/*static int hook_capable(const struct cred *cred,struct user_namespace *ns,int cap,int audit){
  struct judgm_proc_info *info;

  info = judgm_proc_task_lookup(current);
  if(info == NULL){
  return ori_sops->capable(cred,ns,cap,audit);
  }

  pr_alert("judgm:PID %d  capable\n",current->tgid);

  info->status = JUDGE_RF;
  send_sig(SIGKILL,current,0);
  return -EACCES;
  }*/
static int hook_quotactl(int cmds,int type,int id,struct super_block *sb){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->quotactl(cmds,type,id,sb);
    }

    pr_alert("judgm:PID %d  quotactl\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_quota_on(struct dentry *dentry){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->quota_on(dentry);
    }

    pr_alert("judgm:PID %d  quota_on\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_syslog(int type){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->syslog(type);
    }

    pr_alert("judgm:PID %d  syslog\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_settime(const struct timespec *ts,const struct timezone *tz){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->settime(ts,tz);
    }

    pr_alert("judgm:PID %d  settime\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
/*static int hook_bprm_set_creds(struct linux_binprm *bprm){
  struct judgm_proc_info *info;

  info = judgm_proc_task_lookup(current);
  if(info == NULL){
  return ori_sops->bprm_set_creds(bprm);
  }

  pr_alert("judgm:PID %d  bprm_set_creds\n",current->tgid);

  info->status = JUDGE_RF;
  send_sig(SIGKILL,current,0);
  return -EACCES;
  }*/
/*static int hook_bprm_check_security(struct linux_binprm *bprm){
  struct judgm_proc_info *info;

  info = judgm_proc_task_lookup(current);
  if(info == NULL){
  return ori_sops->bprm_check_security(bprm);
  }

  pr_alert("judgm:PID %d  bprm_check_security\n",current->tgid);

  info->status = JUDGE_RF;
  send_sig(SIGKILL,current,0);
  return -EACCES;
  }*/
/*static int hook_bprm_secureexec(struct linux_binprm *bprm){
  struct judgm_proc_info *info;

  info = judgm_proc_task_lookup(current);
  if(info == NULL){
  return ori_sops->bprm_secureexec(bprm);
  }

  pr_alert("judgm:PID %d  bprm_secureexec\n",current->tgid);

  info->status = JUDGE_RF;
  send_sig(SIGKILL,current,0);
  return -EACCES;
  }*/
static int hook_sb_alloc_security(struct super_block *sb){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->sb_alloc_security(sb);
    }

    pr_alert("judgm:PID %d  sb_alloc_security\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_sb_copy_data(char *orig,char *copy){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->sb_copy_data(orig,copy);
    }

    pr_alert("judgm:PID %d  sb_copy_data\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_sb_remount(struct super_block *sb,void *data){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->sb_remount(sb,data);
    }

    pr_alert("judgm:PID %d  sb_remount\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_sb_kern_mount(struct super_block *sb,int flags,void *data){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->sb_kern_mount(sb,flags,data);
    }

    pr_alert("judgm:PID %d  sb_kern_mount\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_sb_show_options(struct seq_file *m,struct super_block *sb){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->sb_show_options(m,sb);
    }

    pr_alert("judgm:PID %d  sb_show_options\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_sb_statfs(struct dentry *dentry){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->sb_statfs(dentry);
    }

    pr_alert("judgm:PID %d  sb_statfs\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_sb_mount(char *dev_name,struct path *path,char *type,unsigned long flags,void *data){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->sb_mount(dev_name,path,type,flags,data);
    }

    pr_alert("judgm:PID %d  sb_mount\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_sb_umount(struct vfsmount *mnt,int flags){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->sb_umount(mnt,flags);
    }

    pr_alert("judgm:PID %d  sb_umount\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_sb_pivotroot(struct path *old_path,struct path *new_path){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->sb_pivotroot(old_path,new_path);
    }

    pr_alert("judgm:PID %d  sb_pivotroot\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_sb_set_mnt_opts(struct super_block *sb,struct security_mnt_opts *opts){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->sb_set_mnt_opts(sb,opts);
    }

    pr_alert("judgm:PID %d  sb_set_mnt_opts\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_sb_parse_opts_str(char *options,struct security_mnt_opts *opts){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->sb_parse_opts_str(options,opts);
    }

    pr_alert("judgm:PID %d  sb_parse_opts_str\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_path_unlink(struct path *dir,struct dentry *dentry){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->path_unlink(dir,dentry);
    }

    pr_alert("judgm:PID %d  path_unlink\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_path_mkdir(struct path *dir,struct dentry *dentry,umode_t mode){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->path_mkdir(dir,dentry,mode);
    }

    pr_alert("judgm:PID %d  path_mkdir\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_path_rmdir(struct path *dir,struct dentry *dentry){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->path_rmdir(dir,dentry);
    }

    pr_alert("judgm:PID %d  path_rmdir\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_path_mknod(struct path *dir,struct dentry *dentry,umode_t mode,unsigned int dev){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->path_mknod(dir,dentry,mode,dev);
    }

    pr_alert("judgm:PID %d  path_mknod\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_path_truncate(struct path *path){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->path_truncate(path);
    }

    pr_alert("judgm:PID %d  path_truncate\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_path_symlink(struct path *dir,struct dentry *dentry,const char *old_name){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->path_symlink(dir,dentry,old_name);
    }

    pr_alert("judgm:PID %d  path_symlink\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_path_link(struct dentry *old_dentry,struct path *new_dir,struct dentry *new_dentry){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->path_link(old_dentry,new_dir,new_dentry);
    }

    pr_alert("judgm:PID %d  path_link\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_path_rename(struct path *old_dir,struct dentry *old_dentry,struct path *new_dir,struct dentry *new_dentry){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->path_rename(old_dir,old_dentry,new_dir,new_dentry);
    }

    pr_alert("judgm:PID %d  path_rename\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_path_chmod(struct path *path,umode_t mode){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->path_chmod(path,mode);
    }

    pr_alert("judgm:PID %d  path_chmod\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_path_chown(struct path *path,uid_t uid,gid_t gid){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->path_chown(path,uid,gid);
    }

    pr_alert("judgm:PID %d  path_chown\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_path_chroot(struct path *path){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->path_chroot(path);
    }

    pr_alert("judgm:PID %d  path_chroot\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
/*static int hook_inode_alloc_security(struct inode *inode){
  struct judgm_proc_info *info;

  info = judgm_proc_task_lookup(current);
  if(info == NULL){
  return ori_sops->inode_alloc_security(inode);
  }

  pr_alert("judgm:PID %d  inode_alloc_security\n",current->tgid);

  info->status = JUDGE_RF;
  send_sig(SIGKILL,current,0);
  return -EACCES;
  }*/
static int hook_inode_init_security(struct inode *inode,struct inode *dir,const struct qstr *qstr,char **name,void **value,size_t *len){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_init_security(inode,dir,qstr,name,value,len);
    }

    pr_alert("judgm:PID %d  inode_init_security\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_inode_create(struct inode *dir,struct dentry *dentry,umode_t mode){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_create(dir,dentry,mode);
    }

    pr_alert("judgm:PID %d  inode_create\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_inode_link(struct dentry *old_dentry,struct inode *dir,struct dentry *new_dentry){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_link(old_dentry,dir,new_dentry);
    }

    pr_alert("judgm:PID %d  inode_link\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_inode_unlink(struct inode *dir,struct dentry *dentry){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_unlink(dir,dentry);
    }

    pr_alert("judgm:PID %d  inode_unlink\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_inode_symlink(struct inode *dir,struct dentry *dentry,const char *old_name){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_symlink(dir,dentry,old_name);
    }

    pr_alert("judgm:PID %d  inode_symlink\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_inode_mkdir(struct inode *dir,struct dentry *dentry,umode_t mode){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_mkdir(dir,dentry,mode);
    }

    pr_alert("judgm:PID %d  inode_mkdir\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_inode_rmdir(struct inode *dir,struct dentry *dentry){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_rmdir(dir,dentry);
    }

    pr_alert("judgm:PID %d  inode_rmdir\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_inode_mknod(struct inode *dir,struct dentry *dentry,umode_t mode,dev_t dev){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_mknod(dir,dentry,mode,dev);
    }

    pr_alert("judgm:PID %d  inode_mknod\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_inode_rename(struct inode *old_dir,struct dentry *old_dentry,struct inode *new_dir,struct dentry *new_dentry){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_rename(old_dir,old_dentry,new_dir,new_dentry);
    }

    pr_alert("judgm:PID %d  inode_rename\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_inode_readlink(struct dentry *dentry){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_readlink(dentry);
    }

    pr_alert("judgm:PID %d  inode_readlink\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
/*static int hook_inode_follow_link(struct dentry *dentry,struct nameidata *nd){
  struct judgm_proc_info *info;

  info = judgm_proc_task_lookup(current);
  if(info == NULL){
  return ori_sops->inode_follow_link(dentry,nd);
  }

  pr_alert("judgm:PID %d  inode_follow_link\n",current->tgid);

  info->status = JUDGE_RF;
  send_sig(SIGKILL,current,0);
  return -EACCES;
  }*/
static int hook_inode_setattr(struct dentry *dentry,struct iattr *attr){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_setattr(dentry,attr);
    }

    pr_alert("judgm:PID %d  inode_setattr\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
/*static int hook_inode_getattr(struct vfsmount *mnt,struct dentry *dentry){
  struct judgm_proc_info *info;

  info = judgm_proc_task_lookup(current);
  if(info == NULL){
  return ori_sops->inode_getattr(mnt,dentry);
  }

  pr_alert("judgm:PID %d  inode_getattr\n",current->tgid);

  info->status = JUDGE_RF;
  send_sig(SIGKILL,current,0);
  return -EACCES;
  }*/
static int hook_inode_setxattr(struct dentry *dentry,const char *name,const void *value,size_t size,int flags){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_setxattr(dentry,name,value,size,flags);
    }

    pr_alert("judgm:PID %d  inode_setxattr\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_inode_getxattr(struct dentry *dentry,const char *name){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_getxattr(dentry,name);
    }

    pr_alert("judgm:PID %d  inode_getxattr\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_inode_listxattr(struct dentry *dentry){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_listxattr(dentry);
    }

    pr_alert("judgm:PID %d  inode_listxattr\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_inode_removexattr(struct dentry *dentry,const char *name){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_removexattr(dentry,name);
    }

    pr_alert("judgm:PID %d  inode_removexattr\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_inode_need_killpriv(struct dentry *dentry){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_need_killpriv(dentry);
    }

    pr_alert("judgm:PID %d  inode_need_killpriv\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_inode_killpriv(struct dentry *dentry){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_killpriv(dentry);
    }

    pr_alert("judgm:PID %d  inode_killpriv\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_inode_getsecurity(const struct inode *inode,const char *name,void **buffer,bool alloc){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_getsecurity(inode,name,buffer,alloc);
    }

    pr_alert("judgm:PID %d  inode_getsecurity\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_inode_setsecurity(struct inode *inode,const char *name,const void *value,size_t size,int flags){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_setsecurity(inode,name,value,size,flags);
    }

    pr_alert("judgm:PID %d  inode_setsecurity\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_inode_listsecurity(struct inode *inode,char *buffer,size_t buffer_size){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_listsecurity(inode,buffer,buffer_size);
    }

    pr_alert("judgm:PID %d  inode_listsecurity\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
/*static int hook_file_alloc_security(struct file *file){
  struct judgm_proc_info *info;

  info = judgm_proc_task_lookup(current);
  if(info == NULL){
  return ori_sops->file_alloc_security(file);
  }

  pr_alert("judgm:PID %d  file_alloc_security\n",current->tgid);

  info->status = JUDGE_RF;
  send_sig(SIGKILL,current,0);
  return -EACCES;
  }*/
static int hook_file_ioctl(struct file *file,unsigned int cmd,unsigned long arg){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->file_ioctl(file,cmd,arg);
    }

    pr_alert("judgm:PID %d  file_ioctl\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
/*static int hook_mmap_addr(unsigned long addr){
  struct judgm_proc_info *info;

  info = judgm_proc_task_lookup(current);
  if(info == NULL){
  return ori_sops->mmap_addr(addr);
  }

  pr_alert("judgm:PID %d  mmap_addr\n",current->tgid);

  info->status = JUDGE_RF;
  send_sig(SIGKILL,current,0);
  return -EACCES;
  }*/
/*static int hook_mmap_file(struct file *file,unsigned long reqprot,unsigned long prot,unsigned long flags){
  struct judgm_proc_info *info;

  info = judgm_proc_task_lookup(current);
  if(info == NULL){
  return ori_sops->mmap_file(file,reqprot,prot,flags);
  }

  pr_alert("judgm:PID %d  mmap_file\n",current->tgid);

  info->status = JUDGE_RF;
  send_sig(SIGKILL,current,0);
  return -EACCES;
  }*/
/*static int hook_file_mprotect(struct vm_area_struct *vma,unsigned long reqprot,unsigned long prot){
  struct judgm_proc_info *info;

  info = judgm_proc_task_lookup(current);
  if(info == NULL){
  return ori_sops->file_mprotect(vma,reqprot,prot);
  }

  pr_alert("judgm:PID %d  file_mprotect\n",current->tgid);

  info->status = JUDGE_RF;
  send_sig(SIGKILL,current,0);
  return -EACCES;
  }*/
static int hook_file_lock(struct file *file,unsigned int cmd){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->file_lock(file,cmd);
    }

    pr_alert("judgm:PID %d  file_lock\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_file_fcntl(struct file *file,unsigned int cmd,unsigned long arg){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->file_fcntl(file,cmd,arg);
    }

    pr_alert("judgm:PID %d  file_fcntl\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_file_set_fowner(struct file *file){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->file_set_fowner(file);
    }

    pr_alert("judgm:PID %d  file_set_fowner\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_file_send_sigiotask(struct task_struct *tsk,struct fown_struct *fown,int sig){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->file_send_sigiotask(tsk,fown,sig);
    }

    pr_alert("judgm:PID %d  file_send_sigiotask\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_file_receive(struct file *file){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->file_receive(file);
    }

    pr_alert("judgm:PID %d  file_receive\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_task_create(unsigned long clone_flags){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->task_create(clone_flags);
    }

    pr_alert("judgm:PID %d  task_create\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_cred_alloc_blank(struct cred *cred,gfp_t gfp){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->cred_alloc_blank(cred,gfp);
    }

    pr_alert("judgm:PID %d  cred_alloc_blank\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
/*static int hook_cred_prepare(struct cred *new,const struct cred *old,gfp_t gfp){
  struct judgm_proc_info *info;

  info = judgm_proc_task_lookup(current);
  if(info == NULL){
  return ori_sops->cred_prepare(new,old,gfp);
  }

  pr_alert("judgm:PID %d  cred_prepare\n",current->tgid);

  info->status = JUDGE_RF;
  send_sig(SIGKILL,current,0);
  return -EACCES;
  }*/
static int hook_kernel_act_as(struct cred *new,u32 secid){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->kernel_act_as(new,secid);
    }

    pr_alert("judgm:PID %d  kernel_act_as\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_kernel_create_files_as(struct cred *new,struct inode *inode){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->kernel_create_files_as(new,inode);
    }

    pr_alert("judgm:PID %d  kernel_create_files_as\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_kernel_module_request(char *kmod_name){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->kernel_module_request(kmod_name);
    }

    pr_alert("judgm:PID %d  kernel_module_request\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_task_fix_setuid(struct cred *new,const struct cred *old,int flags){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->task_fix_setuid(new,old,flags);
    }

    pr_alert("judgm:PID %d  task_fix_setuid\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_task_setpgid(struct task_struct *p,pid_t pgid){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->task_setpgid(p,pgid);
    }

    pr_alert("judgm:PID %d  task_setpgid\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_task_getpgid(struct task_struct *p){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->task_getpgid(p);
    }

    pr_alert("judgm:PID %d  task_getpgid\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_task_getsid(struct task_struct *p){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->task_getsid(p);
    }

    pr_alert("judgm:PID %d  task_getsid\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_task_setnice(struct task_struct *p,int nice){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->task_setnice(p,nice);
    }

    pr_alert("judgm:PID %d  task_setnice\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_task_setioprio(struct task_struct *p,int ioprio){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->task_setioprio(p,ioprio);
    }

    pr_alert("judgm:PID %d  task_setioprio\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_task_getioprio(struct task_struct *p){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->task_getioprio(p);
    }

    pr_alert("judgm:PID %d  task_getioprio\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_task_setrlimit(struct task_struct *p,unsigned int resource,struct rlimit *new_rlim){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->task_setrlimit(p,resource,new_rlim);
    }

    pr_alert("judgm:PID %d  task_setrlimit\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_task_setscheduler(struct task_struct *p){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->task_setscheduler(p);
    }

    pr_alert("judgm:PID %d  task_setscheduler\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_task_getscheduler(struct task_struct *p){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->task_getscheduler(p);
    }

    pr_alert("judgm:PID %d  task_getscheduler\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_task_movememory(struct task_struct *p){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->task_movememory(p);
    }

    pr_alert("judgm:PID %d  task_movememory\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_task_kill(struct task_struct *p,struct siginfo *siginfo,int sig,u32 secid){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->task_kill(p,siginfo,sig,secid);
    }

    pr_alert("judgm:PID %d  task_kill\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_task_wait(struct task_struct *p){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->task_wait(p);
    }

    pr_alert("judgm:PID %d  task_wait\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_task_prctl(int option,unsigned long arg2,unsigned long arg3,unsigned long arg4,unsigned long arg5){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->task_prctl(option,arg2,arg3,arg4,arg5);
    }

    pr_alert("judgm:PID %d  task_prctl\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_ipc_permission(struct kern_ipc_perm *ipcp,short flag){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->ipc_permission(ipcp,flag);
    }

    pr_alert("judgm:PID %d  ipc_permission\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_msg_msg_alloc_security(struct msg_msg *msg){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->msg_msg_alloc_security(msg);
    }

    pr_alert("judgm:PID %d  msg_msg_alloc_security\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_msg_queue_alloc_security(struct msg_queue *msq){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->msg_queue_alloc_security(msq);
    }

    pr_alert("judgm:PID %d  msg_queue_alloc_security\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_msg_queue_associate(struct msg_queue *msq,int msqflg){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->msg_queue_associate(msq,msqflg);
    }

    pr_alert("judgm:PID %d  msg_queue_associate\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_msg_queue_msgctl(struct msg_queue *msq,int cmd){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->msg_queue_msgctl(msq,cmd);
    }

    pr_alert("judgm:PID %d  msg_queue_msgctl\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_msg_queue_msgsnd(struct msg_queue *msq,struct msg_msg *msg,int msqflg){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->msg_queue_msgsnd(msq,msg,msqflg);
    }

    pr_alert("judgm:PID %d  msg_queue_msgsnd\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_msg_queue_msgrcv(struct msg_queue *msq,struct msg_msg *msg,struct task_struct *target,long type,int mode){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->msg_queue_msgrcv(msq,msg,target,type,mode);
    }

    pr_alert("judgm:PID %d  msg_queue_msgrcv\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_shm_alloc_security(struct shmid_kernel *shp){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->shm_alloc_security(shp);
    }

    pr_alert("judgm:PID %d  shm_alloc_security\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_shm_associate(struct shmid_kernel *shp,int shmflg){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->shm_associate(shp,shmflg);
    }

    pr_alert("judgm:PID %d  shm_associate\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_shm_shmctl(struct shmid_kernel *shp,int cmd){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->shm_shmctl(shp,cmd);
    }

    pr_alert("judgm:PID %d  shm_shmctl\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_shm_shmat(struct shmid_kernel *shp,char __user *shmaddr,int shmflg){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->shm_shmat(shp,shmaddr,shmflg);
    }

    pr_alert("judgm:PID %d  shm_shmat\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_sem_alloc_security(struct sem_array *sma){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->sem_alloc_security(sma);
    }

    pr_alert("judgm:PID %d  sem_alloc_security\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_sem_associate(struct sem_array *sma,int semflg){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->sem_associate(sma,semflg);
    }

    pr_alert("judgm:PID %d  sem_associate\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_sem_semctl(struct sem_array *sma,int cmd){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->sem_semctl(sma,cmd);
    }

    pr_alert("judgm:PID %d  sem_semctl\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_sem_semop(struct sem_array *sma,struct sembuf *sops,unsigned nsops,int alter){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->sem_semop(sma,sops,nsops,alter);
    }

    pr_alert("judgm:PID %d  sem_semop\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_netlink_send(struct sock *sk,struct sk_buff *skb){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->netlink_send(sk,skb);
    }

    pr_alert("judgm:PID %d  netlink_send\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_getprocattr(struct task_struct *p,char *name,char **value){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->getprocattr(p,name,value);
    }

    pr_alert("judgm:PID %d  getprocattr\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_setprocattr(struct task_struct *p,char *name,void *value,size_t size){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->setprocattr(p,name,value,size);
    }

    pr_alert("judgm:PID %d  setprocattr\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_secid_to_secctx(u32 secid,char **secdata,u32 *seclen){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->secid_to_secctx(secid,secdata,seclen);
    }

    pr_alert("judgm:PID %d  secid_to_secctx\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_secctx_to_secid(const char *secdata,u32 seclen,u32 *secid){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->secctx_to_secid(secdata,seclen,secid);
    }

    pr_alert("judgm:PID %d  secctx_to_secid\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_inode_notifysecctx(struct inode *inode,void *ctx,u32 ctxlen){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_notifysecctx(inode,ctx,ctxlen);
    }

    pr_alert("judgm:PID %d  inode_notifysecctx\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_inode_setsecctx(struct dentry *dentry,void *ctx,u32 ctxlen){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_setsecctx(dentry,ctx,ctxlen);
    }

    pr_alert("judgm:PID %d  inode_setsecctx\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_inode_getsecctx(struct inode *inode,void **ctx,u32 *ctxlen){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inode_getsecctx(inode,ctx,ctxlen);
    }

    pr_alert("judgm:PID %d  inode_getsecctx\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_unix_stream_connect(struct sock *sock,struct sock *other,struct sock *newsk){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->unix_stream_connect(sock,other,newsk);
    }

    pr_alert("judgm:PID %d  unix_stream_connect\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_unix_may_send(struct socket *sock,struct socket *other){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->unix_may_send(sock,other);
    }

    pr_alert("judgm:PID %d  unix_may_send\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_socket_create(int family,int type,int protocol,int kern){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->socket_create(family,type,protocol,kern);
    }

    pr_alert("judgm:PID %d  socket_create\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_socket_post_create(struct socket *sock,int family,int type,int protocol,int kern){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->socket_post_create(sock,family,type,protocol,kern);
    }

    pr_alert("judgm:PID %d  socket_post_create\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_socket_bind(struct socket *sock,struct sockaddr *address,int addrlen){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->socket_bind(sock,address,addrlen);
    }

    pr_alert("judgm:PID %d  socket_bind\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_socket_connect(struct socket *sock,struct sockaddr *address,int addrlen){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->socket_connect(sock,address,addrlen);
    }

    pr_alert("judgm:PID %d  socket_connect\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_socket_listen(struct socket *sock,int backlog){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->socket_listen(sock,backlog);
    }

    pr_alert("judgm:PID %d  socket_listen\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_socket_accept(struct socket *sock,struct socket *newsock){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->socket_accept(sock,newsock);
    }

    pr_alert("judgm:PID %d  socket_accept\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_socket_sendmsg(struct socket *sock,struct msghdr *msg,int size){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->socket_sendmsg(sock,msg,size);
    }

    pr_alert("judgm:PID %d  socket_sendmsg\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_socket_recvmsg(struct socket *sock,struct msghdr *msg,int size,int flags){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->socket_recvmsg(sock,msg,size,flags);
    }

    pr_alert("judgm:PID %d  socket_recvmsg\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_socket_getsockname(struct socket *sock){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->socket_getsockname(sock);
    }

    pr_alert("judgm:PID %d  socket_getsockname\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_socket_getpeername(struct socket *sock){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->socket_getpeername(sock);
    }

    pr_alert("judgm:PID %d  socket_getpeername\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_socket_getsockopt(struct socket *sock,int level,int optname){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->socket_getsockopt(sock,level,optname);
    }

    pr_alert("judgm:PID %d  socket_getsockopt\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_socket_setsockopt(struct socket *sock,int level,int optname){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->socket_setsockopt(sock,level,optname);
    }

    pr_alert("judgm:PID %d  socket_setsockopt\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_socket_shutdown(struct socket *sock,int how){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->socket_shutdown(sock,how);
    }

    pr_alert("judgm:PID %d  socket_shutdown\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_socket_sock_rcv_skb(struct sock *sk,struct sk_buff *skb){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->socket_sock_rcv_skb(sk,skb);
    }

    pr_alert("judgm:PID %d  socket_sock_rcv_skb\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_socket_getpeersec_stream(struct socket *sock,char __user *optval,int __user *optlen,unsigned len){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->socket_getpeersec_stream(sock,optval,optlen,len);
    }

    pr_alert("judgm:PID %d  socket_getpeersec_stream\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_socket_getpeersec_dgram(struct socket *sock,struct sk_buff *skb,u32 *secid){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->socket_getpeersec_dgram(sock,skb,secid);
    }

    pr_alert("judgm:PID %d  socket_getpeersec_dgram\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_sk_alloc_security(struct sock *sk,int family,gfp_t priority){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->sk_alloc_security(sk,family,priority);
    }

    pr_alert("judgm:PID %d  sk_alloc_security\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_inet_conn_request(struct sock *sk,struct sk_buff *skb,struct request_sock *req){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->inet_conn_request(sk,skb,req);
    }

    pr_alert("judgm:PID %d  inet_conn_request\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_secmark_relabel_packet(u32 secid){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->secmark_relabel_packet(secid);
    }

    pr_alert("judgm:PID %d  secmark_relabel_packet\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_tun_dev_create(void){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->tun_dev_create();
    }

    pr_alert("judgm:PID %d  tun_dev_create\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_tun_dev_attach(struct sock *sk){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->tun_dev_attach(sk);
    }

    pr_alert("judgm:PID %d  tun_dev_attach\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_key_alloc(struct key *key,const struct cred *cred,unsigned long flags){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->key_alloc(key,cred,flags);
    }

    pr_alert("judgm:PID %d  key_alloc\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_key_permission(key_ref_t key_ref,const struct cred *cred,key_perm_t perm){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->key_permission(key_ref,cred,perm);
    }

    pr_alert("judgm:PID %d  key_permission\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_key_getsecurity(struct key *key,char **_buffer){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->key_getsecurity(key,_buffer);
    }

    pr_alert("judgm:PID %d  key_getsecurity\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_audit_rule_init(u32 field,u32 op,char *rulestr,void **lsmrule){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->audit_rule_init(field,op,rulestr,lsmrule);
    }

    pr_alert("judgm:PID %d  audit_rule_init\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_audit_rule_known(struct audit_krule *krule){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->audit_rule_known(krule);
    }

    pr_alert("judgm:PID %d  audit_rule_known\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
static int hook_audit_rule_match(u32 secid,u32 field,u32 op,void *lsmrule,struct audit_context *actx){
    struct judgm_proc_info *info;

    info = judgm_proc_task_lookup(current);
    if(info == NULL){
	return ori_sops->audit_rule_match(secid,field,op,lsmrule,actx);
    }

    pr_alert("judgm:PID %d  audit_rule_match\n",current->tgid);

    info->status = JUDGE_RF;
    send_sig(SIGKILL,current,0);
    return -EACCES;
}
