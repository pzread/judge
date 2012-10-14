#define SYSCALL_WHITELIST_SIZE 41

static int syscall_init_hook(void);
static int syscall_whitelist_cmp(const void *a,const void *b);

static unsigned long* syscall_table;
static unsigned int syscall_max;
static unsigned int syscall_whitelist[SYSCALL_WHITELIST_SIZE] = {
    __NR_execve,
    __NR_open,
    __NR_creat,
    __NR_unlink,
    __NR_access,
    __NR_truncate,
    __NR_stat,
    __NR_lstat,
    __NR_readlink,
    __NR_exit,
    __NR_read,
    __NR_write,
    __NR_close,
    __NR_lseek,
    __NR_getpid,
    __NR_getuid,
    __NR_dup,
    __NR_brk,
    __NR_getgid,
    __NR_geteuid,
    __NR_getegid,
    __NR_dup2,
    __NR_ftruncate,
    __NR_fstat,
    __NR_personality,
    __NR_readv,
    __NR_writev,
    __NR_getresuid,
    __NR_pread64,
    __NR_pwrite64,
    __NR_fcntl,
    __NR_mmap,
    __NR_munmap,
    __NR_ioctl,
    __NR_uname,
    __NR_gettid,
    __NR_set_thread_area,
    __NR_get_thread_area,
    __NR_set_tid_address,
    __NR_exit_group,
    __NR_arch_prctl
};

int judgm_syscall_hook(void);
int judgm_syscall_unhook(void);
int judgm_syscall_check(void);
int judgm_syscall_block(void);

unsigned long *judgm_syscall_ori_table;

extern struct judgm_proc_info* judgm_proc_task_lookup(struct task_struct *task);
extern long hook_sys_block(void);

//typedef asmlinkage long (*func_sys_nanosleep)(struct timespec __user *rqtp,struct timespec __user *rmtp);
//func_sys_nanosleep ori_sys_nanosleep;
//asmlinkage long hook_sys_nanosleep(struct timespec __user *rqtp,struct timespec __user *rmtp);
