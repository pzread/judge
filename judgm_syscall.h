static int syscall_init_hook(void);

static unsigned long* syscall_table;
static unsigned int syscall_max;
static atomic64_t syscall_pending;

int judgm_syscall_hook(void);
int judgm_syscall_unhook(void);
int judgm_syscall_check(void);
int judgm_syscall_block(void);

unsigned long *judgm_syscall_ori_table;

extern struct judgm_proc_info* judgm_proc_task_lookup(struct task_struct *task);
extern long hook_sys_block(void);

typedef asmlinkage long (*func_sys_nanosleep)(struct timespec __user *rqtp,struct timespec __user *rmtp);
func_sys_nanosleep ori_sys_nanosleep;
asmlinkage long hook_sys_nanosleep(struct timespec __user *rqtp,struct timespec __user *rmtp);
