static int __init mod_init(void);
static void __exit mod_exit(void);
static long mod_ioctl(struct file *file,unsigned int cmd,unsigned long arg);

static dev_t mod_dev;
static struct cdev mod_cdev;
static struct class *mod_class;
static struct file_operations mod_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = mod_ioctl
};

extern int judgm_proc_init(void);
extern int judgm_proc_add(unsigned long arg);
extern int judgm_proc_get(unsigned long arg);
extern int judgm_proc_del(unsigned long arg);
extern int judgm_syscall_hook(void);
extern int judgm_syscall_unhook(void);
extern int judgm_security_hook(void);
extern int judgm_security_unhook(void);
