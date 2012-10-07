#define IOCTL_PROC_ADD _IOWR('x',0x0,int)
#define IOCTL_PROC_GET _IOWR('x',0x1,int)
#define IOCTL_PROC_DEL _IOR('x',0x2,int)

struct judge_com_proc_add{
    char path[PATH_MAX + 1];
    unsigned long pid;
    unsigned long task;
    unsigned long memlimit;
};
struct judge_com_proc_get{
    unsigned long task;
    int status;
    unsigned long runtime;
    unsigned long peakmem;
};
