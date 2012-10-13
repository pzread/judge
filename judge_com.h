#define JUDGE_AC 0
#define JUDGE_WA 1
#define JUDGE_TLE 2
#define JUDGE_MLE 3
#define JUDGE_RF 4
#define JUDGE_RE 5
#define JUDGE_CE 6
#define JUDGE_ERR 7

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
