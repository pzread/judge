#ifndef _TASK_H
#define _TASK_H

#include<signal.h>
#include<sys/types.h>
#include<linux/taskstats.h>

#undef RLIM_NLIMITS
#define RLIM_NLIMITS 18

struct taskstats_ex {
    struct taskstats stats;
    uint64_t rlim_exceed[RLIM_NLIMITS];
};

struct task{
    unsigned long refcount;
    pid_t pid;

    void (*sig_handler)(struct task *task,siginfo_t *siginfo);
    void (*stat_handler)(struct task *task,const struct taskstats_ex *statex);

    void *private;
};

int task_init(void);
struct task* task_alloc(pid_t pid);
int task_get(struct task *task);
int task_put(struct task *task);
struct task* task_getby_pid(pid_t pid);

#endif
