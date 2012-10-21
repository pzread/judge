struct judgm_proc_info{
    struct hlist_node node;

    struct task_struct *task;
    struct file *pin;
    struct file *pout;
    char path[PATH_MAX + 1];
    int status;
    unsigned long memlimit;
    unsigned long peakmem;
};
