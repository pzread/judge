typedef int (*check_init)(char *abspath,void **data);
typedef int (*check_run)(void*);
typedef int (*check_post)(void*);
typedef int (*check_clean)(void*);
struct judge_check_info{
    char sopath[PATH_MAX + 1];
    void *sohandle;
    check_init init_fn;
    check_run run_fn;
    check_post post_fn;
    check_clean clean_fn;

    void *data;
};

struct judge_proc_info* judge_proc_create(char *abspath,char *path,char *sopath,unsigned long timelimit,unsigned long memlimit);
int judge_proc_free(struct judge_proc_info *proc_info);
static int proc_protect(struct judge_proc_info *proc_info);
int judge_proc_run(struct judge_proc_info *proc_info);

extern int judge_modfd;
