#define DLL_PUBLIC __attribute__ ((visibility ("default")))

struct judgx_proc_info{
    int status;
    unsigned long runtime;
    unsigned long peakmem;

    char exe_path[PATH_MAX + 1];
    char exe_name[NAME_MAX + 1];
    unsigned long pid; 
    unsigned long task;

    unsigned long timelimit;
    unsigned long memlimit;
};

typedef void (*judgx_ini_handler)(void *data,char *section,char *key,char *value);
typedef void (*judgx_check_run_fn)(void *data);

extern int judgx_ini_load(FILE *f,judgx_ini_handler handler,void *data);
extern int judgx_compile(char *cpppath,char *exepath,char *arg);
extern struct judgx_proc_info* judgx_proc_create(char *exepath,unsigned long timelimit,unsigned long memlimit);
extern int judgx_proc_free(struct judgx_proc_info *proc_info);
extern int judgx_proc_run(struct judgx_proc_info *proc_info,judgx_check_run_fn check_run,void *check_data);
