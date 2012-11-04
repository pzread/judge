typedef int (*line_run_fn)(struct judgx_line_info *line_info);

struct judge_submit_info{
    struct judge_submit_info *next;
    struct judge_submit_info *prev;

    int submitid;
    int proid;
};

static int server_updatedb(PGconn *sqlc,int submitid,int result_count,struct judgx_line_result *result);
static void* server_thread(void *arg);

static struct judge_submit_info server_queue_head;
static sem_t server_queue_sem;
static pthread_mutex_t server_queue_mutex;

int judge_server();

extern struct judge_proc_info* judge_proc_create(char *abspath,char *path,char *sopath,unsigned long timelimit,unsigned long memlimit);
extern int judge_proc_free(struct judge_proc_info *proc_info);
extern int judge_proc_run(struct judge_proc_info *proc_info);
