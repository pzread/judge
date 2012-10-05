struct judge_submit_info{
    struct judge_submit_info *next;
    struct judge_submit_info *prev;

    int submitid;
    int proid;
    int state[JUDGE_SET_COUNTMAX];
    int score[JUDGE_SET_COUNTMAX];
    unsigned long runtime[JUDGE_SET_COUNTMAX];
    unsigned long peakmem[JUDGE_SET_COUNTMAX];
};
struct judge_setting_info{
    unsigned long timelimit;
    unsigned long memlimit;
    int count;
    int score[JUDGE_SET_COUNTMAX];
};

static void server_inihandler(void *data,char *section,char *key,char *value);
static int server_compile(char *cpppath,char *exepath);
static int server_updatedb(struct judge_submit_info *submit_info,struct judge_setting_info *setting_info);
static void* server_thread(void *arg);
int judge_server();

static struct judge_submit_info server_queue_head;
static sem_t server_queue_sem;
static pthread_mutex_t server_queue_mutex;

extern struct judge_proc_info* judge_proc_create(char *abspath,char *path,char *sopath,unsigned long timelimit,unsigned long memlimit);
extern int judge_proc_free(struct judge_proc_info *proc_info);
extern int judge_proc_run(struct judge_proc_info *proc_info);
