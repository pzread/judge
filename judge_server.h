struct judge_server_queue{
    struct judge_server_queue *next;
    struct judge_server_queue *prev;
    int submitid;
    int proid;
};

struct judge_setting_info{
    int timelimit;
    int memlimit;
    int count;
    int score[64];
};

static void server_inihandler(void *data,char *section,char *key,char *value);
static void* server_thread(void *arg);
int judge_server();

static struct judge_server_queue server_queue_head;
static sem_t server_queue_sem;
static pthread_mutex_t server_queue_mutex;
