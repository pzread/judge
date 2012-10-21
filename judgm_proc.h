#define PROC_TASK_HTSIZE 1009

static int proc_get_path(char *in_path,char *real_path);
static int proc_close_fd(struct task_struct *task);

static struct hlist_head *proc_task_ht;
static DEFINE_SPINLOCK(proc_task_htlock);
static struct kmem_cache *proc_info_cachep;

int judgm_proc_init(void);
int judgm_proc_add(unsigned long arg);
int judgm_proc_get(unsigned long arg);
int judgm_proc_del(unsigned long arg);
struct judgm_proc_info* judgm_proc_task_lookup(struct task_struct *task);
