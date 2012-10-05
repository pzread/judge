#define JUDGE_ERR -1
#define JUDGE_AC 0
#define JUDGE_WA 1
#define JUDGE_TLE 2
#define JUDGE_MLE 3
#define JUDGE_RF 4
#define JUDGE_RE 5
#define JUDGE_CE 6

#define JUDGE_SET_COUNTMAX 64

#define JUDGE_DB_STATEMAX 1024
#define JUDGE_DB_SCOREMAX 1024
#define JUDGE_DB_RUNTIMEMAX 1024
#define JUDGE_DB_PEAKMEMMAX 1024

struct judge_proc_info{
    int state;
    char path[PATH_MAX + 1];
    char name[NAME_MAX + 1];
    unsigned long pid; 
    unsigned long task;
    struct judge_check_info *check_info;

    unsigned long timelimit;
    unsigned long memlimit;
    unsigned long runtime;
    unsigned long peakmem;
};

