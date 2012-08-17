#define JUDGE_STATE_RUN 0x0
#define JUDGE_STATE_AC 0x1
#define JUDGE_STATE_WA 0x2
#define JUDGE_STATE_TLE 0x3
#define JUDGE_STATE_RF 0x4
#define JUDGE_STATE_RE 0x5
#define JUDGE_STATE_MLE 0x6

typedef struct{
    ULONG timestart;
    ULONG timeend;
    ULONG timelimit;
    int state;
}JUDGE_INFO,*PJUDGE_INFO;
