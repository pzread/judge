#define DLL_NAME "judge-dll.dll"
#define L_DLL_NAME L"judge-dll.dll"

#define JUDGE_STATE_AC 0x1
#define JUDGE_STATE_WA 0x2
#define JUDGE_STATE_TLE 0x3
#define JUDGE_STATE_RF 0x4
#define JUDGE_STATE_RE 0x5
#define JUDGE_STATE_MLE 0x6

typedef struct{
    HANDLE hComEvent;
    HANDLE hComMap;
}JUDGE_DLL_INFO,*PJUDGE_DLL_INFO;
