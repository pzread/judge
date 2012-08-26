#define UNICODE

#include<windows.h>
#include<psapi.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include"judge.h"

typedef HANDLE WINAPI (*FUNC_CreateJobObject)(LPSECURITY_ATTRIBUTES lpJobAttributes,LPCTSTR lpName);
typedef BOOL WINAPI (*FUNC_SetInformationJobObject)(HANDLE hJob,JOBOBJECTINFOCLASS JobObjectInfoClass,LPVOID lpJobObjectInfo,DWORD cbJobObjectInfoLength);
typedef BOOL WINAPI (*FUNC_AssignProcessToJobObject)(HANDLE hJob,HANDLE hProcess);
typedef BOOL WINAPI (*FUNC_ConvertSidToStringSid)(PSID Sid,LPTSTR *StringSid);
typedef BOOL WINAPI (*FUNC_ConvertStringSidToSid)(LPCTSTR StringSid,PSID *Sid);
typedef BOOL WINAPI (*FUNC_CreateRestrictedToken)(HANDLE ExistingTokenHandle,DWORD Flags,DWORD DisableSidCount,PSID_AND_ATTRIBUTES SidsToDisable,DWORD DeletePrivilegeCount,PLUID_AND_ATTRIBUTES PrivilegesToDelete,DWORD RestrictedSidCount,PSID_AND_ATTRIBUTES SidsToRestrict,PHANDLE NewTokenHandle);

typedef struct{
    ULONG timestart;
    ULONG timeend;
    ULONG timelimit;
    ULONG memlimit;
    ULONG state;
}JUDGE_INFO,*PJUDGE_INFO;
JUDGE_INFO judgeInfo;

#define TokenIntegrityLevel (TOKEN_INFORMATION_CLASS)25
typedef struct _TOKEN_MANDATORY_LABEL{
    SID_AND_ATTRIBUTES Label;
}TOKEN_MANDATORY_LABEL,*PTOKEN_MANDATORY_LABEL;

#define TokenUser (TOKEN_INFORMATION_CLASS)1 
#define TokenGroups (TOKEN_INFORMATION_CLASS)2 
#define TokenLogonSid (TOKEN_INFORMATION_CLASS)28 
#define DISABLE_MAX_PRIVILEGE 1

HANDLE Create_Token(){
    HMODULE hAdvapi32;
    FUNC_ConvertSidToStringSid ConvertSidToStringSid;
    FUNC_ConvertStringSidToSid ConvertStringSidToSid;
    FUNC_CreateRestrictedToken CreateRestrictedToken;

    int i,j;
    ULONG ret;

    HANDLE hOriToken;
    HANDLE hToken;
    PSID_AND_ATTRIBUTES pSID_ATTR;
    PTOKEN_GROUPS pTokenGroup;
    PTOKEN_USER pTokenUser;
    PWCHAR pSIDStr;
    PSID pSID;
    TOKEN_MANDATORY_LABEL TML;

    hAdvapi32 = GetModuleHandle(L"advapi32.dll");
    ConvertSidToStringSid = (FUNC_ConvertSidToStringSid)GetProcAddress(hAdvapi32,"ConvertSidToStringSidW");
    ConvertStringSidToSid = (FUNC_ConvertStringSidToSid)GetProcAddress(hAdvapi32,"ConvertStringSidToSidW");
    CreateRestrictedToken = (FUNC_CreateRestrictedToken)GetProcAddress(hAdvapi32,"CreateRestrictedToken");

    OpenProcessToken(GetCurrentProcess(),TOKEN_ALL_ACCESS,&hOriToken);
    DuplicateTokenEx(hOriToken,0,NULL,SecurityImpersonation,TokenPrimary,&hToken);

    GetTokenInformation(hOriToken,TokenGroups,NULL,0,&ret); 
    pTokenGroup = (PTOKEN_GROUPS)malloc(ret);
    GetTokenInformation(hOriToken,TokenGroups,pTokenGroup,ret,&ret); 
    pSID_ATTR = (PSID_AND_ATTRIBUTES)malloc(sizeof(SID_AND_ATTRIBUTES) * (pTokenGroup->GroupCount + 1));
    j = 0;
    for(i = 0;i < pTokenGroup->GroupCount;i++){
	ConvertSidToStringSid(pTokenGroup->Groups[i].Sid,&pSIDStr);
	if(wcscmp(pSIDStr,L"S-1-1-0") != 0){
	    memcpy(&pSID_ATTR[j],&pTokenGroup->Groups[i],sizeof(SID_AND_ATTRIBUTES));
	    j++;
	}
	LocalFree(pSIDStr);
    }
    free(pTokenGroup);

    GetTokenInformation(hOriToken,TokenUser,NULL,0,&ret); 
    pTokenUser = (PTOKEN_USER)malloc(ret);
    GetTokenInformation(hOriToken,TokenUser,pTokenUser,ret,&ret); 
    memcpy(&pSID_ATTR[j],&pTokenUser->User,sizeof(SID_AND_ATTRIBUTES));
    j++;

    pTokenUser->User.Attributes = SE_GROUP_USE_FOR_DENY_ONLY;
    SetTokenInformation(hOriToken,TokenUser,pTokenUser,ret); 

    free(pTokenUser);

    CreateRestrictedToken(hOriToken,DISABLE_MAX_PRIVILEGE,j,pSID_ATTR,0,NULL,0,NULL,&hToken);
    free(pSID_ATTR);

    ConvertStringSidToSid(L"S-1-16-4096",&pSID);
    TML.Label.Sid = pSID;
    TML.Label.Attributes = SE_GROUP_INTEGRITY;
    SetTokenInformation(hToken,TokenIntegrityLevel,&TML,sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pSID));
    LocalFree(pSID);

    return hToken;
}
int Create_Com(char *inFile,PHANDLE phIn,PHANDLE phOut,PHANDLE phComEvent,PHANDLE phComMap,PULONG *ppDllState){
    SECURITY_ATTRIBUTES sa;

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    *phIn = CreateFileA(inFile,
	    GENERIC_READ,
	    0,
	    &sa,
	    OPEN_EXISTING,
	    0,
	    NULL);
    *phOut = CreateFileA("procout.txt",
	    GENERIC_WRITE,
	    0,
	    &sa,
	    CREATE_ALWAYS,
	    0,
	    NULL);
    *phComEvent = CreateEvent(&sa,FALSE,FALSE,NULL);
    *phComMap = CreateFileMapping(NULL,&sa,PAGE_READWRITE,0,sizeof(JUDGE_INFO),NULL);
    *ppDllState = (PULONG)MapViewOfFile(*phComMap,FILE_MAP_ALL_ACCESS,0,0,sizeof(ULONG));

    return 0;
}
int Init_Hook(HANDLE hProc,HANDLE hComEvent,HANDLE hComMap){
    ULONG ret;

    JUDGE_DLL_INFO dllInfo;
    PVOID addr;
    PVOID rDllName;

    dllInfo.hComEvent = hComEvent;
    dllInfo.hComMap = hComMap;
    addr = (PVOID)((ULONG)GetModuleHandle(L"ntdll.dll") + sizeof(IMAGE_DOS_HEADER));
    VirtualProtectEx(hProc,addr,sizeof(JUDGE_DLL_INFO),PAGE_READWRITE,&ret);
    WriteProcessMemory(hProc,addr,&dllInfo,sizeof(JUDGE_DLL_INFO),NULL);

    rDllName = VirtualAllocEx(hProc,NULL,strlen(DLL_NAME) + 1,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
    WriteProcessMemory(hProc,rDllName,DLL_NAME,strlen(DLL_NAME) + 1,NULL);
    CreateRemoteThread(hProc,
	    NULL,
	    0,
	    (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"),"LoadLibraryA"),
	    rDllName,
	    0,
	    NULL);

    return 0;
}
int Protect(HANDLE hProc,ULONG memlimit){
    HMODULE hKernel32;
    FUNC_CreateJobObject CreateJobObject;
    FUNC_SetInformationJobObject SetInformationJobObject;
    FUNC_AssignProcessToJobObject AssignProcessToJobObject;

    HANDLE hJob;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION JELI;
    JOBOBJECT_BASIC_UI_RESTRICTIONS JBUR;

    hKernel32 = GetModuleHandle(L"kernel32.dll");
    CreateJobObject = (FUNC_CreateJobObject)GetProcAddress(hKernel32,"CreateJobObjectW");
    SetInformationJobObject = (FUNC_SetInformationJobObject)GetProcAddress(hKernel32,"SetInformationJobObject");
    AssignProcessToJobObject = (FUNC_AssignProcessToJobObject)GetProcAddress(hKernel32,"AssignProcessToJobObject");

    hJob = CreateJobObject(NULL,NULL);

    JELI.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_PROCESS_MEMORY; 
    JELI.BasicLimitInformation.ActiveProcessLimit = 1;
    JELI.ProcessMemoryLimit = memlimit;

    JBUR.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS | JOB_OBJECT_UILIMIT_EXITWINDOWS | JOB_OBJECT_UILIMIT_GLOBALATOMS | JOB_OBJECT_UILIMIT_HANDLES | JOB_OBJECT_UILIMIT_READCLIPBOARD | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS | JOB_OBJECT_UILIMIT_WRITECLIPBOARD;

    SetInformationJobObject(hJob,
	    JobObjectExtendedLimitInformation,
	    &JELI,
	    sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
    SetInformationJobObject(hJob,
	    JobObjectBasicUIRestrictions,
	    &JBUR,
	    sizeof(JOBOBJECT_BASIC_UI_RESTRICTIONS));
    AssignProcessToJobObject(hJob,hProc);

    return 0;
}
int Check(const char *outFile,const char *ansFile){
    int i;
    int ret;
    
    FILE *out;
    FILE *ans;
    void *outBuf;
    void *ansBuf;
    int flag;

    out = fopen(outFile,"r");
    ans = fopen(ansFile,"r");
    outBuf = malloc(4096);
    ansBuf = malloc(4096);

    flag = 0;
    while(!feof(out) && !feof(ans)){
	ret = fread(outBuf,1,4096,out);
	if(ret != fread(ansBuf,1,4096,ans)){
	    flag = 1;
	    break;
	}
	if(memcmp(outBuf,ansBuf,ret)){
	    flag = 1;
	    break;
	}
    }

    fclose(out);
    fclose(ans);

    if(flag != 0){
	return 0;
    }
    return 1;
}

int main(int argc,char *args[]){
    int i;
    ULONG ret;

    HANDLE hToken;
    HANDLE hIn;
    HANDLE hOut;
    HANDLE hComEvent;
    HANDLE hComMap;
    PULONG pDllState; 

    STARTUPINFOA stInfo;
    PROCESS_INFORMATION procInfo;

    PROCESS_MEMORY_COUNTERS memInfo;

    if(argc != 6){
	printf("name.exe time(ms) mem(KB) inputfile ansfile\n");
	return 0;
    }

    hToken = Create_Token();
    Create_Com(args[4],&hIn,&hOut,&hComEvent,&hComMap,&pDllState);

    judgeInfo.timelimit = atoi(args[2]);
    judgeInfo.memlimit = atoi(args[3]) * 1024;
    judgeInfo.state = JUDGE_STATE_AC;
    *pDllState = JUDGE_STATE_RE;

    memset(&stInfo,0,sizeof(STARTUPINFO));
    stInfo.cb = sizeof(STARTUPINFO);
    stInfo.dwFlags = STARTF_USESTDHANDLES;
    stInfo.hStdInput = hIn;
    stInfo.hStdOutput = hOut;
    stInfo.hStdError = hOut;
    CreateProcessAsUserA(hToken,
	    args[1],
	    NULL,
	    NULL,
	    NULL,
	    TRUE,
	    CREATE_BREAKAWAY_FROM_JOB | CREATE_SUSPENDED,
	    NULL,
	    NULL,
	    &stInfo,
	    &procInfo);

    printf("PID:%d\n\n",procInfo.dwProcessId);

    Init_Hook(procInfo.hProcess,hComEvent,hComMap);
    WaitForSingleObject(hComEvent,INFINITE);
    Protect(procInfo.hProcess,judgeInfo.memlimit + 32 * 1024);
    judgeInfo.timestart = GetTickCount();

    ResumeThread(procInfo.hThread);

    WaitForSingleObject(procInfo.hProcess,judgeInfo.timelimit + 100);
    judgeInfo.timeend = GetTickCount();
    TerminateProcess(procInfo.hProcess,0);
    CloseHandle(hIn);
    CloseHandle(hOut);

    judgeInfo.state = *pDllState;
    if((judgeInfo.timeend - judgeInfo.timestart) > judgeInfo.timelimit){
	judgeInfo.state = JUDGE_STATE_TLE;
    }
    GetProcessMemoryInfo(procInfo.hProcess,&memInfo,sizeof(PROCESS_MEMORY_COUNTERS));
    if(memInfo.PeakPagefileUsage > judgeInfo.memlimit){
	judgeInfo.state = JUDGE_STATE_MLE;
    }

    if(judgeInfo.state == JUDGE_STATE_AC){
	if(!Check("procout.txt",args[5])){
	    judgeInfo.state = JUDGE_STATE_WA;
	}
    }

    printf("Time: %lums\n",judgeInfo.timeend - judgeInfo.timestart);
    printf("Memory: %dKB\n",(memInfo.PeakPagefileUsage / 1024));

    if(judgeInfo.state == JUDGE_STATE_AC){
	printf("Status: AC\n");
    }else if(judgeInfo.state == JUDGE_STATE_WA){
	printf("Status: WA\n");
    }else if(judgeInfo.state == JUDGE_STATE_TLE){
	printf("Status: TLE\n");
    }else if(judgeInfo.state == JUDGE_STATE_RF){
	printf("Status: RF\n");
    }else if(judgeInfo.state == JUDGE_STATE_RE){
	printf("Status: RE\n");
    }else if(judgeInfo.state == JUDGE_STATE_MLE){
	printf("Status: MLE\n");
    }

    return 0;
}
