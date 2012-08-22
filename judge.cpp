#define UNICODE
#define DLL_NAME "judge-dll.dll"

#include<windows.h>
#include<psapi.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include"judge.h"

typedef HANDLE WINAPI (*FUNC_CreateJobObject)(LPSECURITY_ATTRIBUTES lpJobAttributes,LPCTSTR lpName);
typedef BOOL WINAPI (*FUNC_SetInformationJobObject)(HANDLE hJob,JOBOBJECTINFOCLASS JobObjectInfoClass,LPVOID lpJobObjectInfo,DWORD cbJobObjectInfoLength);
typedef BOOL WINAPI (*FUNC_AssignProcessToJobObject)(HANDLE hJob,HANDLE hProcess);
typedef BOOL WINAPI (*FUNC_ConvertStringSidToSid)(LPCTSTR StringSid,PSID *Sid);

#define TokenIntegrityLevel (TOKEN_INFORMATION_CLASS)25
typedef struct _TOKEN_MANDATORY_LABEL{
    SID_AND_ATTRIBUTES Label;
}TOKEN_MANDATORY_LABEL,*PTOKEN_MANDATORY_LABEL;


int Protect(HANDLE hProc,ULONG memlimit){
    HMODULE hKernel32;
    FUNC_CreateJobObject CreateJobObject;
    FUNC_SetInformationJobObject SetInformationJobObject;
    FUNC_AssignProcessToJobObject AssignProcessToJobObject;
    FUNC_ConvertStringSidToSid ConvertStringSidToSid;

    HANDLE hJob;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION JELI;
    JOBOBJECT_BASIC_UI_RESTRICTIONS JBUR;
    PSID pSID;
    TOKEN_MANDATORY_LABEL TML;
    HANDLE hToken;

    hKernel32 = GetModuleHandle(L"kernel32.dll");
    CreateJobObject = (FUNC_CreateJobObject)GetProcAddress(hKernel32,"CreateJobObjectW");
    SetInformationJobObject = (FUNC_SetInformationJobObject)GetProcAddress(hKernel32,"SetInformationJobObject");
    AssignProcessToJobObject = (FUNC_AssignProcessToJobObject)GetProcAddress(hKernel32,"AssignProcessToJobObject");
    ConvertStringSidToSid = (FUNC_ConvertStringSidToSid)GetProcAddress(GetModuleHandle(L"advapi32.dll"),"ConvertStringSidToSidW");

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

    OpenProcessToken(hProc,TOKEN_ALL_ACCESS,&hToken);
    AdjustTokenPrivileges(hToken,TRUE,NULL,0,NULL,NULL);

    ConvertStringSidToSid(L"S-1-16-0",&pSID);
    TML.Label.Sid = pSID;
    TML.Label.Attributes = SE_GROUP_INTEGRITY;
    SetTokenInformation(hToken,TokenIntegrityLevel,&TML,sizeof(TOKEN_MANDATORY_LABEL) + GetLengthSid(pSID));

    LocalFree(pSID);
    CloseHandle(hToken);

    return 0;
}

typedef struct{
    ULONG timestart;
    ULONG timeend;
    ULONG timelimit;
    ULONG memlimit;
    ULONG state;
}JUDGE_INFO,*PJUDGE_INFO;
JUDGE_INFO judgeInfo;

HANDLE hAnsFile;
HANDLE hInPipe;
char buffer[65536];
char ansBuffer[65536];

DWORD WINAPI IoThread(LPVOID lpParameter){
    ULONG rl;
    ULONG ansrl;
    ULONG outrl;
    bool overFlag;

    HANDLE hOutFile;

    hOutFile = CreateFileA("procout.txt",
	    GENERIC_WRITE,
	    0,
	    NULL,
	    CREATE_ALWAYS,
	    0,
	    NULL);

    overFlag = false;
    while(true){
	if(ReadFile(hInPipe,buffer,65536,&rl,NULL) == false){
	    break;
	}
	if(overFlag == true){
	    continue;
	}

	WriteFile(hOutFile,buffer,rl,&outrl,NULL);

	ReadFile(hAnsFile,ansBuffer,rl,&ansrl,NULL);
	if(rl != ansrl){
	    overFlag = true;
	}

	if(memcmp(buffer,ansBuffer,ansrl) != 0){
	    overFlag = true;
	}
    }

    CloseHandle(hOutFile);

    if(SetFilePointer(hAnsFile,0,NULL,FILE_CURRENT) != SetFilePointer(hAnsFile,0,NULL,FILE_END)){
	overFlag = true;
    }

    if(overFlag == true && judgeInfo.state <= JUDGE_STATE_AC){
	judgeInfo.state = JUDGE_STATE_WA;
    }

    return 0;
}

int RF_Patch(HANDLE hProc){
    int i,j;

    HMODULE hNtDll;
    ULONG base;
    PIMAGE_OPTIONAL_HEADER pIOH;
    PIMAGE_EXPORT_DIRECTORY pIED;
    PULONG rvaList;
    char *name;
    int flag;

    hNtDll = GetModuleHandle(L"ntdll.dll");
    base = (ULONG)hNtDll;

    pIOH = &((PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew))->OptionalHeader;
    pIED = (PIMAGE_EXPORT_DIRECTORY)(base + pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress); 

    int tmp=0;

    rvaList = (PULONG)(base + pIED->AddressOfNames);
    for(i = 0;i < pIED->NumberOfNames;i++){
	name = (char*)(base + rvaList[i]);
	if(name[0] == 'Z' && name[1] == 'w'){
	    printf("%s %08x\n",name,(ULONG)GetProcAddress(hNtDll,name));
	}
    }

    return 0;
}

int main(int argc,char *args[]){
    SECURITY_ATTRIBUTES sa;
    HANDLE hFile;
    HANDLE hOutPipe;
    HANDLE hIoThread;

    STARTUPINFOA stInfo;
    PROCESS_INFORMATION procInfo;
    DEBUG_EVENT dbgEvent;

    PVOID rDllName;
    WCHAR ComEventName[128];
    HANDLE hComEvent;
    WCHAR ComMapName[128];
    HANDLE hComMap;
    PULONG pDllState;

    int timeoutCount;
    PROCESS_MEMORY_COUNTERS memInfo;

    if(argc != 6){
	printf("name.exe time(ms) mem(KB) inputfile ansfile\n");
	return 0;
    }

    judgeInfo.timelimit = atoi(args[2]);
    judgeInfo.memlimit = atoi(args[3]) * 1024;

    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    hFile = CreateFileA(args[4],
	    GENERIC_READ,
	    0,
	    &sa,
	    OPEN_EXISTING,
	    0,
	    NULL);

    hAnsFile = CreateFileA(args[5],
	    GENERIC_READ,
	    0,
	    NULL,
	    OPEN_EXISTING,
	    0,
	    NULL);

    CreatePipe(&hInPipe,&hOutPipe,&sa,65536);

    memset(&stInfo,0,sizeof(STARTUPINFO));
    stInfo.cb = sizeof(STARTUPINFO);
    stInfo.dwFlags = STARTF_USESTDHANDLES;
    stInfo.hStdInput = hFile;
    stInfo.hStdOutput = hOutPipe;
    stInfo.hStdError = hOutPipe;
    CreateProcessA(args[1],
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

    wsprintf(ComEventName,L"JUDGE_COMEVENT_%u",procInfo.dwProcessId);
    hComEvent = CreateEvent(NULL,FALSE,FALSE,ComEventName);
    wsprintf(ComMapName,L"JUDGE_COMMAP_%u",procInfo.dwProcessId);
    hComMap = CreateFileMapping(NULL,NULL,PAGE_READWRITE,0,sizeof(JUDGE_INFO),ComMapName);
    pDllState = (PULONG)MapViewOfFile(hComMap,FILE_MAP_ALL_ACCESS,0,0,sizeof(ULONG));

    judgeInfo.timestart = 0;
    judgeInfo.state = JUDGE_STATE_AC;
    *pDllState = JUDGE_STATE_RE;

    rDllName = VirtualAllocEx(procInfo.hProcess,NULL,strlen(DLL_NAME) + 1,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
    WriteProcessMemory(procInfo.hProcess,rDllName,DLL_NAME,strlen(DLL_NAME) + 1,NULL);
    CreateRemoteThread(procInfo.hProcess,
	    NULL,
	    0,
	    (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"),"LoadLibraryA"),
	    rDllName,
	    0,
	    NULL);

    hIoThread = CreateThread(NULL,0,IoThread,NULL,0,NULL);
    WaitForSingleObject(hComEvent,INFINITE);
    Protect(procInfo.hProcess,judgeInfo.memlimit + 32 * 1024);
    judgeInfo.timestart = GetTickCount();

    ResumeThread(procInfo.hThread);

    WaitForSingleObject(procInfo.hProcess,judgeInfo.timelimit + 100);
    judgeInfo.timeend = GetTickCount();
    TerminateProcess(procInfo.hProcess,0);
    CloseHandle(hOutPipe);
    WaitForSingleObject(hIoThread,INFINITE);

    if(*pDllState != JUDGE_STATE_AC){
	judgeInfo.state = *pDllState;
    }else if((judgeInfo.timeend - judgeInfo.timestart) > judgeInfo.timelimit){
	judgeInfo.state = JUDGE_STATE_TLE;
    }
    GetProcessMemoryInfo(procInfo.hProcess,&memInfo,sizeof(PROCESS_MEMORY_COUNTERS));
    if(memInfo.PeakPagefileUsage > judgeInfo.memlimit){
	judgeInfo.state = JUDGE_STATE_MLE;
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
