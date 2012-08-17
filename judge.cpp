#define UNICODE
#define DLL_NAME "judge-dll.dll"

#include<windows.h>
#include<psapi.h>
#include<tlhelp32.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include"judge.h"

int Crash_Clean(){
    HANDLE hSnap;
    PROCESSENTRY32 entry;
    HANDLE hProc;

    hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    entry.dwSize = sizeof(PROCESSENTRY32);
    Process32First(hSnap,&entry);
    do{
	if(wcscmp(entry.szExeFile,L"WerFault.exe") == 0){
	    hProc = OpenProcess(PROCESS_TERMINATE,FALSE,entry.th32ProcessID);
	    TerminateProcess(hProc,0);
	    CloseHandle(hProc);
	}
    }while(Process32Next(hSnap,&entry));

    return 0;
}

typedef HANDLE WINAPI (*FUNC_CreateJobObject)(LPSECURITY_ATTRIBUTES lpJobAttributes,LPCTSTR lpName);
typedef BOOL WINAPI (*FUNC_SetInformationJobObject)(HANDLE hJob,JOBOBJECTINFOCLASS JobObjectInfoClass,LPVOID lpJobObjectInfo,DWORD cbJobObjectInfoLength);
typedef BOOL WINAPI (*FUNC_AssignProcessToJobObject)(HANDLE hJob,HANDLE hProcess);
typedef BOOL WINAPI (*FUNC_DebugActiveProcessStop)(DWORD dwProcessId);

int Protect(HANDLE hProc,ULONG memlimit){
    HMODULE hKernel32;
    FUNC_CreateJobObject CreateJobObject;
    FUNC_SetInformationJobObject SetInformationJobObject;
    FUNC_AssignProcessToJobObject AssignProcessToJobObject;
    FUNC_DebugActiveProcessStop DebugActiveProcessStop;

    HANDLE hJob;
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION JELI;
    JOBOBJECT_BASIC_UI_RESTRICTIONS JBUR;
    HANDLE hToken;
    
    hKernel32 = GetModuleHandle(L"kernel32.dll");
    CreateJobObject = (FUNC_CreateJobObject)GetProcAddress(hKernel32,"CreateJobObjectA");
    SetInformationJobObject = (FUNC_SetInformationJobObject)GetProcAddress(hKernel32,"SetInformationJobObject");
    AssignProcessToJobObject = (FUNC_AssignProcessToJobObject)GetProcAddress(hKernel32,"AssignProcessToJobObject");
    DebugActiveProcessStop = (FUNC_DebugActiveProcessStop)GetProcAddress(hKernel32,"DebugActiveProcessStop");

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

    return 0;
}

PJUDGE_INFO pJudgeInfo;

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

    if(overFlag == true && pJudgeInfo->state <= JUDGE_STATE_AC){
	pJudgeInfo->state = JUDGE_STATE_WA;
    }

    return 0;
}

int main(int argc,char *args[]){
    ULONG timelimit;
    ULONG memlimit;

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

    PROCESS_MEMORY_COUNTERS memInfo;

    if(argc != 6){
	printf("name.exe time(ms) mem(KB) inputfile ansfile\n");
	return 0;
    }

    timelimit = atoi(args[2]);
    memlimit = atoi(args[3]) * 1024;

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
    pJudgeInfo = (PJUDGE_INFO)MapViewOfFile(hComMap,FILE_MAP_ALL_ACCESS,0,0,sizeof(JUDGE_INFO));

    pJudgeInfo->timestart = 0;
    pJudgeInfo->timelimit = timelimit;
    pJudgeInfo->state = JUDGE_STATE_RUN;

    rDllName = VirtualAllocEx(procInfo.hProcess,NULL,strlen(DLL_NAME) + 1,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE);
    WriteProcessMemory(procInfo.hProcess,rDllName,DLL_NAME,strlen(DLL_NAME) + 1,NULL);
    CreateRemoteThread(procInfo.hProcess,
	    NULL,
	    0,
	    (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32.dll"),"LoadLibraryA"),
	    rDllName,
	    0,
	    NULL);

    WaitForSingleObject(hComEvent,INFINITE);

    hIoThread = CreateThread(NULL,0,IoThread,NULL,0,NULL);
    Protect(procInfo.hProcess,memlimit);
    pJudgeInfo->timestart = GetTickCount();
    
    ResumeThread(procInfo.hThread);

    while(true){
	if(WaitForSingleObject(hComEvent,1200) == WAIT_TIMEOUT){ 
	    break;
	}else if(pJudgeInfo->state != JUDGE_STATE_RUN){
	    break;
	}
    }

    if(pJudgeInfo->state == JUDGE_STATE_RUN){
	pJudgeInfo->timeend = GetTickCount();
	pJudgeInfo->state = JUDGE_STATE_RE;
	TerminateProcess(procInfo.hProcess,0);
    }
    CloseHandle(hOutPipe);
    Crash_Clean();

    printf("Time: %lums\n",pJudgeInfo->timeend - pJudgeInfo->timestart);

    GetProcessMemoryInfo(procInfo.hProcess,&memInfo,sizeof(PROCESS_MEMORY_COUNTERS));
    printf("Memory: %dKB\n",(memInfo.PeakPagefileUsage / 1024));

    if(memInfo.PeakPagefileUsage > memlimit){
	pJudgeInfo->state = JUDGE_STATE_MLE;
    }

    WaitForSingleObject(hIoThread,INFINITE);

    if(pJudgeInfo->state == JUDGE_STATE_AC){
	printf("Status: AC\n");
    }else if(pJudgeInfo->state == JUDGE_STATE_WA){
	printf("Status: WA\n");
    }else if(pJudgeInfo->state == JUDGE_STATE_TLE){
	printf("Status: TLE\n");
    }else if(pJudgeInfo->state == JUDGE_STATE_RF){
	printf("Status: RF\n");
    }else if(pJudgeInfo->state == JUDGE_STATE_RE){
	printf("Status: RE\n");
    }else if(pJudgeInfo->state == JUDGE_STATE_MLE){
	printf("Status: MLE\n");
    }

    return 0;

}
