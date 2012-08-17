#define UNICODE

#include<windows.h>

#include"judge.h"

HANDLE hComEvent;
HANDLE hComMap;
PJUDGE_INFO pJudgeInfo;

void PF_Hook(){
    pJudgeInfo->timeend = GetTickCount();
    pJudgeInfo->state = JUDGE_STATE_RF;
    SetEvent(hComEvent);
    TerminateProcess(GetCurrentProcess(),0);
}
int Patch(HANDLE hProc,ULONG addr,ULONG hook){
    ULONG rl;
    ULONG old;
    UCHAR code[5]={0xE9,0x0,0x0,0x0,0x0};

    *(PULONG)(code + 1) = hook - addr - 5;
 
    VirtualProtectEx(hProc,(PVOID)addr,5,PAGE_EXECUTE_READWRITE,&old); 
    WriteProcessMemory(hProc,(PVOID)addr,(PVOID)code,5,&rl);

    return 0;
}
int PF_Patch(HANDLE hProc){
    HMODULE hNtDll;
    ULONG ZwOpenFileAddr;
    ULONG ZwCreateFileAddr;
    ULONG ZwCreateProcessAddr;
    ULONG ZwCreateThreadAddr;
    ULONG ZwOpenThreadAddr;

    hNtDll = GetModuleHandleA("ntdll.dll");
    ZwOpenFileAddr = (ULONG)GetProcAddress(hNtDll,"NtOpenFile");
    ZwCreateFileAddr = (ULONG)GetProcAddress(hNtDll,"NtCreateFile");
    ZwCreateProcessAddr = (ULONG)GetProcAddress(hNtDll,"ZwCreateProcess");
    ZwCreateThreadAddr = (ULONG)GetProcAddress(hNtDll,"ZwCreateThread");
    ZwOpenThreadAddr = (ULONG)GetProcAddress(hNtDll,"ZwOpenThread");

    Patch(hProc,ZwOpenFileAddr,(ULONG)PF_Hook);
    Patch(hProc,ZwCreateFileAddr,(ULONG)PF_Hook);
    Patch(hProc,ZwCreateProcessAddr,(ULONG)PF_Hook);
    Patch(hProc,ZwCreateThreadAddr,(ULONG)PF_Hook);
    Patch(hProc,ZwOpenThreadAddr,(ULONG)PF_Hook);

    return 0;
}

DWORD WINAPI watcher(LPVOID lpParameter){
    WCHAR ComEventName[128];
    WCHAR ComMapName[128];

    wsprintf(ComEventName,L"JUDGE_COMEVENT_%u",GetCurrentProcessId());
    hComEvent = OpenEvent(EVENT_ALL_ACCESS,FALSE,ComEventName);
    wsprintf(ComMapName,L"JUDGE_COMMAP_%u",GetCurrentProcessId());
    hComMap = OpenFileMapping(FILE_MAP_ALL_ACCESS,FALSE,ComMapName);
    pJudgeInfo = (PJUDGE_INFO)MapViewOfFile(hComMap,FILE_MAP_ALL_ACCESS,0,0,sizeof(JUDGE_INFO));

    PF_Patch(GetCurrentProcess());

    while(true){
	if(pJudgeInfo->timestart > 0 && (GetTickCount() - pJudgeInfo->timestart) > pJudgeInfo->timelimit){
	    pJudgeInfo->timeend = GetTickCount();
	    pJudgeInfo->state = JUDGE_STATE_TLE;
	    SetEvent(hComEvent);
	    TerminateProcess(GetCurrentProcess(),0);
	}else{
	    SetEvent(hComEvent);
	}

	Sleep(100);
    }
}

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved){
    if(fdwReason == DLL_PROCESS_ATTACH){
	CreateThread(NULL,0,watcher,NULL,0,NULL);
    }else if(fdwReason == DLL_PROCESS_DETACH){	
	pJudgeInfo->timeend = GetTickCount();
	pJudgeInfo->state = JUDGE_STATE_AC;
	SetEvent(hComEvent);
    }

    return TRUE;
}
