#define UNICODE

#include<windows.h>

#include"judge.h"

HANDLE hComEvent;
HANDLE hComMap;
PULONG pDllState;

HANDLE hLog;

void dbg(ULONG dbgAddr){
    WriteFile(hLog,(char*)dbgAddr,strlen((char*)dbgAddr),NULL,NULL);
}
void RF_Hook(){
    ULONG dbgAddr;

    __asm("movl %0,%%eax":"=r"(dbgAddr)::);

    dbg(dbgAddr);

    *pDllState = JUDGE_STATE_RF;
    SetEvent(hComEvent);
    TerminateProcess(GetCurrentProcess(),0);
}
int Patch(HANDLE hProc,ULONG addr,ULONG hook,ULONG dbgAddr){
    ULONG rl;
    ULONG old;
    UCHAR code[10]={0xB8,0x0,0x0,0x0,0x0,0xE9,0x0,0x0,0x0,0x0};

    *(PULONG)(code + 1) = dbgAddr;
    *(PULONG)(code + 6) = hook - addr - 5;

    VirtualProtectEx(hProc,(PVOID)addr,10,PAGE_EXECUTE_READWRITE,&old); 
    WriteProcessMemory(hProc,(PVOID)addr,(PVOID)code,10,&rl);

    return 0;
}

char excludeList[128][128] = {
    "ZwGetTickCount",
    "ZwSetEvent",
    "ZwDelayExecution",
    "ZwQueryValueKey",
    "ZwWriteFile",
    "ZwReadFile",
    "ZwQueryInformationFile",
    "ZwSetInformationFile",
    "ZwQueryInformationProcess",
    "ZwSetInformationThread",
    "ZwClose",
    "ZwOpenKey",
    "ZwTerminateProcess",
    "ZwFlushInstructionCache",
    "ZwProtectVirtualMemory",
    "ZwWriteVirtualMemory",
    "ZwAllocateVirtualMemory",
    "ZwContinue",
    "ZwDeviceIoControlFile",
    "ZwQueryVirtualMemory",
    "ZwFreeVirtualMemory",
    "ZwTestAlert",
    "ZwCreateSemaphore",
    "ZwRequestWaitReplyPort",
    "ZwQueryPerformanceCounter"
};
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

    rvaList = (PULONG)(base + pIED->AddressOfNames);
    for(i = 0;i < pIED->NumberOfNames;i++){
	name = (char*)(base + rvaList[i]);
	if(name[0] == 'Z' && name[1] == 'w'){
	    flag = 0;
	    for(j = 0;j < 25;j++){
		if(strcmp(name,excludeList[j]) == 0){
		    flag = 1;
		    break;
		}
	    }
	    if(flag == 0){
		Patch(hProc,(ULONG)GetProcAddress(hNtDll,name),(ULONG)RF_Hook,(ULONG)name);
	    }
	}
    }

    return 0;
}

DWORD WINAPI watcher(LPVOID lpParameter){
    WCHAR ComEventName[128];
    WCHAR ComMapName[128];

    SetErrorMode(SEM_NOGPFAULTERRORBOX);

    wsprintf(ComEventName,L"JUDGE_COMEVENT_%u",GetCurrentProcessId());
    hComEvent = OpenEvent(EVENT_ALL_ACCESS,FALSE,ComEventName);
    wsprintf(ComMapName,L"JUDGE_COMMAP_%u",GetCurrentProcessId());
    hComMap = OpenFileMapping(FILE_MAP_ALL_ACCESS,FALSE,ComMapName);
    pDllState = (PULONG)MapViewOfFile(hComMap,FILE_MAP_ALL_ACCESS,0,0,sizeof(ULONG));

    hLog = CreateFileA("RFLog.txt",
	    GENERIC_WRITE,
	    0,
	    NULL,
	    CREATE_ALWAYS,
	    0,
	    NULL);

    RF_Patch(GetCurrentProcess());

    while(true){
	SetEvent(hComEvent);
	Sleep(100);
    }
}

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved){
    if(fdwReason == DLL_PROCESS_ATTACH){
	CreateThread(NULL,0,watcher,NULL,0,NULL);
    }else if(fdwReason == DLL_PROCESS_DETACH){	
	*pDllState = JUDGE_STATE_AC;
	SetEvent(hComEvent);
    }

    return TRUE;
}
