#define UNICODE

#include<windows.h>

#include"judge.h"

HANDLE hComEvent;
HANDLE hComMap;
PULONG pDllState;

void RF_Hook(){
    *pDllState = JUDGE_STATE_RF;
    TerminateProcess(GetCurrentProcess(),0);
}
int Patch(HANDLE hProc,ULONG addr,ULONG hook,ULONG dbgAddr){
    ULONG rl;
    ULONG old;
    UCHAR code[5]={0xE9,0x0,0x0,0x0,0x0};

    *(PULONG)(code + 1) = hook - addr - 5;

    VirtualProtectEx(hProc,(PVOID)addr,5,PAGE_EXECUTE_READWRITE,&old); 
    WriteProcessMemory(hProc,(PVOID)addr,(PVOID)code,5,&rl);

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
    "ZwQueryPerformanceCounter",
    "ZwQueryInformationThread",
    "ZwTerminateThread",
    "ZwReleaseMutant",
    "ZwWaitForSingleObject"
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
	    for(j = 0;j < 29;j++){
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

extern "C" BOOL WINAPI DllMain(HINSTANCE hinstDLL,DWORD fdwReason,LPVOID lpvReserved){
    if(fdwReason == DLL_PROCESS_ATTACH){
	WCHAR ComEventName[128];
	WCHAR ComMapName[128];

	SetErrorMode(SEM_NOGPFAULTERRORBOX);

	wsprintf(ComEventName,L"JUDGE_COMEVENT_%u",GetCurrentProcessId());
	hComEvent = OpenEvent(EVENT_ALL_ACCESS,FALSE,ComEventName);
	wsprintf(ComMapName,L"JUDGE_COMMAP_%u",GetCurrentProcessId());
	hComMap = OpenFileMapping(FILE_MAP_ALL_ACCESS,FALSE,ComMapName);
	pDllState = (PULONG)MapViewOfFile(hComMap,FILE_MAP_ALL_ACCESS,0,0,sizeof(ULONG));

	RF_Patch(GetCurrentProcess());
	SetEvent(hComEvent);
    }else if(fdwReason == DLL_PROCESS_DETACH){	
	*pDllState = JUDGE_STATE_AC;
    }

    return TRUE;
}
