#define UNICODE

#include<windows.h>
#include<aclapi.h>
#include<sddl.h>
#include<stdio.h>
#include<stdlib.h>

typedef BOOL WINAPI (*FUNC_ConvertStringSidToSid)(LPCTSTR StringSid,PSID *Sid);

int Set_Priv(HANDLE hToken,PWCHAR pPrivStr,BOOL enable){
    TOKEN_PRIVILEGES tp;
    LUID luid;

    LookupPrivilegeValue(NULL,pPrivStr,&luid);

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if(enable){
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    }else{
	tp.Privileges[0].Attributes = 0;
    }

    AdjustTokenPrivileges(hToken,
	    FALSE,
	    &tp,
	    sizeof(TOKEN_PRIVILEGES),
	    NULL,
	    NULL);

    return 0;
}
int Set_ACL(WCHAR *file){
    HMODULE hAdvapi32;
    FUNC_ConvertStringSidToSid ConvertStringSidToSid;

    PSECURITY_DESCRIPTOR pSD;
    
    PSID pOriSID;
    PSID pAdminSID;
    PWCHAR pSIDStr;
    
    PACL pOldACL;
    PACL pNewACL;
    EXPLICIT_ACCESS ea;

    hAdvapi32 = GetModuleHandle(L"advapi32.dll");
    ConvertStringSidToSid = (FUNC_ConvertStringSidToSid)GetProcAddress(hAdvapi32,"ConvertStringSidToSidW");

    printf("%S\n",file);

    if(GetNamedSecurityInfo(file,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,&pOriSID,NULL,&pOldACL,NULL,&pSD)){
	return 0;
    }

    printf("OK\n");

    ConvertStringSidToSid(L"S-1-5-32-544",&pAdminSID);
    SetNamedSecurityInfo(file,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION,pAdminSID,NULL,NULL,NULL);

    memset(&ea,0,sizeof(EXPLICIT_ACCESS));
    ea.grfAccessPermissions = GENERIC_EXECUTE | GENERIC_READ;
    ea.grfAccessMode = GRANT_ACCESS;
    ea.grfInheritance= NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_NAME;
    ea.Trustee.ptstrName = L"Everyone";
    SetEntriesInAcl(1,&ea,pOldACL,&pNewACL);

    SetNamedSecurityInfo(file,SE_FILE_OBJECT,OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,pOriSID,NULL,pNewACL,NULL);

    return 0;
}

int main(){
    HANDLE hToken;

    OpenProcessToken(GetCurrentProcess(),TOKEN_ALL_ACCESS,&hToken);
    Set_Priv(hToken,SE_TAKE_OWNERSHIP_NAME,TRUE);
    Set_Priv(hToken,SE_RESTORE_NAME,TRUE);

    Set_ACL(L"C:\\Windows\\SysWOW64\\kernel32.dll");
    Set_ACL(L"C:\\Windows\\SysWOW64\\KernelBase.dll");
    Set_ACL(L"C:\\Windows\\SysWOW64\\msvcrt.dll");
    Set_ACL(L"C:\\Windows\\SysWOW64\\ntdll.dll");
    Set_ACL(L"C:\\Windows\\System32\\kernel32.dll");
    Set_ACL(L"C:\\Windows\\System32\\KernelBase.dll");
    Set_ACL(L"C:\\Windows\\System32\\msvcrt.dll");
    Set_ACL(L"C:\\Windows\\System32\\ntdll.dll");
    Set_ACL(L"C:\\Windows\\System32\\wow64.dll");
    Set_ACL(L"C:\\Windows\\System32\\wow64cpu.dll");
    Set_ACL(L"C:\\Windows\\System32\\wow64win.dll");
    Set_ACL(L"C:\\Windows");

    return 0;
}
