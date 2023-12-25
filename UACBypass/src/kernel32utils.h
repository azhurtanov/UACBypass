#include "windows.h"
#include "ntdllutils.h"
#pragma once
DWORD kHashFunction(PCSTR FunctionName);
PVOID kGetFunctionAddress(DWORD FunctionHash);





typedef struct tagTHREADENTRY32 {
  DWORD dwSize;
  DWORD cntUsage;
  DWORD th32ThreadID;
  DWORD th32OwnerProcessID;
  LONG  tpBasePri;
  LONG  tpDeltaPri;
  DWORD dwFlags;
} THREADENTRY32, *LPTHREADENTRY32;



typedef HANDLE(WINAPI *CREATETOOLHELP32SNAPSHOT)(
  DWORD dwFlags,
  DWORD th32ProcessID
);

typedef DWORD(WINAPI *GETCURRENTPROCESSID)();
typedef DWORD(WINAPI *GETCURRENTTHREADID)();
typedef BOOL(WINAPI *GETTHREADTIMES)(
  HANDLE     hThread,
  LPFILETIME lpCreationTime,
  LPFILETIME lpExitTime,
  LPFILETIME lpKernelTime,
  LPFILETIME lpUserTime
);

typedef DWORD(WINAPI *CLOSEHANDLE)(
    HANDLE hObject
);

typedef BOOL(WINAPI *THREAD32NEXT)(
  HANDLE          hSnapshot,
  LPTHREADENTRY32 lpte
);

typedef BOOL(WINAPI *THREAD32FIRST)(
  HANDLE          hSnapshot,
  LPTHREADENTRY32 lpte
);

typedef HANDLE(WINAPI *OPENTHREAD)(
  DWORD dwDesiredAccess,
  BOOL  bInheritHandle,
  DWORD dwThreadId
);

typedef DWORD(WINAPI *SUSPENDTHREAD)(
  HANDLE hThread
);