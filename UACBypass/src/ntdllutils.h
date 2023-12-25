#pragma once
#include "Windows.h"  
#define SEED 0x63191199
#define ROL8(v) (v << 8 | v >> 24)
#define ROR8(v) (v >> 8 | v << 24)
#define ROX8(v) ((SEED % 2) ? ROL8(v) : ROR8(v))



typedef struct _UNICODE_STRING {
  USHORT Length;
  USHORT MaximumLength;
  PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;



typedef struct _RTL_USER_PROCESS_PARAMETERS {
  BYTE           Reserved1[16];
  PVOID          Reserved2[10];
  UNICODE_STRING ImagePathName;
  UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB_LDR_DATA {
  BYTE       Reserved1[8];
  PVOID      Reserved2[3];
  LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef VOID (WINAPI *PPS_POST_PROCESS_INIT_ROUTINE)(VOID);

typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;

typedef struct {
  ULONG PriorityClass;
  ULONG PrioritySubClass;
} KPRIORITY, *PKPRIORITY;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;


typedef struct _LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID EntryPoint;
    PVOID Reserved3;
    UNICODE_STRING FullDllName;
    BYTE Reserved4[8];
    PVOID Reserved5[3];
    union {
        ULONG CheckSum;
        PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef NTSTATUS(WINAPI* NTGETCONTEXTTHREAD)(
	HANDLE hThread,
	WOW64_CONTEXT *lpContext
);

typedef NTSTATUS(NTAPI* NTWAITFORSINGLEOBJECT)(
	HANDLE         Handle,
	BOOLEAN        Alertable,
	PLARGE_INTEGER Timeout
);

typedef enum _PROCESSINFOCLASS{
	ProcessBasicInformation = 0,
	ProcessDebugPort = 7,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27, 
	ProcessBreakOnTermination = 29,
	ProcessTelemetryIdInformation = 64,
	ProcessSubsystemInformation = 75
} PROCESSINFOCLASS;

typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_BASIC_INFORMATION {
	ULONG Reserved;
	ULONG TimerResolution;
	ULONG PageSize;
	ULONG NumberOfPhysicalPages;
	ULONG LowestPhysicalPageNumber;
	ULONG HighestPhysicalPageNumber;
	ULONG AllocationGranularity;
	ULONG_PTR MinimumUserModeAddress;
	ULONG_PTR MaximumUserModeAddress;
	KAFFINITY ActiveProcessorsAffinityMask;
	CHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION;

typedef NTSTATUS(NTAPI* NTQUERYINFORMATIONPROCESS)(
	HANDLE           ProcessHandle,
	PROCESSINFOCLASS ProcessInformationClass,
	PVOID            ProcessInformation,
	ULONG            ProcessInformationLength,
	PULONG           ReturnLength
);

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
  ULONG           Length;
  HANDLE          RootDirectory;
  PUNICODE_STRING ObjectName;
  ULONG           Attributes;
  PVOID           SecurityDescriptor;
  PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef NTSTATUS(NTAPI * RTLCREATEUSERTHREAD)(
	IN HANDLE ProcessHandle,
	IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
	IN BOOLEAN CreateSuspended,
	IN ULONG StackZeroBits OPTIONAL,
	IN SIZE_T StackReserve OPTIONAL,
	IN SIZE_T StackCommit OPTIONAL,
	IN PTHREAD_START_ROUTINE StartAddress,
	IN PVOID Parameter OPTIONAL,
	OUT PHANDLE ThreadHandle OPTIONAL,
	OUT PCLIENT_ID ClientId OPTIONAL
);

typedef NTSTATUS(WINAPI *NTWRITEVIRTUALMEMORY)	(
	HANDLE ProcessHandle, 
	PVOID BaseAddress, 
	PVOID Buffer, 
	ULONG NumberOfBytesToWrite, 
	PULONG NumberOfBytesWritten);

typedef NTSTATUS(WINAPI *NTRESUMETHREAD)(
	HANDLE hThread,
	PULONG SuspendCount
);

typedef NTSTATUS(NTAPI* NTREADVIRTUALMEMORY)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	PVOID Buffer,
	ULONG NumberOfBytesToRead,
	PULONG NumberOfBytesReaded
	);

typedef void (NTAPI* RTLINITUNICODESTRING)(
	PUNICODE_STRING         DestinationString,
	PCWSTR SourceString
	);


typedef NTSTATUS(NTAPI* NTQUERYVIRTUALMEMORY)(
	HANDLE                   ProcessHandle,
	PVOID                    BaseAddress,
	MEMORY_INFORMATION_CLASS MemoryInformationClass,
	PVOID                    MemoryInformation,
	SIZE_T                   MemoryInformationLength,
	PSIZE_T                  ReturnLength
	);

typedef NTSTATUS(NTAPI* NTQUERYSYSTEMINFORMATION)(
	SYSTEM_INFORMATION_CLASS SystemInformationClass,
	PVOID                    SystemInformation,
	ULONG                    SystemInformationLength,
	PULONG                   ReturnLength);

typedef NTSTATUS(NTAPI* NTPROTECTVIRTUALMEMORY)(
	HANDLE Process,
	PVOID BaseAddress,
	PULONG NumberOfBytesToProtect,
	ULONG NewAccessProtection,
	PULONG OldAccessProtection
	);

typedef NTSTATUS(WINAPI* RTLWOW64GETTHREADCONTEXT)(
	HANDLE hThread,
	WOW64_CONTEXT* lpContext
	);

typedef NTSTATUS(WINAPI* RTLWOW64SETTHREADCONTEXT)(
	HANDLE hThread,
	WOW64_CONTEXT* lpContext
	);

typedef NTSTATUS(NTAPI* NTOPENTHREAD)(
	PHANDLE            ThreadHandle,
    ACCESS_MASK        DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes,
	PCLIENT_ID         ClientId
);

typedef NTSTATUS(NTAPI* NTSUSPENDTHREAD)(
	HANDLE ThreadHandle,
	PULONG PreviousSuspendCount
);

PVOID GetFunctionAddress(DWORD FunctionHash);
DWORD HashFunction(PCSTR FunctionName);