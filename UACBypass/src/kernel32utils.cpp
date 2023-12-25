#include "Windows.h"   
#include "kernel32utils.h" 
#include "ntdllutils.h"


DWORD kHashFunction(PCSTR FunctionName)
{
    
    DWORD i = 0;
    DWORD Hash = SEED;
    DWORD obf = SEED;

    while (FunctionName[i])
    {

        ULONG64 t = (ULONG64)FunctionName + i++;
        obf -=i;
        WORD PartialName = *(WORD*)(t);
        obf +=i;
        DWORD t1 = ROR8(Hash); // maybe word
        obf = Hash + i;
        Hash ^= PartialName + t1;
        
  
    }

    return Hash;
}

PVOID kGetFunctionAddress(DWORD FunctionHash){    
    
    PIMAGE_NT_HEADERS pNtHeaders;
    PPEB Peb = (PPEB)__readgsqword(0x60);
    PPEB_LDR_DATA Ldr = Peb->Ldr;
    PLDR_DATA_TABLE_ENTRY LdrEntry;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory;
    PVOID DllBase = NULL;
    
    for (LdrEntry = (PLDR_DATA_TABLE_ENTRY)Ldr->Reserved2[1]; LdrEntry->DllBase != NULL; LdrEntry = (PLDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
    
    DllBase = LdrEntry->DllBase;
  
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)DllBase;
    PIMAGE_NT_HEADERS NtHeaders = (PIMAGE_NT_HEADERS)((ULONG_PTR)DllBase + DosHeader->e_lfanew);
    
    PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
    
    DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((ULONG_PTR)DllBase + VirtualAddress);

    PCHAR DllName = (PCHAR)((ULONG_PTR)DllBase + ExportDirectory->Name);
    

    if ((*(ULONG*)DllName | 0x20202020) != 'nrek') continue;
    if ((*(ULONG*)(DllName + 4) | 0x20202020) == '23le') break;
    }
    
    if (!ExportDirectory) return FALSE;
    DWORD NumberOfNames = ExportDirectory->NumberOfNames;
    PDWORD Functions = (PDWORD)((ULONG_PTR)DllBase + ExportDirectory->AddressOfFunctions);
    PDWORD Names = (PDWORD)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNames);
    PWORD Ordinals = (PWORD)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNameOrdinals);
  
    for(int i=0; i<NumberOfNames; i++){
        
        PCHAR FunctionName = (PCHAR)((ULONG_PTR)DllBase + Names[i]);
        
        //printf("FunctionName: %s. FunctionHash: 0x%x. FunctionOrdinal: %i. VirtualAddress: %x\n", FunctionName, HashFunction(FunctionName),Ordinals[i], Functions[Ordinals[i]]);
        
        if(kHashFunction(FunctionName) == FunctionHash)
            return (PVOID)((ULONG_PTR)DllBase + Functions[Ordinals[i]]);
        
    }
    
    return 0;
}
