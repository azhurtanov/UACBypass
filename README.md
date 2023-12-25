# UACBypass
UAC bypass via UIAccess trick. 
1. PE injection into explorer
2. FileOperations::Copy of quickassist.exe + d2d1.dll (dll-sideload) to "C:\Program Files\Windows Mail". Sideload performs hook injection.
3. PkgMgr (elevated) started and injected by quickassist to launch the shellcode
