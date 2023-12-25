# UACBypass
UAC bypass via UIAccess trick. Can be both built as exe and dll. Check the build.bat file.
1. PE injection into explorer
2. FileOperations::Copy of quickassist.exe + d2d1.dll (dll-sideload) to "C:\Program Files\Windows Mail". Sideload performs hook injection.
3. PkgMgr (elevated) started and injected by quickassist to launch the shellcode
