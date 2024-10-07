# Windows Server Taskmgr Patch

This patch enables all function which has been disabled in server editions, including statistics of disk, network, GPU, power consumption and the "App History" & "Startup" tab.

Supports all server editions starting from server 2012.

## Usage

### One-time patch

Just run the executable. It will start a patched task manager.

### Install

Add an "image hijack" entry in registry:

```
Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe]
"debugger"="C:\\PATH\\TO\\taskmgrPatch.exe"
```

## Notes

Microsoft has disabled per-App network usage monitoring in Server 2022, so the network will always display as 0%

It is possible to enable this by adding the missing component (`Ndu.sys` and `nduprov.dll`), but this adds overhead to network I/O and I don't recommend doing so.

You can get these component in `Microsoft-Windows-Client-Features-Package.ESD\amd64_microsoft-windows-ndu_31bf3856ad364e35_10.0.20348.1_none_389b6e2a201adb7a` which can be downloaded from UUPdump.

`nduprov.dll` needs to be patched to ignore errors of `DeviceIoControl(IOCTL_LMR_QUERY_PER_PROCESS_STATISTICS)` in `NduGetSmbNetStatsAsSruStatsList` which is unsupported in server editions.

```
.text:0000000180003502                 test    esi, esi
.text:0000000180003504                 jz      short loc_18000356B
.text:0000000180003506                 cmp     esi, 7Ah ; 'z'
.text:0000000180003509                 jz      loc_18000881F
.text:000000018000350F                 cmp     esi, 272h
.text:0000000180003515                 jnz     loc_18000887B   <--  nop this instruction
.text:000000018000351B                 test    cs:Microsoft_Windows_NduEnableBits, 1
.text:0000000180003522                 jnz     loc_180008862
```
