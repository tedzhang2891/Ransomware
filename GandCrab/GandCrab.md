# 趋势科技 GandCrab 勒索软件案例

> 2019年中国农历年，当大家还都沉浸在新年的快乐中时，一种新型勒索软件（GandCrab v5.1）爆发并在业界掀起一场新的风暴。趋势科技工程师快速响应，仅用2天时间实现了针对此版本恶意软件的解密工具。

## 序章 红色邮件

时间定格在2019年2月16日的一个午后，趋势科技工程师T正在家中陪伴家人，突然一阵急促的电话铃声响起。

“喂，是T吗？”，电话那头传来了T的上司L急促的声音。

“上司一般不会在周末打电话打扰职员的”，T心里想。“一定是遇到了不得了的事情”。

“是我，发生了什么事？”，T急忙询问L。

“你快看一下邮件，一种新的勒索软件爆发了。”

T急忙打开电脑，一封邮件跳入了T的目光，标题中的“Important”用红色字体凸显出来，使得这封邮件显得格外的与众不同。

T的心已经提了起来，“这封邮件内容一定很爆炸”，随即点开了邮件。

邮件格式非常正式，“5000台机器被锁死，其中有工作站也有服务器；客户无奈只能给黑客付款，优先解锁一批关键机器；客户获得了一组解密工具并请求趋势科技开发解密工具；客户拒绝在客户的环境中收集信息”。T在心中快速的总结信息。

“看来我们必须接下这个Case，根据目前收集到的信息和资料，我们需要尽快给支持团队一个结论。”，L在电话那端说。

“是的，目前我们收集到了病毒样本，黑客的解密工具。我想我可以开始工作，但是这需要一些时间，你知道的。”

“OK，开始吧，一旦有进展立刻告诉我。”

## 第一章 调查

T立刻展开工作，他首先打开虚拟机（*作为一名专业的病毒分析专家，他有很多用于病毒分析的工具，但是首先必须确保病毒不会污染工作环境，因此在虚拟机中运行病毒是隔离危险的必要手段。*）运行病毒，并尝试用客户已经购买的解密工具解密准备好的测试文件，但是失败了。

“黑客很聪明”，T心想：“也许每一台设备都需要对应一个解密工具”。

“我记得Support提供了一批客户机器上文件，这些文件都被加密了。也许我可以在这些文件中找一找线索”，T一遍想一遍打开了Support提供的数据，并且他发现了一个线索。

`---BEGIN GANDCRAB KEY---
lAQAAOdRXMC9UBjj6uq6mZfhIfzVbK5m0WfQZyTiHZ8WtYHyG5P53Fd+2iXjO22X3Jcr/jqqbEjFmgha2oWFcPv+4DQC5WoUl0ZvbmBPdYOqGt1kQr7Cspps1qDED+WKc5hOzjNgP79v2YA+kBgzCSEyvSouyg8y6islTro2ghLSJWVal0tNlhZ+YJWmG5F8YH5W9cW0eNCEPQ0zx8gHAL6T1RBJ2NGig39VcRmIpto5L6ZBk6cOyrTCWztDEgCPsLqxN0XOoKRbwqDoPykfIMn96i6zVVVfJFIHyMFNnJHd3BeGpklL9yMi6K2uOL2BqfmpjCMhzNcOI3EC4eWcerlWqjAjTPDok7xkNrsyxYWqqL2nFclN+4a+IVgNBnOcs0I3mFQj1Z1550ymgNO5g1Sdy3ty3L1kcuCu40HjZ3zTK92x4D1aGl8YhJja10jQx0LNUTyXY0Hu1kNG6c6NEIp+6OIOiyiK9F15XvCT5DsF7nU7Hm3Z/...模糊化处理
---END GANDCRAB KEY---`

看起来每一台设备会对应这样一个文件，既然客户购买的解密工具能够解锁一部分设备的数据，那解密工具应该包含了解密数据所需要的全部算法。 

“我应该从解密工具入手。”

T收到的解密工具一共有8个，虽然8个工具的哈希值并不一样，但是它们却具有相同的Size。基于经验，T判断这8个工具是相同的解密算法，差异的部分可能就是解密需要的Key。

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/diff%20decryptor.png)

利用BeyondCompare工具，并选择16进制比较两个解密工具后，T发现正如他所判断的，两个文件之间的差异非常小。

"看起来差异只有两块，一块显而易见是加密后的文件扩展名，另一块看起来很像是解密密钥。"

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/2-Target%20extension.png)

正如T所推测的，这块重要的数据实际上是被Base64编码后的解密密钥。

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/1-base64%20RSA%20private%20key.png)

“Base64 decode RSA私钥，然后检查被加密后的扩展名是否与解密工具一致。”

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/3-base64decode%20RSA%20pbData.png)

“判断输入的路径是一个目录或特定文件，如果是执行目录解密，如果没有传入文件路径，执行全盘解密。”

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/4-decryptSingleOrFull.png)

"解密数据之前，首先初始化内部结构"

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/5-make%20a%20struct%20to%20save%20RSA%20pbData%20and%20size.png)

虽然在之后通过分析病毒样本，T得到了病毒在加密文件后在文件末尾追加了一个解密块，里面存储了很多信息。（但此时T并不知道加密后文件的组织形式）

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/6-each%20file%20have%20this%20structure%20at%20end%20of%20file.png)

经过一些分析，T已经掌握了解密过程。他很兴奋：“看起来，解密的过程分为几个步骤。”

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/10-load%20decrypt%20info.png)

“首先，分配一块540字节的内存，然后调整文件指针，指向被加密文件的末尾。从文件末尾读取540字节的数据，并比较magic_sign_b和magic_sign_a是否等于0x93892918和0x38281。如果是，说明文件是被GandCrab加密的，那么将从解密块中提取出被加密的SalsaKey并用RSA私钥解密它。”

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/9-decrypt%20salsa%20logic.png)

"最后，从解密块中读出被加密的文件一共被分成了多少块，一次取出一块用Salsa20算法解密数据。因为是流式加密，所以解密后的块大小与未解密的块大小一致，所以并不需要调整块大小。"

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/8-full%20decrypt%20logic.png)

通过分析黑客的解密工具，T产生了一个不好的预感。解密数据需要RSA Key，这个Key是如何产生的，如果我们无法获取这个Key将无法提供解密程序。

“目前下结论还太早，我手中还有病毒样本。既然解密工具中无法找到更多的信息，那现在必须开始分析病毒样本了。” T深吸了一口气，病毒样本不像解密工具，很多的病毒样本都采用了对抗分析的机制，在这个领域黑客与病毒分析员之间进行着无休止的斗争。

## 第二章 初识样本

在勒索软件领域T有丰富的经验，分析恶意软件的过程与调查犯罪现场非常相似，收集可以收集到的一切信息是分析过程的重要一环。

“我应该先尝试通过PE软件分析下这个样本，看看有没有什么发现。”，T熟练的打开一款PE分析工具，并将样本送入分析。

分析软件很快将病毒样本的信息显示了出来，“UPX Packed？**[1]** **[2]**”，T发现了重要信息。一旦发现压缩壳，继续分析的意义已经不大了。

“必须先脱壳**[3]**”，因为UPX是开源的，只要锁定恶意软件采用的版本，通过UPX工具既可以脱壳。

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/b2-exeinfope.png)

通过ExeInfoPE **[4]**这款软件，T已经锁定了upx的版本，在github上下载对应版本的UPX后，T成功的将病毒样本脱壳，并得到了病毒的主文件。

脱壳后的样本依旧是一个PE文件，经过ExeInfoPE分析后，T了解到了有价值的信息：

“Microsft Visual C++ v1.0 - 2010，这应该是病毒编译器版本。**[5]**”

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/b2-compiler.png)

“capimoja.exe这是程序的原名。”

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/b2-original_name.png)

快速分析已经无法得到更多有价值的信息了，为了找出加密方法，必须进行主文件分析了。

这是一个看似很平常样本文件，它的段分布很合理，并且代码段中并没有夹杂不可解释的数据。

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/b2-segments.png)

“这个样本很奇怪，静态分析无法定位到病毒加密算法的位置。”。基于大量样本分析工具的经验，T判断这应该存在一个不是那么显而易见的壳。通过代码分析，他找到了一些奇怪的数据被放到了栈上。

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/b2-dataonstack.png)

这种写法在正常软件中是很少见的，T感到继续分析主样本是没有意义的，如果主样本中存在一个自定义壳，那么它一定会执行起来并把真正的载荷释放出来。

“我应该把精力放在载荷上，开始动态分析，快速跳过壳的部分。”

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/b2-setexecutable.png)

“栈上的数据被处理后复制到内存，并设置为可执行？”，一旦数据被设置为可执行，那说明这部分是动态加载的代码，这种实现方式一般都是为了躲避静态分析，是非常重要的线索。

“我应该把这部分代码抽取出来，进行静态分析。”，T同时在输入框中键入了抽取指令，但是他失败了。

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/b2-extractfailed.png)

无论怎么尝试，总是会导致程序崩溃。“显然，这里有黑客植入的保护技术，但是我不应该在这里浪费时间。”，T放弃了采用Windbg的命令抽取方式，转而采用编写IDC脚本，并且这一次他成功了。

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/b2-idcscript.png)

病毒程序在将载荷标记为可执行后，会将控制权转交给它，至此病毒再也不会回到主程序中了。

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/b2-executepayload.png)

## 第三章 神秘代码

“我已经分析完解密工具，根据我的判断解密数据需要特殊的密钥用于解密流式密码本。但目前我并没有掌握特殊密钥是如何生成的。”

“这次的攻击是有计划的，应该是团队行动。我们的Support已经从客户那边取回了付款通道的截图数据，他们只接受电子货币，并且利用洋葱网络匿名，很难追踪。” L快速的向更新他所掌握的信息。“话说回来，病毒分析进展如何。”

“样本是一个UPX打包程序，解包已经完成。”，T开始汇报目前所取得的进展。

“很好”

“但主程序并不是真正具有恶意行为的程序，黑客利用技术手段进行了隐藏。目前静态分析已经无法进行，通过调试分析我已经将主程序中的可疑代码进行了转储，正准备进行载荷的分析。”

“可恶，我就知道没那么简单。” 从收到邮件的那时起L就没有放松过，因为他知道支持团队殷切盼望着他的团队能够带去好消息，但是直到目前还没有任何有价值的进展。

“OK，T你知道这件事的影响，无论如何我们必须尽快的给支持团队一个回复，他们在承受着市场与客户的双重压力。”

“放心吧，明天上午8点钟，我们一定会有一个结论给到支持团队。我保证。” 

T从来不承诺任何他认为不确定的事情，但是这一刻他知道，整个产品线都在承受着巨大的压力，这是一个大客户，如果我们无法给客户一个满意的答复，也许我们会失去这个客户。

几年前，正是由于这份使命，他加入了趋势科技成为一名安全工程师。现在，兑现诺言，践行使命的时刻已经来了，他决心接下重担，让团队可以依靠他。

放下电话，T发现时间已经到了深夜，距离他接到Case至今已经过去10个小时。

“看来今天要奋战了。”

T打开分析工具，加载了提取出来的载荷代码。

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/b2-magiccode.png)

看到眼前载荷指令，T回想到之前他分析过的《危机病毒**[6]**》，在危机病毒中他也提取出了类似的指令段。

“这一定不是加密代码” T知道在危机病毒中这一段相似的代码仍然是一种保护机制，可以理解为加密数据的第三层保护壳（第一层是UPX，第二层是主程序）。

“没有时间了，我不能在这里陷进去。” 过去的经验起到了很好的帮助作用，T没有在这里深入研究。“这应该会继续释放代码，我不得不继续跟踪动态调试。”

通过分析T发现载荷代码中有大量的无法解释的数据出现在代码段中，“这代码真麻烦，是动态解释执行的。”

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/b2-dynamiccode.png)

大约过去了1个小时，T终于掌握了载荷代码的执行逻辑。神秘代码的面纱慢慢被揭开，行为暴露在研究人员的面前。

“初始化一块内存，准备复制代码。”

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/b2-allocforrealcode.png)

“看起来提取出了一个PE文件。”

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/b2-copyrealcode.png)

“居然把主程序代码段清0？”

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/b2-clearmaincode.png)

“原来是准备用新的程序替换主程序啊。”

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/b2-fillmaincode.png)

事实上，载荷代码中隐藏了一个完整的PE文件，这个PE文件会在运行时被释放出来，并且覆盖主文件的进程空间。

“偷梁换柱啊，这招太妙了。” T暗自佩服，安全研究员与黑客就像一对绝佳的对手，所谓道高一尺魔高一丈，大家虽然未曾某面，但是都在相互的学习中进步。虽然T并不认可黑客这种行为的价值观，但是承认黑客的技术确是另外一回事。

## 第四章 核心代码

“嘀嗒，嘀嗒” 时间行走发出的声音在深夜格外清晰。距离L交代的回复时间还有6个小时。

神秘代码释放出了一个全新的PE文件，并覆盖了主程序，现在主程序已经变身成了恶意程序，它将开始暴露加密算法的实现细节。

“我现在要把PE文件转储。” 转储当前的PE文件进行静态分析的时候到了，通过静态分析安全人员会梳理出恶意软件的具体行为，并为下一步解密提供算法支持。

“似乎黑客意识到有人可以突破前三层的保护来到这里。”，虽然已经转储了核心代码，但是在分析的过程中T发现仍然存在很多刻意设置的障碍。

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/b4-apiconfuse.png)

“系统API全部被替换了，到这里还在严防死守。”，替换系统API是一种比较高级的保护方法，它大大增加了安全人员在分析代码时的困难。例如，勒索软件要加密文件首先需要创建一个文件句柄，完成这个工作需要调用系统API，如果黑客不替换系统API，那么我们只要在系统API处打上一个断点，守株待兔即可。但是现在这不起作用了，因为勒索软件永远不会落入你设置的陷阱，它开辟了另外一条路去获取文件句柄。

“这只会拖慢我，但并不会阻止我。”，T给自己鼓了口气。

一年前，当T在处理危机病毒时，危机病毒也采用一种替换系统API的技术。当时那种技术令T印象深刻，危机病毒在内存中创建了一张API指针表，把一个修改过的系统模块加载进内存，并将其中的API更新到API指针表中。危机病毒开始不再使用系统API而使用自己实现的API，从而绕过了断点捕捉。

再久一些，席卷世界的想哭病毒，也有一种特殊的方法加载它隐藏在资源文件中的动态链接库，并且能够逃过断点捕捉技术的检查。因为好奇，T在当时把想哭病毒中的加载功能抽取出来，仔细的研究了一段时间。

见过了太多的技术领域奇技淫巧，T慢慢成长起来，现在他所掌握的技术足以应对当前的情况。经过一段时间的分析，他掌握了核心代码中的加密算法。

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/b4-File%20encrypt%20process%20A.png)

“加密的过程是，病毒分配了540字节数据块，这个块是用来保存解密需要的信息的。”

“打开要加密的文件，将当前文件指针调整到文件尾部540字节的起始位置。并检查magic_sign_b和magic_sign_a是否等于0x93892918和0x38281，如果相等说明这个文件被加密过了。啊哈，这与之前解密工具中看到的一样。”

“接下来初始化Salsa20流式密码本，并且将初始化向量和Salsa20用公钥加密，保存在540字节的解密块中。并且每次读取的数据块大小被设置成了1MB。”

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/b4-Init%20decrypt%20block%20process.png)

“初始化的随机数就是Salsa20的初始化向量。然后按照设置好的块大小每次读取1MB的数据，加密后覆盖原文件，并更新块数量。”

![](https://github.com/tedzhang2891/Ransomware/blob/master/GandCrab/picture/b4-File%20encrypt%20process%20B.png)

完成所有的加密工作后，病毒会在用户的磁盘上写入一个勒索文档，文档中储存了开篇提到的那个`---BEGIN GANDCRAB KEY---`。

## 第五章 答复

“加密和解密算法都有了，但是没有解密密码本的Key我们没有办法解密用户数据啊。” 深夜T给L发送了一条简讯。

“看来这次要让支持团队和用户失望了。”，T很沮丧，花费了10几个小时只能得到无法解密数据这个答案，他有些不甘心，但是也没有办法。

“嗡嗡”，是T的手机在震动，他拿起手机。

“欧洲那边传来了好消息，罗马尼亚警方捣毁了一个数据犯罪据点，缴获了一台用于作案的服务器，并获得了解密数据用的Key，我们的法务专员正在密切与警方合作。”

简讯是L发来的，L一宿未眠他也在尽最大的能力和资源寻求解决方法。

“太好了，看来峰回路转了。”

在距离截止时间还是4小时时，可以解密的希望终于出现了。T所不知道的是，整个公司的很多业务线都在高效的运作，争取每一种帮助用户的可能。这是一场跨国际的团队合作。



## 附录

**[1]** 壳旨在保护病毒数据，使得分析人员很难或需要花费很大的代价才能分析出病毒行为的一种保护机制，在恶意软件中广泛存在。

**[2]** UPX壳是一种压缩壳，它对代码进行压缩，在执行时先执行解压缩代码，然后执行本体，是一种流行的代码压缩技术。

**[3]** 脱壳，是一种逆向技术，病毒分析人员采用这种技术与黑客进行对抗，将被保护的内容呈现出来以供分析。

**[4]** 一款显示PE信息的软件，功能很丰富，研究人员一般用它来做快速分析。

**[5]** 得到病毒对应编译器版本是非常有用的，某些时候当你发现病毒内部存在一些算法很难分析，又无法调试，那么有一种方法是抽取汇编级别的代码重新编译后在本地调试验证。为了使抽取的汇编代码通过编译，正确链接到本地的C Runtime环境中，必须要找到对应的编译器版本。

**[6]** 危机病毒Crysis是2017年开始流行的一种勒索软件，在世界范围内产生了巨大的影响。