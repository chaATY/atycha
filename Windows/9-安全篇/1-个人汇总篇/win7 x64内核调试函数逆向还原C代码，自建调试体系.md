一、前言  
网上公开的自建调试体系大都是基于wrk xp的，其中mengwuji的为win7 x86，想把该项目用于x64，于是自给自足陆陆续续花了一个月时间成功在win7 x64 sp1上跑起来，该项目参考了前面所述开源代码，在看雪白嫖了这么多干货，不敢藏私，取之于看雪开源于看雪。

二、项目概述  
采用Vs2019+WDK，提供完整的解决方案，下载即可编译运行。注意事项：  
1、PsGetNextProcessThread DbgkDebugObjectType这两个常用的函数、变量采用特征码定位，其余采用解析pdb符号定位函数地址

2、采用InlinHook替换以下内核函数：  
```c
NtDebugActiveProcess  
NtCreateDebugObject  
NtRemoveProcessDebug  
NtWaitForDebugEvent  
NtDebugContinue  
DbgkExitProcess  
DbgkExitThread  
DbgkCopyProcessDebugPort  
DbgkForwardException  
DbgkMapViewOfSection  
DbgkUnMapViewOfSection  
DbgkClearProcessDebugObject  
DbgkCreateThread  
DbgkDebugObjectType-调试对象类型  
DbgkpQueueMessage-这换这个的原因是由于偷懒没有重写DbgkpPostModuleMessages，而这个函数内部有调用DbgkpQueueMessage  
```
3、基于win7 x64不负责过PG，有需要的项目里带了老v的时光倒流过pg代码.  
4、DebugPort除了在函数内部使用的还需要替换这几处的偏移，我只是做了简单处理把DebugPort移位到ExitTime，这种方案不保险，因为EPROCESS里的其他未使用的成员也可能被列入关照对象，在x64这样干的反调试驱动估计少，为了完美解决可以参考看雪大老xiaofu的这篇帖子扩充EPROCESS结构体https://bbs.pediy.com/thread-246625.htm,使用这种方法也有缺陷，只对之后的新进程有效，使用之前需要创建进程回调记录新加载的进程，自己维护判断进程EPROCESS是否经过扩充。  
三、其他  
1、由于异常相关函数不能windbg下断调试，嫌麻烦没有处理，只是简单的在KiDispatchException里改了DebugPort偏移，后面有时间会把异常相关的一起处理掉  
2、由于在代码里面直接对PEB里的BeingDebugged调试标志写False，所以在进程附加的时候不会被断下。

管杀不管埋，蓝屏概不负责！  
其他的自己参照代码改吧