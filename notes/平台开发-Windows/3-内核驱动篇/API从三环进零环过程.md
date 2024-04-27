---
title: API从三环进零环过程
date: 2023-11-04 14:05
author: CHA.ATY
tags:
  - Windows
  - 内核驱动
category: 技术分享
---

![](https://img.shields.io/badge/IDA-7.7.220118_SP1-green.svg)
![](https://img.shields.io/badge/Windows10-22H2_19045.3570-green.svg)

# 一、前言

Application Programming Interface，简称 API 函数。

Windows 的 API 主要是存放在 `C:\WINDOWS\system32` 下面所有的 dll。

重要的 DLL：
1. kernel32.dll：最核心的功能模块，比如管理内存、进程和线程相关的函数等。
2. user32.dll：是Windows用户界面相关应用程序接口,如创建窗口和发送消息等。
3. gdi32.dll：全称是Graphical Device Interface(图形设备接口)，包含用于画图和显示文本的函数。比如要显示一个程序窗口，就调用了其中的函数来画这个窗口。
4. ntdll.dll：大多数API都会通过这个DLL进入内核(0环)。

进入零环两种方法：
- 快速调用：sysenter 指令进0环这种方式不需要查内存，而是直接从CPU的[MSR](https://so.csdn.net/so/search?q=MSR&spm=1001.2101.3001.7020)寄存器中获取所需数据，所以称为快速调用
- 中断调用：通过中断门进0环，此过程需要查IDT表和TSS表

---

# 二、分析 ReadProcessMemory

[ReadProcessMemory 函数原型](https://learn.microsoft.com/zh-cn/windows/win32/api/memoryapi/nf-memoryapi-readprocessmemory)

IDA 首先分析 kernel32.dll，平常都是听说 kernel32.dll 提供了部分 API 的接口调用，所以先来看 kernel32.dll，搜索 ReadProcessMemory 关键字如下图所示。

可以看到是该 ReadProcessMemory 函数在内部调用了 NtReadVirtualMemory 函数，也就是kernel32.dll 提供了接口调用 `call ds:NtReadVirtualMemory`，IDA中的明显特征调用是其他的DLL中的函数。
![[平台开发-Windows/res/5.png]]

这里查看导入表可以看到该 NtReadVirtualMemory 函数是 ntdll.dll 中的，如下图：
![[平台开发-Windows/res/6.png]]

接着我们用 IDA 打开 ntdll.dll。并找到 NtReadVirtualMemory 函数，如下图：
![[平台开发-Windows/res/7.png]]

主要核心的代码就这几条，可以看到这里有两个值，一个是`0BAh`（每个函数都是不同的），还有一个是`7FFE0300h`（相同的）
* `0BAh`->函数服务号
* `7FFE0300h`->快速调用

```IDA
// NtReadVirtualMemory
.text:7C92D9FE                 mov     eax, 0BAh       ; eax = 0xBA
.text:7C92DA03                 mov     edx, 7FFE0300h  ; ecx = 7FFE0300
.text:7C92DA08                 call    dword ptr [edx] ; call 7FFE0300
.text:7C92DA0A                 retn    14h             ; 堆栈平衡
```

这里call了一个[edx]，那么接下来我们就要去找[edx]指向的是哪个函数，而edx的内容则取决于7FFE0300h 这个地址里面是什么。

而想要了解 7FFE0300h 这个地址里的内容，需要先了解一个结构体->[_KUSER_SHARED_DATA](http://terminus.rewolf.pl/terminus/structures/ntdll/_KUSER_SHARED_DATA_x64.html)。

---

# 三、[_KUSER_SHARED_DATA](http://terminus.rewolf.pl/terminus/structures/ntdll/_KUSER_SHARED_DATA_x64.html)

在用户层和内核层分别定义了一个`_KUSER_SHARED_DATA`结构区域，用于在用户层和内核层共享某些数据。

它们使用固定的地址值映射，`_KUSER_SHARED_DATA`结构区域在User和Kernel层地址分别为：
- User层地址为：0x7FFE0000
- Kernel层地址为：0xFFDF0000

**注意点**：User层和Kernel层映射同一个物理页。虽然它们指向的是同一个物理页，但在 User层（3环）是只读的，在 Kernel层（0环）是可写的，所以这也是应用层和驱动层实现调用的数据交换的一种方式。

直接在windbg里查看一下这两个地址的内容，首先挂载到任意一个进程：
```dbg
PROCESS 88049c68  SessionId: 0  Cid: 0930    Peb: 7ffd9000  ParentCid: 05b8
    DirBase: 7f4b64c0  ObjectTable: a7725ab8  HandleCount: 14034.
    Image: OEM8.exe

kd> .process 88049c68  
Implicit process is now 88049c68
WARNING: .cache forcedecodeuser is not enabled
```
接着查看这两个地址的内容：
```dbg
kd> dd 0x7ffe0000
7ffe0000  00000000 0f99a027 5283733f 00000000
7ffe0010  00000000 22ad355a 01d5b7d1 01d5b7d1
7ffe0020  f1dcc000 ffffffbc ffffffbc 014c014c
7ffe0030  003a0043 0057005c 006e0069 006f0064
7ffe0040  00730077 00000000 00000000 00000000
7ffe0050  00000000 00000000 00000000 00000000
7ffe0060  00000000 00000000 00000000 00000000
7ffe0070  00000000 00000000 00000000 00000000
kd> dd 0xffdf0000
ffdf0000  00000000 0f99a027 5283733f 00000000
ffdf0010  00000000 22ad355a 01d5b7d1 01d5b7d1
ffdf0020  f1dcc000 ffffffbc ffffffbc 014c014c
ffdf0030  003a0043 0057005c 006e0069 006f0064
ffdf0040  00730077 00000000 00000000 00000000
ffdf0050  00000000 00000000 00000000 00000000
ffdf0060  00000000 00000000 00000000 00000000
ffdf0070  00000000 00000000 00000000 00000000
```
两块地址空间的内容完全相同，指向的都是同一个物理页。

接着再查看一下两个地址的属性：
```dbg
kd> !vtop 7f4b64c0 0x7ffe0000 
X86VtoP: Virt 000000007ffe0000, pagedir 000000007f4b64c0
X86VtoP: PAE PDPE 000000007f4b64c8 - 000000004fe09801
X86VtoP: PAE PDE 000000004fe09ff8 - 000000004fa07867
X86VtoP: PAE PTE 000000004fa07f00 - 80000000001e2025
X86VtoP: PAE Mapped phys 00000000001e2000
Virtual address 7ffe0000 translates to physical address 1e2000.
kd> !vtop 7f4b64c0 0xffdf0000
X86VtoP: Virt 00000000ffdf0000, pagedir 000000007f4b64c0
X86VtoP: PAE PDPE 000000007f4b64d8 - 000000004c00b801
X86VtoP: PAE PDE 000000004c00bff0 - 000000000018a063
X86VtoP: PAE PTE 000000000018af80 - 00000000001e2163
X86VtoP: PAE Mapped phys 00000000001e2000
Virtual address ffdf0000 translates to physical address 1e2000.
```
- 0x7ffe0000 这个 3 环的地址的 PTE 属性：5 -> 0101 R/W位为0，所以是只读的。
- 0xffdf0000 这个 0 环的地址的 PTE 属性：3 -> 0101 R/W位为1，所以是可读可写的。

**重要的知识点：**

因为 \_KUSER_SHARED_DATA 结构体是调用 0 环函数的重要点，所以操作系统对所有的进程其中的 \_KUSER_SHARED_DATA 的地址都是一样的，都是 0x7FFE0000 这个地址

那么问题就来了？那我是不是hook这个地方也同样能够实现全局的 HOOK 进入三环的函数？

答案是的，但是上面也可以发现用户层是不可写的，如果你在 0 环的话那么就可以全局 HOOK 的操作！

---

# 四、SystemCall

继续查看 NtReadVirtualMemory 这个函数
```dbg
.text:7C92E2BB                 mov     eax, 0BAh       ; NtReadVirtualMemory
.text:7C92E2C0                 mov     edx, 7FFE0300h
.text:7C92E2C5                 call    dword ptr [edx]
.text:7C92E2C7                 retn    14h
```

已知 0x7ffe0000 这个内存是一块共享的内存区域，接下来看一下偏移 0x300 的位置也就是 7FFE0300 这个地址的值是什么，通过查看 \_KUSER_SHARED_DATA 结构体找到偏移 0x300 的位置：
```dbg
// 注：0x7FFE0000是一个进程的CR3，在dt命令执行先切换到一个进程的上下文.process
kd> dt _KUSER_SHARED_DATA 0x7ffe0000 
nt!_KUSER_SHARED_DATA
   ......
   +0x2f8 TestRetInstruction : 0xc3
   +0x300 SystemCall       : 0x776c70b0
   +0x304 SystemCallReturn : 0x776c70b4
   ......
```

这个地方是一个 SystemCall，查看一下对应的反汇编代码，看看 NtReadVirtualMemory 函数的call dword ptr [edx]具体是做了什么。
```dbg
kd> u 0x776c70b0
ntdll!KiFastSystemCall
776c70b0 8bd4            mov edx,esp
776c70b2 0f34            sysenter
776c70b4 c3              ret
```

这个函数叫 **KiFastSystemCall**，实际上就只有三行代码，首先把 esp 保存到 edx ，目的是为了在零环能够方便的找到三环的堆栈。接着用快速调用指令 sysenter 进到零环，最后通过 ret 指令返回。

然而并不是所有的CPU都支持sysenter快速调用指令。这就要了解一下另外一个问题？0x7ffe0300到底存储的是什么？

操作系统在启动的时候，需要初始化 \_KUSER_SHARED_DATA 这个结构体，其中最重要的就是初始化 0x300 这个位置。操作系统要往这里面写一个函数，这个函数决定了所有的3环的 API 进入0环的方式。

操作系统在写入之前会通过 cpuid 这个指令来检查当前的 CPU 是否支持快速调用，如果支持的话，就往 0x300 这个位置写入 **KiIntSystemCall**。如果不支持，则写入 **KiIntSystemCall**。
1. 如果当前操作系统支持快速调用的话那么`u 0x776c70b0`出现的就是相关KiFastSystemCall快速调用的流程（通过sysenter）
```dbg
kd> u 0x776c70b0
ntdll!KiFastSystemCall
776c70b0 8bd4            mov edx,esp
776c70b2 0f34            sysenter
776c70b4 c3              ret
```
2. 如果当前操作系统不支持快速调用的话那么`u 0x7c92e510`出现的就是相关KiIntSystemCall的调用流程（通过中断门），我们可以在 IDA 中看到 KiIntSystemCall 的函数内容
```dbg
.text:7C92EBA5                 lea     edx, [esp+arg_4]
.text:7C92EBA9                 int     2Eh            
.text:7C92EBAB                 retn

```
KiIntSystemCall 就只有三行代码，利用int 0x2E这条指令通过中断门的方式进入零环。

也就是说Windows使用了两种从三环进零环的方式：
- KiFastSystemCall：sysenter快速调用指令。
- KiIntSystemCall：int 0x2E 中断门。

---

# 五、进入零环方式一：KiFastSystemCall

如果操作系统支持快速调用的方式，那么操作系统通过三环进入零环是通过 syscenter 指令
```dbg
kd> u 0x776c70b0
ntdll!KiFastSystemCall               
776c70b0 8bd4            mov edx,esp // edx 3环栈顶 系统调用号在eax寄存器
776c70b2 0f34            sysenter    // 寄存器数据传递
776c70b4 c3              ret
```

## 1. 查看是否支持快速调用

通过CPUID指令查看当前CPU是否支持快速调用，方法是将EAX值设置为1，然后调用CPUID指令，指令执行结果存储在ECX和EDX中，其中EDX的SEP位(11位)表明CPU是否支持快速调用指令 sysenter / sysexit。

当通过 eax=1 来执行 cpuid 指令时，处理器的特征信息被放在 ecx 和 edx 寄存器中，其中edx包含了一个SEP位（11位），该位指明了当前处理器知否支持 sysenter/sysexit 指令，`cpuid`指令：
![[平台开发-Windows/res/9.png]]
接着单步走一下，可以发现ecx和edx都改变了
- ecx：7FFAFBBF
- edx：BFEBFBFF -> 1011 1111 1110 1011 1111 1011 1111 1111

可以看到第0位开始，第11位为1，当前环境是支持快速调用的
![[个人汇总-杂七杂八/res/10.png]]

## 2. sysenter执行的本质

CPU 如果支持 sysenter 指令时，操作系统会提前将 CS、SS、ESP、EIP 的值存储在 MSR 寄存器中因为想要**从三环进入到零环首先必须要提权**，提权需要切换 CS、SS、EIP、ESP。

sysenter 指令执行时，CPU会将 MSR 寄存器中的值直接写入相关寄存器，没有读内存的过程，所
以叫快速调用，本质是一样的！
1. CS 的权限由 3 变为 0，意味着需要新的 CS
2. SS 与 CS 的权限永远一致，所以需要新的 SS
3. 权限发生切换的时候，堆栈也一定会切换，需要新的 ESP
4. 进 0 环后代码的位置，需要 EIP

在了解 sysenter 指令之前，要先了解一个寄存器，叫 MSR。操作系统并没有公开这个寄存器的内部细节。但是我们可以知道这个寄存器的部分含义，如下图：
- 0x174 保存的是 CS
- 0x175 保存的是 ESP
- 0x176 保存的是 EIP
![[个人汇总-杂七杂八/res/11.png]]
![[个人汇总-杂七杂八/res/12.png]]

如果想查看msr寄存器174就可以使用下面的指令
```dbg
kd> rdmsr 174
msr[174] = 00000000`00000008
```

sysenter 快速调用指令完成的事情就是从 msr 寄存器里拿到 174、175、176 的值，覆盖原来寄存器的值。

MSR寄存器只提供了三个寄存器分别是ESP、EIP、CS，那么 SS 谁提供的呢？
- sysenter 默认算法，SS = CS+8（具体细节请参考Intel白皮书第二卷 搜索sysenter）
- 这个SS的值实际上是写死的。示例：如果提权之后的CS的值为8，那么 SS=CS+8=0x10

**快速调用的内核函数KiFastCallEntry**
![[个人汇总-杂七杂八/res/13.png]]

---

# 六、进入零环方式二：KiIntSystemCall

如果当前CPU不支持快速调用的话，那么它的实现方式是通过 int 0x2E 中断门来进入零环。

中断门进零环，门描述符里保存有CS和EIP，需要的 CS、EIP 在 IDT 表中，需要查内存(SS与ESP由TSS提供)。
![[个人汇总-杂七杂八/res/14.png]]

如果是通过中断门的方式进入到零环的话，最终EIP会指向哪呢？这就要查看IDT表了。

首先查看idt表的基址
```dbg
kd> r idtr
idtr=80b95400
```

接着查看IDT表项0x2E的位置的段描述符
```dbg
kd> dq 80b95400+0x2E*8
80b95570  83e8ee00`00083fee 83e88e00`000876b0
80b95580  83e88e00`000836b0 83e88e00`000836ba
80b95590  83e88e00`000836c4 83e88e00`000836ce
80b955a0  83e88e00`000836d8 83e88e00`000836e2
80b955b0  83e88e00`000836ec 83e28e00`00089104
80b955c0  83e88e00`00083700 83e88e00`0008370a
80b955d0  83e88e00`00083714 83e88e00`0008371e
80b955e0  83e88e00`00083728 83e88e00`00083732
```

通过拆分83e8ee00\`00083fee这个中断门描述符可以得出CS段选择子为0008，EIP为83e83fee。也就是说API通过中断门的方式最终会跳转到0x83e83fee。接着查看一下这个地址的反汇编
```dbg
kd> u 83e83fee
nt!KiSystemService:
83e83fee 6a00            push    0
83e83ff0 55              push    ebp
83e83ff1 53              push    ebx
83e83ff2 56              push    esi
83e83ff3 57              push    edi
83e83ff4 0fa0            push    fs
83e83ff6 bb30000000      mov     ebx,30h
83e83ffb 668ee3          mov     fs,bx
```
KiSystemService 函数的地址是8开头的，而且模块是nt不再是ntdll。也就是说
- 中断门调用的内核函数是 KiSystemService
- KiSystemService是 KiIntSystemCall 中断门提权`int 2Eh`之后的EIP的位置

到这里，API已经完成了从三环进入零环的过程。

int 0x2E 和 sysenter 两种进入零环的方式的本质都是**切换寄存器**。

---

# 七、总结

sysenter快速调用指令完成的事情就是从msr寄存器里拿到174 175和176的值，覆盖原来寄存器的值。int 0x2E和sysenter两种进入零环的方式的本质都是**切换寄存器**。

还有一个问题在于，通过msr寄存器只能拿到三个值，分别是CS ESP和EIP，那么SS来自于哪呢？这个SS的值实际上是写死的。举个例子来说，如果提权之后的CS的值为8，那么SS=CS+8=0x10。(具体细节请参考Intel白皮书第二卷 搜索sysenter)

![[平台开发-Windows/res/8.png]]

---

> 版权声明©：
>
> 本文为 CHA.ATY 的原创文章，遵循 [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) 许可证进行授权，转载请附上原文出处链接及本声明。
>
> 作者：CHA.ATY
>
> 邮箱：2165150141@qq.com