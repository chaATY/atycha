---
title: CSGO 辅助思路 & VAC 保护分析
date: 2023-11-26
author: CHA.ATY
environment:
  - Windows10-22H2_19045.3570
tags:
  - Game
---

#  一、整体门槛与难点

Vanguard反作弊系统是一个比较注重门槛的保护系统，和国内的重检测反作弊系统整体设计和实现思路还是不太一样的。这里先讨论一下其门槛与分析难点，在后文对这些再进行分块讨论。

1. 在游戏安装后，会同时安装Riot Vanguard到 _C:\Program Files\Riot Vanguard_ 目录下。其整体反作弊实现由驱动 _vgk.sys_ 和三环程序 _vgc.exe_ 实现
2. vgk驱动开机自启，boot模式启动，游戏启动时会校验这一状态若不是开机自启则无法开启游戏。vgk驱动会拦截所有无签驱动、漏洞驱动和黑驱动的加载。即，所有公开ARK和一些Rootkit工具，甚至Dbgview均无法使用。但是经过测试，对驱动添加带时间戳的签名后可成功加载。
3. Ring3和Ring0均无法写游戏内存（MmCopyVirtualMemory返回STATUS_MEMORY_NOT_ALLOCATED）
4. FAKE UWorld
5. 对特定的一些分析工具会有专门的检测，并在检测到后写出标记对该机器拉黑
6. 各类回调几乎全部注册（进程、线程、对象、镜像加载、注册表等）
![](网络安全-GameSecurity/res/71.png)

---

# 二、调试

## Ring0

因为vgk驱动开机自启+上的不是常规的VMP壳，ARK工具无法使用也无法用常规的模拟执行框架分析其驱动，所以希望能够调试其驱动模块。尝试了三种方案，均没有成功：

1. 去特征Vmware+VirtualKD
2. 去特征Vmware+VmwareHardenedLoader+IDA+gdb
3. ida+gdbstub+qemu+virtio

看外网似乎 [qemu去特征](https://github.com/doomedraven/Tools/blob/master/Virtualization/kvm-qemu.sh) + memflow-KVM + USB/显卡穿透 这个方案可以调试。时间问题还没有去尝试，后续的分析均用模拟器完成的，可见 [vgk驱动分析](http://www.qfrost.com/posts/vanguard/#vgk%E9%A9%B1%E5%8A%A8%E5%88%86%E6%9E%90) 部分。

## Ring3

尝试了很多方法，包括VT调试器，均没有成功。整体反作弊系统搭配驱动有很强的反调试门槛。限于时间原因，暂时搁置，进行其他方向的分析。

---

# 三、读写内存

Vanguard的一个大门槛就是写不了内存。具体表现是Ring3调用ReadProcessMemory和WriteProcessMemory返回失败，Ring0调用MmCopyVirtualMemory返回STATUS_MEMORY_NOT_ALLOCATED。因为调试不了这个问题卡了很久。后面发现vgk驱动Hook了所有其他驱动的导入表，对危险函数（比如MmCopyVirtualMemory）进行了Hook。驱动里直接打印地址即可验证：
```cpp
	SYSTEM_MODULE_INFORMATION_ENTRY ntoskrnl = { 0 }, vgk = { 0 }, QSafe = { 0 };
	if (TRUE == Utils::find_kernel_module("ntoskrnl.exe", &vgk)) {
		kprintf("[QSafe] : ntoskrnl.exe : 0x%p : 0x%X\n", vgk.image_base, vgk.image_size);
	}
	else
		kprintf("[QSafe] : Not find ntoskrnl.exe\n");
	if (TRUE == Utils::find_kernel_module("vgk.sys", &vgk)) {
		kprintf("[QSafe] : vgk.sys : 0x%p : 0x%X\n", vgk.image_base, vgk.image_size);
	}
	else
		kprintf("[QSafe] : Not find vgk.sys\n");
	if (TRUE == Utils::find_kernel_module("QSafe.sys", &QSafe)) {
		kprintf("[QSafe] : QSafe.sys : 0x%p : 0x%X\n", QSafe.image_base, QSafe.image_size);
	}
	else
		kprintf("[QSafe] : Not find QSafe.sys\n");

	kprintf("[QSafe] : MmCopyMemory : %p\n", MmCopyMemory);
	kprintf("[QSafe] : MmCopyVirtualMemory : %p\n", MmCopyVirtualMemory);
	kprintf("[QSafe] : MmGetSystemRoutineAddress : %p\n", MmGetSystemRoutineAddress);
    kprintf("[QSafe] : ZwProtectVirtualMemory : %p\n", ZwProtectVirtualMemory);
```
```bash
[QSafe] : ntoskrnl.exe : 0xFFFFF8004AE00000 : 0x1046000
[QSafe] : vgk.sys : 0xFFFFF80054940000 : 0x1506000
[QSafe] : QSafe.sys : 0xFFFFF80096F50000 : 0x4DD000
[QSafe] : MmCopyMemory : FFFFF8004B13F7B0
[QSafe] : MmCopyVirtualMemory : FFFFF8005496726C
[QSafe] : MmGetSystemRoutineAddress : FFFFF80054967390
[QSafe] : ZwProtectVirtualMemory : 0xfffff8004b1f4510
```

可以看到，vgk IAT Hook了我驱动的MmCopyVirtualMemory从而实现监控驱动的读写内存行为。但是其并没有Hook MmCopyMemory、MmGetSystemRoutineAddress和ZwProtectVirtualMemory函数。所以可以通过MmGetSystemRoutineAddress获取真实函数地址再调用从而绕过其IAT Hook

```cpp
// anti vgk hook MmCopyVirtualMemory
UNICODE_STRING usMmCopyVirtualMemory = { 0 };
Utils::string::CHAR_TO_UNICODE_STRING("MmCopyVirtualMemory", &usMmCopyVirtualMemory);
PVOID rawMmCopyVirtualMemory = MmGetSystemRoutineAddress(&usMmCopyVirtualMemory);
kprintf("[QSafe] : rawMmCopyVirtualMemory : %p\n", rawMmCopyVirtualMemory);

SIZE_T BytesRead = 0;
if (protocol == READ_PROTOCOL)                   // ReadVirtualMemory
  nStatus = Utils::call<NTSTATUS>(rawMmCopyVirtualMemory, ProcessObj, BaseAddress, PsGetCurrentProcess(), (void*)OutputAddress, RegionSize, PreviousMode, &BytesRead);
else if (protocol == WRITE_PROTOCOL)              // WriteVirtualMemory
  nStatus = Utils::call<NTSTATUS>(rawMmCopyVirtualMemory, PsGetCurrentProcess(), BaseAddress, ProcessObj, (void*)OutputAddress, RegionSize, PreviousMode, &BytesRead);
```

至此，可以驱动读写游戏内存。

结论是：**利用vgk.sys的最先启动特点，拦截后续所有驱动的加载，并Hook驱动的IAT以达到监控敏感函数调用且不触发PatchGuard的效果（因为Hook的IAT而不是InlineHook）。绕过方案是通过其他方式获得API函数真实地址（MmGetSystemRoutineAddress或遍历导出表都可以）并调用**

这种方法的监控确实有效果，但是非常激进，因为会Hook后续所有驱动的IAT，很容易与其他安全方案或杀软等工具产生冲突。

---

# 四、FAKE UWorld

PACKMAN壳和VGK驱动联动实现的一个门槛方案，出发点是打击跨进程类外挂，目前来看确实有很好的效果（外网没有看到海外服跨进程外挂的资料，相关外挂资料均为注式的进程内外挂）。PACKMAN壳修改UWorldStateKey来保证游戏向UE GWORLD写入Magic Number，该指针从外部看来指向一块无效的内存。如下面这段代码，是*UWorldProxy::operate=*函数，r14为解密后真正的GWorld地址，r15为要赋值的World指针，他们指向的空间在外部进程看来均是不可访问的。
![](网络安全-GameSecurity/res/72.png)

为了保证游戏本身的正常访问，VGK驱动Hook ntoskrnl.KiClearLastBranchRecordStack.g_LbrClearStack，该函数会在SwapContext时被调用。VGK驱动对游戏白名单线程在SwapContext时替换CR3，将真正GWorld地址（PACKMAN写入的Magic Number）和保存有真正World对象的内存页面恢复，从而保证游戏白名单线程通过World指针访问到正确的World对象。而其他线程由于没有执行SwapContext中的替换CR3操作，认为真正GWorld地址和World指针指向的内存页是无法访问的。
![](网络安全-GameSecurity/res/73.png) ![](网络安全-GameSecurity/res/74.png)

从外网的资料来看，外挂往往剑走偏锋来绕过这种保护。VGK将存有真实数据的内存页保存在一块固定大小固定tag的pool内存上，外挂枚举内核中特定大小特定tag的pool内存（uc上称之为Guard Region），找到这块内存页，并从中找到真实的World指针。笔者在2023年10月分析Valorant+vgk发现这块内存+0x60偏移上依旧保存着Wolrd指针，但是这个World指针指向的内存空间对其他进程来说是也是不可见的了，外挂必须注入游戏进程空间来通过World指针来读取游戏数据。  
相关的资料参考：[unknowncheats : Getting guarded region in usermode](https://www.unknowncheats.me/forum/valorant/524469-getting-guarded-region-usermode.html)

---

# 五、反注入

高位注入、PML4这些核弹玩法暂不讨论，下面分析一下Vanguard对其他较为常规一些的注入方式的对抗。

## 远线程注入

常规的远线程注入是不可取的，Vanguard注册了线程创建回调
![](网络安全-GameSecurity/res/75.png)

具体判定逻辑暂未分析，应该和线程启动点入口有关，凡是不合规的线程启动都会导致游戏退出
![](网络安全-GameSecurity/res/76.png)

## 消息钩子注入

找了个标准的消息钩子注入方法进行测试 [SetWindowsHookEx-Injector](https://github.com/DrNseven/SetWindowsHookEx-Injector)

整一条行为序列：FindWindowW->GetWindowThreadProcessId->LoadLibraryEx->GetProcAddress->SetWindowsHookEx(WH_GETMESSAGE)->PostThreadMessage  
都是成功的，但注入后没有效果，认为反作弊系统应该对最后的消息做了过滤。

后面测试发现，注入的dll若是带签名可以成功通过消息钩子注入；若不带签名，dll的内存可以映射到游戏中但无注入效果（DllMain没有被执行）

## InlineHook+ManualMap

通过驱动调用VirtualAlloc向游戏进程申请内存写入Dll和Shellcode，在游戏中寻找Hook点执行ManualMap Shellcode从而加载Dll。在ByPass vgk的内存读写保护后，这个方法我是跑通了。
![](网络安全-GameSecurity/res/77.png)

但是内存属性这里有坑。我申请可读可写可执行的内存用于注入dll，在一段时间后游戏会crash
![](网络安全-GameSecurity/res/78.png)

但是若驱动申请可读可写不可执行内存，通过页表修改X位使该内存具有执行权限，这个问题消失。以此推断Vanguard扫描了VAD上具有执行权限的内存段。
```cpp
CR3 cr3{ };
cr3.Flags = __readcr3();
CR4 cr4{};
cr4.Flags = __readcr4();
cr4.Flags &= ~CR4_SMEP_ENABLE_FLAG;
cr4.Flags &= ~CR4_SMAP_ENABLE_FLAG;
__writecr4(cr4.Flags);
for (uintptr_t current_address = address; current_address < address + size; current_address += 0x1000)
{
  const PAGE_INFORMATION page_information = get_page_information((void*)current_address, cr3);
  page_information.PDE->ExecuteDisable = 0;
  __invlpg((void*)current_address);

  if (!page_information.PDE || (page_information.PTE && !page_information.PTE->Present))
  { }
  else
  {
    page_information.PTE->ExecuteDisable = 0;
    __invlpg((void*)current_address);
  }
  __invlpg((void*)current_address);
}
cr3.Flags &= 0x7FFFFFFFFFFFFFFF;
__writecr3(cr3.Flags);
```

## unwind info

---

# 六、反CE

### **弹窗退出**

运行CE游戏直接弹窗退出。
![](网络安全-GameSecurity/res/79.png)

后面经过分析发现反作弊在运行时扫描CE特征，并在CE进程启动时驱动回调拦截CE进程初始化过程并检查。对于反作弊系统运行时扫描CE特征的检测，我通过对CE源代码修改和二进制文件加壳进行躲避，源码主要修改点有：Title、图标、For Windows Name、Target file name、Caption、Form Name、Version Info、Service Name、DBKKernel Name、ico、Hook OutputDebugString。 源码修改重编译后，加壳，先运行CE后运行游戏不会被弹窗。

但是若是先运行游戏，再运行CE，依然会被弹窗。对于这个问题也去分析了一下原因
![](网络安全-GameSecurity/res/80.png)

观察表现，游戏启动后，启动CE，CE进程不会出现，但游戏弹窗，只有把弹窗关闭后CE进程才出现。认为是某个回调拦截了CE的启动或CE的启动过程。考虑到先启动CE再运行游戏没有被弹窗退出，故认为CE进程内的静态特征应该是全部被抹掉了，启动时被检测大概率是初始化的某一步被检测到了。分析CE源码，发现CE在启动时，会向注册表写入键值用于服务注册和驱动通信等操作。同时Vanguard注册了注册表回调，故认为极大可能是CE启动时向注册表写键值这一步被检测拦截了。具体验证因为时间关系还未实施。

## 读写内存

使用魔改版CE先启动CE再启动游戏可以不弹窗，但是无法读写扫描游戏内存。使用驱动对CE句柄进行回调提权依旧不可行。开启CE驱动的DBVM功能，游戏会主动掉线（认为VGK驱动检测VT环境）。
![](网络安全-GameSecurity/res/81.png)

想到的解决方案有两个：
1. 自己编写一个CE插件，加载自己的驱动接管CE的内存读写操作，并且自己的驱动绕过MmCopyVirtualMemory钩子或使用其他方式读写内存。
2. 使用CE的DBK驱动。特意去看了一下CE DBK驱动的源码，对应其 _IOCTL_CE_READMEMORY_ 和 _IOCTL_CE_WRITEMEMORY_ 两个dispatch。分析发现CE DBK驱动读写内存是使用KeAttachProcess+memcpy实现的，也就是切CR3直接读写，这种方式不会受到MmCopyVirtualMemory的IAT Hook影响。但是vgk驱动开机自启拦截所有驱动的加载，其中也包括CE的dbk驱动。我的做法是修改CE源码，修改DBK驱动服务名、驱动程序名、符号链接名后，重编译加壳加签名，可成功加载DBK驱动读写游戏内存。
![](82.png)

**结论：魔改去特征CE重编译加壳加签名，先运行CE再运行游戏，使用CE魔改后的DBK驱动，可成功读写扫描游戏内存**

---

# 七、vgk驱动分析

**分析时vgk版本：1.12.0.207**

因为vgk驱动加的不是传统的VMP变异，常规的模拟执行框架跑不出东西。我魔改了一个框架，原理是使用Unicorn+VEH实现模拟执行，映射系统模块，Hook指令读内存和指令写内存的中断，追踪API调用和关键结构体的读写。vgk的技术力应该是相当之高了，目前只跑了DriverEntry，可以看到里面内容较多且杂、乱。部分分析结论一定程度上基于自身经验与推测。这边先输出结论。

在vgk驱动入口函数DriverEntry中：

1. vgk驱动写出日志到 _C:\Program Files\Riot Vanguard\Logs_ 文件夹中
2. vgk驱动程序依赖写出文件vgkbootstatus.dat判定当前驱动是否是开机自启的
3. vgk驱动初始化时使用 _ZwQuerySystemInformation SystemModuleInformation(0x4D)_ 扫描系统中已存在的模块并扫描其内存判黑
4. vgk通过int20检测当前系统是否处于 _过PG_ 状态
5. vgk驱动使用多种反调试技术并多次调用，包括不限于：DbgPrompt、硬断寄存器清空、注册SEH接收主动触发的异常、读取KdDebuggerEnabled和KdDebuggerNotPresent变量、使用错误MSR指令、MSR_IA32_DEBUGCTL、iretq指令等
6. vgk驱动使用错误传参等方式检测模拟器
7. vgk驱动修改瞬写MSR_LSTAR检测VT
8. vgk驱动入口读取LastBranchFromIP_MSR和MSR_LASTBRANCH_TOS检测模拟鼠标类外挂
9. vgk驱动Hook ntoskrnl.KiClearLastBranchRecordStack.g_LbrClearStack在SwapContext时获取执行时机，对游戏白名单线程替换含有正确游戏数据的真页表
10. vgk驱动DriverEntry函数内完成 进程、线程、对象、镜像加载、注册表、电源状态、关机等回调函数的注册。
11. vgk驱动DriverEntry函数通过CiCheckSignedFile校验已存在的驱动模块签名与完整性，判定合法性
12. vgk驱动DriverEntry函数会收集硬件信息，包括Boot GUID、硬盘序列号等。

下面根据模拟执行的结果，按照vgk驱动的执行顺序，分析其实现细节。整体上还是有一些规律的，所以我将其DriverEntry函数简单划分为几个阶段

## 第一部分初始化与状态检测阶段

在DriverEntry开始，先注册了驱动卸载函数
```log
[19d8]  Executing ntoskrnl.exe!RtlDuplicateUnicodeString
[19d8]  	RtlDuplicateUnicodeString : \REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\vgk = 0
[19d8]  Emulating write to MainModule.DriverObject+00000068     // _DRIVER_OBJECT.DriverUnload
```

然后获取系统当前时间再创建log文件
```log
[19d8]  Emulating read from KUSER_SHARED_DATA+00000014	// SystemTime
[19d8]  Executing ntoskrnl.exe!ExSystemTimeToLocalTime
[19d8]  Executing ntoskrnl.exe!RtlTimeToTimeFields
[19d8]  Executing ntoskrnl.exe!vswprintf_s
[19d8]  	Result : 2023-01-29_04-03-33
[19d8]  Executing ntoskrnl.exe!ExAllocatePoolWithTag
[19d8]  Executing ntoskrnl.exe!swprintf_s
[19d8]  	Result : \??\c:\Program Files\Riot Vanguard\Logs\vgk_2023-01-29_04-03-33.log
[19d8]  Executing ntoskrnl.exe!ExFreePool
[19d8]  Executing ntoskrnl.exe!RtlInitUnicodeString
[19d8]  Executing ntoskrnl.exe!IoCreateFileEx
[19d8]  	Creating file : \??\c:\Program Files\Riot Vanguard\Logs\
[19d8]  	Return : c000003a
[19d8]  Executing ntoskrnl.exe!ZwClose
[19d8]  	Closing Kernel Handle : 0
[19d8]  Executing ntoskrnl.exe!RtlInitUnicodeString
[19d8]  Executing ntoskrnl.exe!IoCreateFileEx
[19d8]  	Creating file : \??\c:\Program Files\Riot Vanguard\Logs\vgk_2023-01-29_04-03-33.log
[19d8]  Executing ntoskrnl.exe!ExFreePool
```

并可以看到向其中写入了日期版本号等信息和系统版本号等信息
```log
[19d8]  Executing ntoskrnl.exe!RtlTimeToTimeFields
[19d8]  Executing ntoskrnl.exe!vswprintf_s
[19d8]  	Result : 2023-01-29_04-03-33
[19d8]  Executing ntoskrnl.exe!vswprintf_s
[19d8]  	Result : 1000004A
[19d8]  Executing ntoskrnl.exe!ExAllocatePoolWithTag
[19d8]  Executing ntoskrnl.exe!_vsnwprintf
[19d8]  Executing ntoskrnl.exe!ExAllocatePoolWithTag
[19d8]  Executing ntoskrnl.exe!swprintf_s
[19d8]  	Result : [2023-01-29_04-03-33] [!] [1000004A]: 1.12.0.207 ; Thu Nov 10 20:17:38 2022	// 日期和vgk驱动版本号

[19d8]  Emulating read from KUSER_SHARED_DATA+0000026c	// NtMajorVersion
[19d8]  Emulating read from KUSER_SHARED_DATA+00000260	// NtBuildNumber
[19d8]  Emulating read from KUSER_SHARED_DATA+00000270	// NtMinorVersion
[19d8]  Emulating read from KUSER_SHARED_DATA+00000014  // SystemTime
[19d8]  Executing ntoskrnl.exe!RtlTimeToTimeFields
[19d8]  Executing ntoskrnl.exe!vswprintf_s
[19d8]  	Result : 2023-01-29_04-03-33
[19d8]  Executing ntoskrnl.exe!vswprintf_s
[19d8]  	Result : 1000004E
[19d8]  Executing ntoskrnl.exe!ExAllocatePoolWithTag
[19d8]  Executing ntoskrnl.exe!_vsnwprintf
[19d8]  Executing ntoskrnl.exe!ExAllocatePoolWithTag
[19d8]  Executing ntoskrnl.exe!swprintf_s
[19d8]  	Result : [2023-01-29_04-03-33] [!] [1000004E]: 10 ; 0 ; 19042		// 系统版本号  Win10 19042
[19d8]  Executing ntoskrnl.exe!ExFreePool
[19d8]  Executing ntoskrnl.exe!ExFreePool
```

接下来，vgk驱动会去写关键文件vgkbootstatus.dat，文件内容应该与驱动是否是boot状态启动有关。游戏启动时会读取该文件判定本次vgk驱动启动是否是开机自启的，若不是则会要求用户重启电脑。（保证游戏运行该次开机vgk驱动boot加载拦截外挂驱动加载，确保外挂驱动启动时机一定在vgk驱动之后）
```log
[19d8]  Emulating read from KUSER_SHARED_DATA+0000026c  // NtMajorVersion
[19d8]  Emulating read from KUSER_SHARED_DATA+00000270  // NtMinorVersion
[19d8]  Executing ntoskrnl.exe!wcscpy_s
[19d8]  Executing ntoskrnl.exe!wcscat_s
[19d8]  Executing ntoskrnl.exe!wcscat_s
[19d8]  Executing ntoskrnl.exe!RtlInitUnicodeString
[19d8]  Executing ntoskrnl.exe!IoCreateFileEx
[19d8]  	Creating file : \??\C:\Windows\vgkbootstatus.dat
[19d8]  	Return : 00000000
[19d8]  Executing ntoskrnl.exe!ZwWriteFile
[19d8]  Executing ntoskrnl.exe!ZwFlushBuffersFile
[19d8]  Executing ntoskrnl.exe!ZwClose
[19d8]  	Closing Kernel Handle : 160
```

我尝试拦截vgk驱动对该文件的写入操作，vgk驱动会写出错误日志并返回STATUS_FAILED_DRIVER_ENTRY直接加载失败
```log
[0708]  Executing ntoskrnl.exe!swprintf_s
[0708]          Result : [2023-01-12_08-36-59] [-] [E0000050]: C0000365
[0708]  Executing ntoskrnl.exe!ExFreePool
[0708]  Executing ntoskrnl.exe!ExFreePool
[0708]  Main Thread Done! Return = c0000365		// STATUS_FAILED_DRIVER_ENTRY
```

接下来vgk驱动调用了 KeIpiGenericCall 去调用了一个函数，里面清掉了所有核的DR7硬断寄存器。KeIpiGenericCall函数内会调用BroadcastFunction函数，通过IPI（Inter-Processor Interrupt）使所有核心执行一个函数，也就是函数的执行不会受到其他核干扰的效果。在这里就是将所有核的DR7清掉了。在后续，还有多次使用了这个方法。
```code
[19d8]  Executing ntoskrnl.exe!KeIpiGenericCall
[19d8]  	BroadcastFunction: vgk.sys + 0x1b5c
[19d8]  	Content: 0
[19d8]  Clearing Interrupts
[19d8]  Writing 0 to DR7
[19d8]  Restoring Interrupts
[19d8]  	IPI Returned : 0
```

然后 vgk调用ZwQuerySystemInformation并传递SystemInformationClass参数为SystemModuleInformation(0x4D)枚举了系统模块信息，即，尝试获取先于vgk驱动加载的驱动的信息，进行判定
```code
[19d8]  Reading CR0
[19d8]  Executing ntoskrnl.exe!_stricmp
[19d8]  Executing ntoskrnl.exe!ZwQuerySystemInformation
[19d8]  	Class 0000004d status : c0000004
[19d8]  Executing ntoskrnl.exe!ExAllocatePoolWithTag
[19d8]  Executing ntoskrnl.exe!ZwQuerySystemInformation
[19d8]  	Class 0000004d status : 00000000            
[19d8]  	Class 0000004d success
[19d8]  	Base is : 7ff6770f0000
[19d8]  Executing ntoskrnl.exe!ExFreePool
[19d8]  Executing ntoskrnl.exe!ZwQuerySystemInformation
[19d8]  	Class 0000004d status : c0000004
[19d8]  Executing ntoskrnl.exe!ExAllocatePoolWithTag
[19d8]  Executing ntoskrnl.exe!ZwQuerySystemInformation
[19d8]  	Class 0000004d status : 00000000
[19d8]  	Class 0000004d success
[19d8]  	Base is : 7ff6770f0000
[19d8]  Executing ntoskrnl.exe!ExFreePool
[19d8]  Executing ntoskrnl.exe!ZwQuerySystemInformation
[19d8]  	Class 0000004d status : c0000004
[19d8]  Executing ntoskrnl.exe!ExAllocatePoolWithTag
[19d8]  Executing ntoskrnl.exe!ZwQuerySystemInformation
[19d8]  	Class 0000004d status : 00000000
[19d8]  	Class 0000004d success
[19d8]  	Base is : 7ff6770f0000
```

然后接下来大量读取相关数据，认为是获取已存在驱动模块的相关信息
```log
[19d8]  Getting data @ ntoskrnl.exe!MmHighestUserAddress
[19d8]  Getting data @ ntoskrnl.exe!MmHighestUserAddress
[19d8]  Getting data @ ntoskrnl.exe!MmHighestUserAddress
[19d8]  Getting data @ ntoskrnl.exe!MmHighestUserAddress
................................................................
```

然后，vgk分别创建了一个事件对象，一个时钟对象，一个回调对象
```log
[19d8]  Executing ntoskrnl.exe!KeInitializeEvent
[19d8]  	Event object : 7ff6addb82f8
[19d8]  Executing ntoskrnl.exe!KeInitializeTimer
[19d8]  Executing ntoskrnl.exe!KeSetTimer
[19d8]  	Timer object : 7ff6addb9350
[19d8]  	DPC object : 0
[19d8]  Executing ntoskrnl.exe!ExCreateCallback
[19d8]  	Callback object : 92790fefd8
[19d8]  	*Callback object : 0
[19d8]  	Callback name : \Callback\542875F90F9B47F497B64BA219CACF69
```

到此位置，第一部分初始化阶段完成，vgk驱动开始检测调试器。

## 反调试阶段

反调试阶段内，vgk驱动会连续调用多种不同的反调试、反模拟器和PG检测手段。并且这一连续的过程在后面多次穿插出现。认为整个阶段被封装成一个函数多次穿插调用。

vgk驱动首先用int20检测了当前是否处于ByPassPG环境下。int20会执行KiSwInterrupt，如果没有PatchGuard Context就会清栈蓝屏。所以其实这个手段与其说是检测PG，不如说是主动触发PG检测，如果系统ByPassPG，就会蓝屏。
```log
[19d8]  [Info] Checking for Patchguard (int 20)
```

然后注册了SEH调用DbgPrompt，该API会在有内核调试器附加时向用户请求输入，若无调试器则会抛出异常，转发给SEH。通过SEH内是否接受到异常来检测调试器。
```log
[19d8]  Executing ntoskrnl.exe!DbgPrompt
[19d8]  Executing ntoskrnl.exe!__C_specific_handler
```

清空硬断寄存器Dr7
```log
[19d8]  Writing 0 to DR7
```

读取了内核调试标志变量KdDebuggerEnabled和KdDebuggerNotPresent，并且为了防止替换导出表还直接去KUSER_SHARED_DATA上读了一次。变量验完后再调用KdChangeOption判断返回值是否是STATUS_DEBUGGER_INACTIVE，完毕后再清除一次硬断寄存器。
```log
[19d8]  Getting data @ ntoskrnl.exe!KdDebuggerEnabled
[19d8]  Getting data @ ntoskrnl.exe!KdDebuggerNotPresent
[19d8]  Emulating read from KUSER_SHARED_DATA+000002d4  // KdDebuggerEnabled
[19d8]  Executing ntoskrnl.exe!KdChangeOption
[19d8]  Writing 0 to DR7
```

给出了一条错误的MSR指令，并主动进入SEH异常
```log
[19d8]  Reading from unsupported MSR : 4b564d00
[19d8]  Failed to emulate instruction
[19d8]  Executing ntoskrnl.exe!__C_specific_handler
```

速写瞬改MSR_IA32_DEBUGCTL
```log
[19d8]  Clearing Interrupts
[19d8]  Reading MSR DBGCTL_MSR : 0
[19d8]  Writing MSR DBGCTL_MSR : 3
[19d8]  Reading MSR DBGCTL_MSR : 3
[19d8]  Writing MSR DBGCTL_MSR : 0
[19d8]  Restoring Interrupts
```

执行iretq指令反调试反模拟器
```log
[19d8]  Clearing Interrupts
[19d8]  [Info] IRET Timing Emulation
[19d8]  Restoring Interrupts
[19d8]  Clearing Interrupts
[19d8]  [Info] IRET Timing Emulation
[19d8]  Restoring Interrupts
[19d8]  Clearing Interrupts
[19d8]  [Info] IRET Timing Emulation
[19d8]  Restoring Interrupts
[19d8]  Clearing Interrupts
[19d8]  [Info] IRET Timing Emulation
[19d8]  Restoring Interrupts
[19d8]  Clearing Interrupts
[19d8]  [Info] IRET Timing Emulation
[19d8]  Restoring Interrupts
```

反调试阶段到此结束

### **核心初始化阶段**

第一次调用反调试函数结束后，vgk获取了当前的EPROCESS和System进程的EPROCESS
```log
[19d8]  Executing ntoskrnl.exe!IoGetCurrentProcess
[19d8]  Emulating read from PID4.ETHREAD+000000b8       // ethread->Tcb.ApcState.Process
[19d8]  	Returning : 7ff7b9bc1000
[19d8]  Getting data @ ntoskrnl.exe!PsInitialSystemProcess
```

而且vgk驱动尝试打开vgk_CHEATINGBAD对象，这个对象我系统上是不存在的所以返回了失败，具体暂时不清楚是什么用处，猜测可能和机器码封禁有关。
```log
[19d8]  Executing ntoskrnl.exe!ZwOpenSection
[19d8]  	Section name : \Device\vgk_CHEATINGBAD, access : f001f, ret : c0000034
```

创建了一个回调对象
```log
[19d8]  Executing ntoskrnl.exe!ExCreateCallback
[19d8]  	Callback object : 92790fef60
[19d8]  	*Callback object : 0
[19d8]  	Callback name : \Callback\542875F90F9B47F497B64BA219CACF69
```

接下来通过ZwQuerySystemInformation和PsLoadedModuleList两种方法获取驱动模块信息，并获取物理内存进行访问扫描
```log
[19d8]  Executing ntoskrnl.exe!ZwQuerySystemInformation
[19d8]  	Class 0000004d status : c0000004
[19d8]  Executing ntoskrnl.exe!ExAllocatePoolWithTag
[19d8]  Executing ntoskrnl.exe!ZwQuerySystemInformation
[19d8]  Executing ntoskrnl.exe!ExFreePool
[19d8]  Getting data @ ntoskrnl.exe!MmHighestUserAddress
[19d8]  Getting data @ ntoskrnl.exe!PsLoadedModuleList
[19d8]  Emulating read from LdrEntry.ntoskrnl.exe+00000110
[19d8]  Executing ntoskrnl.exe!MmIsAddressValid
[19d8]  Reading CR3
[19d8]  Executing ntoskrnl.exe!MmGetPhysicalAddress
[19d8]  	Getting Physical address for 8040201000
[19d8]  	Return : 8040201
[19d8]  Executing ntoskrnl.exe!MmGetPhysicalAddress
[19d8]  	Getting Physical address for 10080402000
[19d8]  	Return : 10080402
[19d8]  Executing ntoskrnl.exe!MmGetPhysicalAddress
[19d8]  	Getting Physical address for 180c0603000
[19d8]  	Return : 180c0603
[19d8]  Executing ntoskrnl.exe!MmGetPhysicalAddress
[19d8]  	Getting Physical address for 20100804000
[19d8]  	Return : 20100804
................................................................
```

扫描完毕后

接下来使用MDL申请了一块内核空间并调用了2048次RtlRandomEx获取了2048个数，每次传递的随机数种子都不一样
```cpp
[19d8]  Executing ntoskrnl.exe!ExAllocatePoolWithTag
[19d8]  Executing ntoskrnl.exe!ExAllocatePoolWithTag
[19d8]  Executing ntoskrnl.exe!IoAllocateMdl
[19d8]  Executing ntoskrnl.exe!MmBuildMdlForNonPagedPool
[19d8]  Executing ntoskrnl.exe!IoAllocateMdl
[19d8]  Executing ntoskrnl.exe!MmBuildMdlForNonPagedPool
[19d8]  Executing ntoskrnl.exe!RtlRandomEx
[19d8]  	Seed is a7dee806
[19d8]  Executing ntoskrnl.exe!RtlRandomEx
[19d8]  	Seed is 64d0ad0c
[19d8]  Executing ntoskrnl.exe!RtlRandomEx
[19d8]  	Seed is cede0f85
[19d8]  Executing ntoskrnl.exe!RtlRandomEx
[19d8]  	Seed is 2e75bc4e
[19d8]  Executing ntoskrnl.exe!RtlRandomEx
[19d8]  	Seed is a42e3fef
[19d8]  Executing ntoskrnl.exe!RtlRandomEx
[19d8]  	Seed is 11a9341
[19d8]  Executing ntoskrnl.exe!RtlRandomEx
[19d8]  	Seed is ac485ec
................................................................
```

然后创建了两条线程，但是这两条线程一直在调用KeDelayExecutionThread等待事件，具体作用暂时没有分析到。
```log
[19d8]  Executing ntoskrnl.exe!PsCreateSystemThread
[2e90]  Thread Initialized, starting...
[19d8]  Executing ntoskrnl.exe!PsCreateSystemThread
[271c]  Thread Initialized, starting...
[2e90]  Executing ntoskrnl.exe!KeDelayExecutionThread
[2e90]  	Sleep : 500
[271c]  Executing ntoskrnl.exe!KeDelayExecutionThread
[271c]  	Sleep : 500
................................................................
```

接下来主线程读取了两个标志，用于检测鼠标模拟类驱动外挂
```log
[19d8]  Reading MSR LastBranchFromIP_MSR : 0
[19d8]  Reading MSR MSR_LASTBRANCH_TOS : 0
```

大致原理是通过PMI（Performance Monitoring Interrupt）实现收集LBR（Last Branch Recorder）信息。CPU提供了性能监视（PM）功能，windows为这个功能设计了一个接口用于收集信息，也就是PMI。这个功能非常强大，甚至可以监控跨进程的内存读取（[看雪 - [原创]基于PMI实现对读写行为检测](https://bbs.kanxue.com/thread-274613.htm)），也有诸多的feature，包括PEBs/Intel PT/LBR等，而feature的开启就通过MSR标志位，比如这里判断这个MSR标志位来判断是否开启收集LBR信息的功能。LBR这个feature在windows10上是默认开启的，我这边因为是模拟环境所以没有开启。VGK发现LBR feature没有开启后会开启这个feature以收集上一次分支跳转/RET的地址。因为fps自瞄实现需要模拟鼠标，往往会call MouseClassServiceCallback函数。VGK挂钩了这个函数后，读取上一次的分支执行的地址，如果发现未知地址，则认为存在异常。这种检测方式的绕过思路是：call MouseClassServiceCallback函数前立马关闭LBR收集，调用完毕后马上恢复回来。

具体可以参考资料：  
[看雪 - [原创]某号称国外最强反作弊如何偷鸡监控和拦截鼠标输入](https://bbs.kanxue.com/thread-268012.htm)

还有其他的一些检测内核模拟鼠标的操作：  
[52pojie - [游戏安全] 驱动外挂的原理及检测手段](https://www.52pojie.cn/thread-1218621-1-1.html)

接下来开始注册回调，先注册了进程、线程、对象、镜像加载、注册表回调。
```log
[19d8]  Executing ntoskrnl.exe!PsSetCreateProcessNotifyRoutine
[19d8]  Executing ntoskrnl.exe!PsSetCreateProcessNotifyRoutineEx
[19d8]  Executing ntoskrnl.exe!PsSetCreateThreadNotifyRoutine
[19d8]  Executing ntoskrnl.exe!PsSetLoadImageNotifyRoutine
[19d8]  Executing ntoskrnl.exe!ObRegisterCallbacks
[19d8]  Executing ntoskrnl.exe!CmRegisterCallbackEx
```

而后注册了电源状态回调，该回调会在系统电源特征发生变化时调用
```log
[19d8]  Executing ntoskrnl.exe!ExCreateCallback
[19d8]  	Callback object : 7ff6addb83e8
[19d8]  	*Callback object : 0
[19d8]  	Callback name : \Callback\PowerState
[19d8]  Executing ntoskrnl.exe!ExRegisterCallback
```

接下来程序会通过系列函数判定当前系统中驱动模块的签名信息，并写出日志
```log
[19d8]  Emulating read from KUSER_SHARED_DATA+0000026c
[19d8]  Executing ntoskrnl.exe!IoCreateFileEx
[19d8]  Executing ntoskrnl.exe!ZwQueryInformationFile
[19d8]  	QueryInformationFile with class 00000005		// FileStandardInformation 
[19d8]  Executing ntoskrnl.exe!ExAllocatePoolWithTag
[19d8]  Executing ntoskrnl.exe!ZwReadFile
[19d8]  Executing cng.sys!BCryptOpenAlgorithmProvider
[19d8]  Executing cng.sys!BCryptGetProperty
[19d8]  Executing cng.sys!BCryptCreateHash
[19d8]  Executing cng.sys!BCryptHashData
[19d8]  Executing cng.sys!BCryptGetProperty
[19d8]  Executing cng.sys!BCryptFinishHash
[19d8]  Executing CI.dll!CiCheckSignedFile
[19d8]  Executing CI.dll!CiFreePolicyInfo
[19d8]  Executing ntoskrnl.exe!ExFreePool
```

接下来开始枚举进程。在枚举进程的开始时，vgk驱动传递了0号pid给各个api尝试查询信息，0号pid应该是不存在的，认为可能是故意的反模拟器操作
```log
[19d8]  Executing ntoskrnl.exe!PsLookupProcessByProcessId
[19d8]  	Process 00000000 EPROCESS being retrieved
[19d8]  Executing ntoskrnl.exe!PsGetProcessImageFileName
```

然后vgk驱动获取了4号pid(System进程)的imagefilename，认为可能在做反模拟器之类的操作。后续便是大量调用PsLookupProcessByProcessId暴力枚举进程。
```log
[19d8]  Executing ntoskrnl.exe!PsLookupProcessByProcessId
[19d8]  	Process 00000004 EPROCESS being retrieved
[19d8]  Executing ntoskrnl.exe!PsGetProcessImageFileName
[19d8]  Emulating read from PID4.EPROCESS+000005a8          // unsigned char ImageFileName[15];
```

接下来vgk驱动关中断瞬写MSR寄存器的MSR_LSTAR域，该位置保存着系统调用函数KiSystemCall64的地址。这个操作有两个用途：

1. 可以反VT。一些垃圾的VT在wrmsr后未判断地址合法性就会保存这个错误地址，后续VT处理rdmsr时使用到了非法地址，就炸了
2. 刷新LSTAR域
```log
[19d8]  Clearing Interrupts
[19d8]  Reading MSR MSR_LSTAR : 10000
[19d8]  Writing MSR MSR_LSTAR : 7ff6add4148c
[19d8]  Writing MSR MSR_LSTAR : 10000
[19d8]  Restoring Interrupts
```

接下来vgk驱动读取了hal.dll的内容并调用系列Hash函数进行hash校验
```log
[19d8]  Executing ntoskrnl.exe!RtlInitAnsiString
[19d8]  Executing ntoskrnl.exe!RtlAnsiStringToUnicodeString
[19d8]  Executing ntoskrnl.exe!IoCreateFileEx
[19d8]  	Creating file : \SystemRoot\system32\hal.dll
[19d8]  	Return : 00000000
[19d8]  Executing ntoskrnl.exe!ZwQueryInformationFile
[19d8]  	QueryInformationFile with class 00000005
[19d8]  Executing ntoskrnl.exe!ExAllocatePoolWithTag
[19d8]  Executing ntoskrnl.exe!ZwReadFile
```

hal.dll即Hardware Abstraction Layer DLL，是Windows的硬件抽象层模块，也是一个核心模块，不知道为什么vgk驱动着重校验这个dll。并且测试时发现，若因运行特殊工具导致机器码被封无法启动游戏时，Vanguard弹窗也是提示本机的hal.dll被判黑
![](网络安全-GameSecurity/res/83.png)

然后vgk驱动尝试获取物理内存大小，并写出日志
```log
[19d8]  Executing ntoskrnl.exe!ZwOpenKey
[19d8]  	Try to open \REGISTRY\MACHINE\HARDWARE\RESOURCEMAP\System Resources\Physical Memory : 00000000
[19d8]  Executing ntoskrnl.exe!ZwQueryValueKey
[19d8]  Executing ntoskrnl.exe!ExAllocatePoolWithTag
[19d8]  Executing ntoskrnl.exe!ZwQueryValueKey
```

接下来，vgk驱动会获取硬件信息Boot GUID
```log
[19d8]  Executing ntoskrnl.exe!ExGetFirmwareEnvironmentVariable
[19d8]  	Reading UEFI Var : BootCurrent - GUID : 8be4df61-93ca-11d2-92790fed20
[19d8]  	Requested length : 2
[19d8]  Executing ntoskrnl.exe!swprintf_s
[19d8]  	Result : Boot0000
[19d8]  Executing ntoskrnl.exe!ExAllocatePoolWithTag
[19d8]  Executing ntoskrnl.exe!ExGetFirmwareEnvironmentVariable
[19d8]  	Reading UEFI Var : Boot0000 - GUID : 8be4df61-93ca-11d2-92790fed20
[19d8]  	Requested length : 1000
```

再继续，vgk驱动通过LDR链枚举当前驱动模块，并读取DllBase和SizeOfImage保存到一个列表上，并调用qsort API进行排序。（这里想吐槽一下这个qsort，反正我模拟器排序执行这个函数要一分多钟，换到真实机器上就算快一点，也得几秒的性能损耗吧，而且还是阻塞式的主线程，不知道作者怎么想的
```log
[19d8]  Executing ntoskrnl.exe!ExAllocatePoolWithTag
[19d8]  Getting data @ ntoskrnl.exe!PsLoadedModuleList
[19d8]  Emulating read from LdrEntry.ntoskrnl.exe+00000030  // DllBase
[19d8]  Emulating read from LdrEntry.ntoskrnl.exe+00000000  // InLoadOrderLinks
[19d8]  Getting data @ ntoskrnl.exe!PsLoadedModuleList
[19d8]  Emulating read from LdrEntry.CEA.sys+00000030
[19d8]  Emulating read from LdrEntry.CEA.sys+00000040       // SizeOfImage
[19d8]  Emulating read from LdrEntry.CEA.sys+00000030
[19d8]  Emulating read from LdrEntry.ntoskrnl.exe+00000000
[19d8]  Emulating read from LdrEntry.CEA.sys+00000000
[19d8]  Getting data @ ntoskrnl.exe!PsLoadedModuleList
[19d8]  Emulating read from LdrEntry.BOOTVID.dll+00000030
[19d8]  Emulating read from LdrEntry.BOOTVID.dll+00000000
................................................................
[19d8]  Executing ntoskrnl.exe!qsort
```

完事后，调用MmGetPhysicalAddress以页为单位暴力扫内存，感觉像是在扫全部物理内存，地址连续、数量庞大。
```log
[19d8]  Executing ntoskrnl.exe!MmGetPhysicalAddress
[19d8]  	Getting Physical address for fffff80441e20000
[19d8]  	Return : fffff80441e20
[19d8]  Executing ntoskrnl.exe!MmGetPhysicalAddress
[19d8]  	Getting Physical address for fffff80441e21000
[19d8]  	Return : fffff80441e21
................................................................
```

接下来又去获取设备环境变量
```log
[19d8]  Getting data @ ntoskrnl.exe!MmHighestUserAddress
[19d8]  Executing ntoskrnl.exe!ExAllocatePoolWithTag
[19d8]  Executing ntoskrnl.exe!ExGetFirmwareEnvironmentVariable
[19d8]          Reading UEFI Var : Boot0000 - GUID : 8be4df61-93ca-ffff8009000011d2-6816bfea58
[19d8]          Requested length : 1000
[19d8]  Executing ntoskrnl.exe!ExGetFirmwareEnvironmentVariable
[19d8]          Reading UEFI Var : Boot0001 - GUID : 8be4df61-93ca-ffff8009000011d2-6816bfea58
[19d8]          Requested length : 1000
[19d8]  Executing ntoskrnl.exe!ExGetFirmwareEnvironmentVariable
[19d8]          Reading UEFI Var : Boot0002 - GUID : 8be4df61-93ca-ffff8009000011d2-6816bfea58
[19d8]          Requested length : 1000
[19d8]  Executing ntoskrnl.exe!ExGetFirmwareEnvironmentVariable
[19d8]          Reading UEFI Var : Boot0003 - GUID : 8be4df61-93ca-ffff8009000011d2-6816bfea58
[19d8]          Requested length : 1000
[19d8]  Executing ntoskrnl.exe!ExGetFirmwareEnvironmentVariable
[19d8]          Reading UEFI Var : Boot0004 - GUID : 8be4df61-93ca-ffff8009000011d2-6816bfea58
[19d8]          Requested length : 1000
[19d8]  Executing ntoskrnl.exe!ExGetFirmwareEnvironmentVariable
[19d8]          Reading UEFI Var : Boot0005 - GUID : 8be4df61-93ca-ffff8009000011d2-6816bfea58
[19d8]          Requested length : 1000
[19d8]  Executing ntoskrnl.exe!ExGetFirmwareEnvironmentVariable
[19d8]          Reading UEFI Var : Boot0006 - GUID : 8be4df61-93ca-ffff8009000011d2-6816bfea58
[19d8]          Requested length : 1000
[19d8]  Executing ntoskrnl.exe!ExGetFirmwareEnvironmentVariable
[19d8]          Reading UEFI Var : Boot0007 - GUID : 8be4df61-93ca-ffff8009000011d2-6816bfea58
[19d8]          Requested length : 1000
[19d8]  Executing ntoskrnl.exe!ExGetFirmwareEnvironmentVariable
[19d8]          Reading UEFI Var : Boot0008 - GUID : 8be4df61-93ca-ffff8009000011d2-6816bfea58
[19d8]          Requested length : 1000
[19d8]  Executing ntoskrnl.exe!ExGetFirmwareEnvironmentVariable
[19d8]          Reading UEFI Var : Boot0009 - GUID : 8be4df61-93ca-ffff8009000011d2-6816bfea58
[19d8]          Requested length : 1000
```

而后创建一条线程，线程内先执行反调试函数，再暴力枚举了一遍进程，对每个存在的进程执行PsIsProtectedProcessLight、PsIsProtectedProcess判定其保护状态再获取filename，全部扫完后就退出了
```log
[3ad0]  Thread Initialized, starting...
[3ad0]  Reading MSR MSR_0_P5_IP_ADDR : fff

// Anti Debug

[3ad0]  Executing ntoskrnl.exe!KeReadStateTimer
[3ad0]  Executing ntoskrnl.exe!ExAcquireSpinLockShared
[3ad0]  Executing ntoskrnl.exe!ExReleaseSpinLockShared

[3ad0]  Executing ntoskrnl.exe!ZwQuerySystemInformation
[3ad0]          Class 00000005 status : c0000004
[3ad0]  Executing ntoskrnl.exe!ExAllocatePoolWithTag
[3ad0]  Executing ntoskrnl.exe!ZwQuerySystemInformation
[3ad0]          Class 00000005 status : 00000000
[3ad0]          Class 00000005 success

[3ad0]  Executing ntoskrnl.exe!PsLookupProcessByProcessId
[3ad0]          Process 00000000 EPROCESS being retrieved
[3ad0]  Executing ntoskrnl.exe!PsIsProtectedProcessLight
[3ad0]  Executing ntoskrnl.exe!PsIsProtectedProcess
[3ad0]  Executing ntoskrnl.exe!PsGetProcessId
[3ad0]  Executing ntoskrnl.exe!ExAcquireSpinLockShared
[3ad0]  Executing ntoskrnl.exe!ExReleaseSpinLockShared
[3ad0]  Executing ntoskrnl.exe!ExAcquireSpinLockShared
[3ad0]  Executing ntoskrnl.exe!ExReleaseSpinLockShared
[3ad0]  Executing ntoskrnl.exe!PsGetProcessImageFileName
[3ad0]  Executing ntoskrnl.exe!ObReferenceProcessHandleTable
[3ad0]  Executing ntoskrnl.exe!ObDereferenceObject
[3ad0]  Executing ntoskrnl.exe!PsLookupProcessByProcessId
[3ad0]          Process 00000004 EPROCESS being retrieved
[3ad0]  Executing ntoskrnl.exe!PsIsProtectedProcessLight
[3ad0]  Executing ntoskrnl.exe!PsIsProtectedProcess
[3ad0]  Emulating read from PID4.EPROCESS+00000440			// UniqueProcessId
[3ad0]  Executing ntoskrnl.exe!ObDereferenceObject
[3ad0]  Executing ntoskrnl.exe!PsLookupProcessByProcessId
[3ad0]          Process 000000ac EPROCESS being retrieved
[3ad0]  Executing ntoskrnl.exe!PsLookupProcessByProcessId
[3ad0]          Process 00000260 EPROCESS being retrieved
[3ad0]  Executing ntoskrnl.exe!PsLookupProcessByProcessId
[3ad0]          Process 000003bc EPROCESS being retrieved
...................................................

[3ad0]  Executing ntoskrnl.exe!ExFreePool
[3ad0]  Executing ntoskrnl.exe!KeWaitForMutexObject
[3ad0]  Executing ntoskrnl.exe!PsTerminateSystemThread
```

同时主线程又创建了一条线程，线程内向vgkbootstatus.dat文件写入了内容，然后执行了一次反调试，而后就退出了
```log
[279c]  Thread Initialized, starting...
[279c]  Reading MSR MSR_0_P5_IP_ADDR : fff
[279c]  Writing 0 to DR7
[279c]  Reading CR0
[279c]  Executing ntoskrnl.exe!KeReadStateTimer
[279c]  Executing ntoskrnl.exe!wcscpy_s
[279c]  Executing ntoskrnl.exe!wcscat_s
[279c]  Executing ntoskrnl.exe!wcscat_s
[279c]  Executing ntoskrnl.exe!RtlInitUnicodeString
[279c]  Executing ntoskrnl.exe!IoCreateFileEx
[279c]          Creating file : \??\C:\Windows\vgkbootstatus.dat
[279c]          Return : 00000000
[279c]  Executing ntoskrnl.exe!ZwWriteFile
[279c]  Executing ntoskrnl.exe!ZwClose
[279c]          Closing Kernel Handle : 1c8

// AntiDebug

[279c]  Executing ntoskrnl.exe!ExAcquireSpinLockShared
[279c]  Executing ntoskrnl.exe!ExReleaseSpinLockShared
[279c]  Executing ntoskrnl.exe!ExAcquireSpinLockShared
[279c]  Executing ntoskrnl.exe!ExReleaseSpinLockShared
[279c]  Executing ntoskrnl.exe!ExAllocatePoolWithTag
[279c]  Executing ntoskrnl.exe!ExFreePool
[279c]  Executing ntoskrnl.exe!KeWaitForMutexObject
[279c]  Executing ntoskrnl.exe!PsTerminateSystemThread
[279c]          thread boom
```

接下来主线程注册关机回调，并创建设备vgk_PLZNOHACK（嗯？这个名字….），然后创建vgk的驱动符号链接。
```log

[TID:000031f0]  Executing ntoskrnl.exe!IoCreateDevice
[TID:000031f0]          Created device : \Device\vgk_PLZNOHACK
[TID:000031f0]  Executing ntoskrnl.exe!IoRegisterShutdownNotification
[TID:000031f0]  Executing ntoskrnl.exe!IoCreateSymbolicLink
[TID:000031f0]          Symbolic Link Name : \DosDevices\vgk
[TID:000031f0]          DeviceName : \Device\vgk_PLZNOHACK
```

刚看到这里的时候我以为我被检测了，plz no hack 是作弊提示信息，后面重装游戏不开任何工具启动了一次，看到确实设备名就是这个，那说明分析应该无误
![](网络安全-GameSecurity/res/84.png)

最后，主线程退出，DriverEntry分析完毕
```log
[TID:000031f0]  Executing ntoskrnl.exe!ZwOpenKey
[TID:000031f0]          Try to open \REGISTRY\MACHINE\SYSTEM\ControlSet001\Services\vgk
[TID:000031f0]  Main Thread Done! Return = 0
```

可以看到Vanguard反作弊系统是非常优秀、应用了非常多先进且前沿技术的，并且其中很多技术是笔者没有见过的，所以分析报告中难免会有勘误。