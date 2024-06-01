---
title: 无痕HOOK 硬断+VEH
date: 2023-11-06 20:22
author: CHA.ATY
tags:
  - C
  - Windows
  - Hook
category: 技术分享
---

![](https://img.shields.io/badge/C-17-green.svg) ![](https://img.shields.io/badge/C++-17-green.svg)
![](https://img.shields.io/badge/visual_studio-2019-green.svg)
![](https://img.shields.io/badge/Windows10-22H2_19045.3570-green.svg)

# 一、前言

硬断 HOOK 也有人叫 **无痕HOOK** 是利用 VEH 异常+硬件断点 实现的。硬件断点不依赖被调试程序，而是依赖于CPU中的调试寄存器。

利用这种方式可以实现在不破坏代码的前提下进行 Hook，可以完美的避开 crc32 检测，不容易被分析人员发现。由于是在异常处理函数中实现的 Hook 逻辑，还能顺手加一个反调试，防止别人逆向自己写的程序。

平常常用的三环Hook通常是InlineHook和虚Hook，这两种Hook方式均是通过修改内存来劫持控制流，InlineHook通过修改代码段上的代码而虚Hook通过修改虚表指针。因为均对内存做了修改（且往往Hook的位置都是敏感内存），很容易被诸如CRC之类的手段检测到。故学习了一下三环下的无痕HOOK，注意这里的无痕指的仅仅是不对代码段等内存产生修改，而不是不会被发现。

在x86架构下有一组特殊的寄存器叫做硬件断点寄存器，分别是Dr0-Dr7。其中Dr0-Dr3这四个寄存器用于于设置硬件断点的，Dr4和Dr5由系统保留，Dr6用于显示哪个硬件调试寄存器引发的断点，Dr7则是用于控制断点属性。如果我们能够设置硬件断点到我们想Hook的位置，那样程序运行到该处时就会抛出一个异常，转而进入异常处理函数；如果我们设置了与之匹配的异常处理函数，则可以在异常发生时劫持得到程序的控制流程流。 硬件断点寄存器可以通过修改线程上下文结构体（ThreadContext）来设置，而异常处理函数通常则是使用VEH。

---

# 二、实现步骤

实现硬件断点 Hook 的具体步骤：
1. 找到我们想 Hook 的线程（一条或者是多条）。
2. 得到线程上下文（通俗点就是线程中寄存器，调试器寄存器，指针，堆栈指针等各种信息），每个线程上下文是独立的  。
3. 修改 DR0-DR7 然后设置线程上下文。这样程序执行到我们下断点的位置就会抛异常了。
4. 当然抛异常，我们要异常处理函数去处理，也就是我们上面说的 VEH。所以我们要设置一个异常处理函数，接收异常并且处理异常。
5. 这样全部完成以后，CPU执行指令，执行到我们下断的地方，发现指令地址和 DR0-DR3 中的某一个地址相同，就回抛异常，异常到我们的异常处理函数。我们就相当于 Hook 到信息了，然后做想做的事，之后再把EIP改回去正常执行代码即可。

---

# 三、设置硬件断点

首先来说一下关于硬件断点hook的原理，在Windows API中存在一个重要的结构体**PCONTEXT**
```c
typedef struct DECLSPEC_NOINITALL _CONTEXT {

    //
    // The flags values within this flag control the contents of
    // a CONTEXT record.
    //
    // If the context record is used as an input parameter, then
    // for each portion of the context record controlled by a flag
    // whose value is set, it is assumed that that portion of the
    // context record contains valid context. If the context record
    // is being used to modify a threads context, then only that
    // portion of the threads context will be modified.
    //
    // If the context record is used as an IN OUT parameter to capture
    // the context of a thread, then only those portions of the thread's
    // context corresponding to set flags will be returned.
    //
    // The context record is never used as an OUT only parameter.
    //

    DWORD ContextFlags;

    //
    // This section is specified/returned if CONTEXT_DEBUG_REGISTERS is
    // set in ContextFlags.  Note that CONTEXT_DEBUG_REGISTERS is NOT
    // included in CONTEXT_FULL.
    //

    DWORD   Dr0;
    DWORD   Dr1;
    DWORD   Dr2;
    DWORD   Dr3;
    DWORD   Dr6;
    DWORD   Dr7;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_FLOATING_POINT.
    //

    FLOATING_SAVE_AREA FloatSave;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_SEGMENTS.
    //

    DWORD   SegGs;
    DWORD   SegFs;
    DWORD   SegEs;
    DWORD   SegDs;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_INTEGER.
    //

    DWORD   Edi;
    DWORD   Esi;
    DWORD   Ebx;
    DWORD   Edx;
    DWORD   Ecx;
    DWORD   Eax;

    //
    // This section is specified/returned if the
    // ContextFlags word contians the flag CONTEXT_CONTROL.
    //

    DWORD   Ebp;
    DWORD   Eip;
    DWORD   SegCs;              // MUST BE SANITIZED
    DWORD   EFlags;             // MUST BE SANITIZED
    DWORD   Esp;
    DWORD   SegSs;

    //
    // This section is specified/returned if the ContextFlags word
    // contains the flag CONTEXT_EXTENDED_REGISTERS.
    // The format and contexts are processor specific
    //

    BYTE    ExtendedRegisters[MAXIMUM_SUPPORTED_EXTENSION];

} CONTEXT;

typedef CONTEXT *PCONTEXT;
```
这个结构体里保存着所有的寄存器信息，其中和硬件断点相关的字段有下面几个
```c
DWORD   Dr0;
DWORD   Dr1;
DWORD   Dr2;
DWORD   Dr3;
DWORD   Dr6;
DWORD   Dr7;
```
和硬件调试相关的寄存器一共有6个。如果我们能获取到线程的Context环境，并且修改dr寄存器，就能给需要hook的地址下硬件断点。

---

# 四、注册VEH

接下来就进入到第二步，注册异常处理函数。当程序执行到hook点时，触发硬件断点，从而触发EXCEPTION_SINGLE_STEP异常，那么我们就可以自己注册一个VEH异常处理函数来处理这个异常，那么就可以在处理完成之后编写自己的hook代码

windwos操作系统专门针对异常的处理有一整套完整的机制，这里为了理解，简单介绍一下：windwos下3环进程运行时，如果遇到异常，大致的处理顺序如下：

1. 先看看有没有调试器（通过编译器运行exe也算），如果有，就发消息给调试器让其处理；
2. 如果没有调试器，或则调试器没处理，进入进程自己的VEH继续处理。VEH本质是个双向链表，存储了异常的handler代码，此时windwos会挨个遍历这个链表执行这些handler（感觉原理和vmp很像，估计vmp借鉴了这里的思路）
3. 如果VEH还没处理好，接着由线程继续处理。线程同样有个异常接管的链表，叫SEH；windows同样会遍历SEH来处理异常
4. 如果SEH还没处理好，继续给线程的UEH传递，UEH只有一个处理函数了
5. 如果UEH还没处理好，就回到进程的VCH处理

基于windwos开发的应用数以万计，微软绝对不可能出厂时就考虑到所有的异常，其各种handler不太可能处理所有的异常，所以微软又开放了接口，让开发人员自定义异常的handler；对于开发人员来说，肯定是越靠前越好，所以这里选择VEH来添加自定义的handler（调试器是最先收到异常通知的，但外挂在正常使用时不太可能有调试的功能，除非开发人员自己单独开发调试器的功能，这样成本太高了）。windwos开放了一个API，叫AddVectoredExceptionHandler，可以给VEH添加用户自定义的异常处理handler，如下
```c
AddVectoredExceptionHandler(1, PvectoredExceptionHandler)
```
函数有两个参数：第一个参数如果不是0，那么自定义的handler最先执行；如果是0，那么自定义的handler最后执行。这里我们当然希望自己的handler最先执行了，所以设置成1；另一个参数就是自定义的回调函数。

---

# 五、代码实现VEH无痕Hook

## 实现一

首先我们需要获取到当前的线程环境结构体
```c
void SetSehHook()
{
	//遍历线程 通过openthread获取到线程环境后设置硬件断点
	HANDLE hTool32 = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hTool32!= INVALID_HANDLE_VALUE)
	{
		//线程环境结构体
		THREADENTRY32 thread_entry32;
		thread_entry32.dwSize = sizeof(THREADENTRY32);
		HANDLE hHookThread = NULL;
		//遍历线程
		if (Thread32First(hTool32,&thread_entry32))
		{
			do 
			{
				//如果线程父进程ID为当前进程ID
				if (thread_entry32.th32OwnerProcessID==GetCurrentProcessId())
				{
					hHookThread = OpenThread(THREAD_SET_CONTEXT | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, thread_entry32.th32ThreadID);
					SuspendThread(hHookThread);//暂停线程
					//设置硬件断点
					CONTEXT thread_context = { CONTEXT_DEBUG_REGISTERS };
					thread_context.Dr0 = g_HookAddr;
					thread_context.Dr7 = 0x405;
					//设置线程环境 这里抛异常了
					DWORD oldprotect;
					VirtualProtect((LPVOID)g_HookAddr, 5, PAGE_EXECUTE_READWRITE, &oldprotect);//修改PTE p=1 r/w1=0
					SetThreadContext(hHookThread, &thread_context);
					ResumeThread(hHookThread);//线程跑起来吧~~~
					CloseHandle(hHookThread);
				}
			} while (Thread32Next(hTool32, &thread_entry32));
		}
		CloseHandle(hTool32);
	}
}
```

这里通过遍历线程，设置线程环境的方式来给所有的线程设置硬件断点。接着注册VEH异常处理函数
```c
 AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)ExceptionFilter);//添加VEH异常处理
```

接着编写回调函数
```c
LONG NTAPI  ExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo)
{

	//判断当前异常码是否为硬件断点异常
	if (ExceptionInfo->ExceptionRecord->ExceptionCode== EXCEPTION_SINGLE_STEP)
	{
		
		//判断发生异常的地址是否和hook的地址一致
		if ((DWORD)ExceptionInfo->ExceptionRecord->ExceptionAddress == g_HookAddr)
		{

			//获取当前线程上下文
			PCONTEXT pcontext = ExceptionInfo->ContextRecord;

			//获取聊天记录
			RecvMsg(pcontext);
            
			//修复EIP 
			pcontext->Eip=(DWORD)&OriginalFunc;

			
			//异常处理完成 让程序继续执行
			return EXCEPTION_CONTINUE_EXECUTION;

		}
	}
	return EXCEPTION_CONTINUE_SEARCH;
}
```

最后需要修复EIP，让程序正常运行，我这里时让EIP指向一个逻函数，再通过裸函数跳转到目标返回地址
```c
void __declspec(naked) OriginalFunc(void)
{
	__asm
	{
		//调用被覆盖的call
		call OverReciveMsgCallAddr;
		//跳转到返回地址
		jmp RetkReciveMsgAddr;

	}
}
```

## 实现二

![[平台开发-Windows/res/59.png]]![[平台开发-Windows/res/60.png]]![[平台开发-Windows/res/61.png]]![[平台开发-Windows/res/62.png]]

注意事项:  
1. 设置线程上下文之前要先暂停线程,设置完毕再恢复线程  
否则可能访问冲突  
2. 修改drx之前 一定要GetThreadContext,虽然有的游戏不需要,毕竟我们需要通用  
3. 要筛选线程,并不是所有线程都是我们需要hook的

**我们拿天堂W举例子**  

找个位置 hook 明文包，明文包位置如下:
![[平台开发-Windows/res/63.png]]
我们hook的代码  
mov  rcx,rax  
当执行到这里断下的时候本条代码并没有被执行  
而是抛出异常到回调函数  
  
所以异常处理 只需要2句代码  
第一句 还原mov rcx,rax  
第二句 修改RIP 指向下一条代码  
  
有同学说 , 不用还原代码 不修改RIP 让他直接执行不行吗?  
答案是不行的,这里已经有异常了,如果不修改RIP 就变成死循环了
```c
// 还原处理
异常信息->ContextRecord->Rcx = rax;// mov rcx,rax
异常信息->ContextRecord->Rip = 3;
```
好我们直接创建一个无痕_hook类直接调用安装  
```c
无痕_hook.安装(g_hook1, g_hook2, 0, 0, 0x55, 异常处理，排除线程ID);
```
注意事项:  
1. 需要几个断点,写几个地址  
2. DR7需要一个断点写1   二个写5    三个写0x15  四个写0x55   当然也可以一直写0x55  

回调函数
![[平台开发-Windows/res/64.png]]

注意事项:  
1. 处理完毕的异常 要返回去继续运行, 没有处理的异常继续搜索 注意返回值不一样  
2. 还原被hook的代码  然后RIP跳到下一条  
3. 有的同学说  调试输出信息会产生错误, 那是因为这个函数里面我们用了OutputDebugString,他也是抛异常的方式输出的,所以放到异常处理函数中 会产生递归,解决方法非常简单, 我们把自己DLL的线程排除在hook之外即可,你hook自己的界面线程干嘛 - -
```c
DWORD 排除线程ID[10] = {0};
排除线程ID[0] = GetCurrentThreadId();
```
代码完成我们直接到游戏中进行走路,hook成功,抓到封包了.
![[平台开发-Windows/res/65.png]]

## 实现三

下面来看一个demo，这个Demo实现了硬断MessageBoxA这个API
```cpp
HMODULE hUser32 = GetModuleHandleA("user32.dll");
size_t hookaddr = (size_t)GetProcAddress(hUser32, "MessageBoxA");

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)ExceptionHandler);
        if(SetHwBreakpoint() == FALSE)  printf("SetHwBreakpoint Error:%d\n", GetLastError());
        break;
    }
    case DLL_THREAD_ATTACH:     // 对每一个新创建的线程均添加硬件断点
    {
        SetHwBreakpoint();
    }
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

BOOL SetHwBreakpoint()
{
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(GetCurrentThread(), &ctx);
    ctx.Dr0 = hookaddr;
    ctx.Dr7 = 0x1;
    return SetThreadContext(GetCurrentThread(), &ctx);
}

size_t NTAPI ExceptionHandler(EXCEPTION_POINTERS* ExceptionInfo)
{
    if ((size_t)ExceptionInfo->ExceptionRecord->ExceptionAddress == hookaddr)
    {
        printf("Hook!\n");
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else
    {
        //在异常handler里重设drx防止断点被意外清除
        ExceptionInfo->ContextRecord->Dr0 = hookaddr;
        ExceptionInfo->ContextRecord->Dr7 = 0x405;
        return EXCEPTION_CONTINUE_SEARCH;
    }
}
```
如果用心的去试一下，就会发现这个Demo在某些情况下是无法实现Hook的，比如在远线程注入该Dll的时候就发现Hook不住MessageboxA

为什么会这样呢？这里又是一个点，就是一个程序的上下文（寄存器等信息）是绑定于线程还是进程的。三环的远线程注入DLL本质是将Dll写入该进程的内存中，然后CreateRemoteThread在DllMain的位置创建了一个线程运行Dll的Main函数。DllMain函数中调用了SetHwBreakpoint对硬件断点寄存器做了修改，但此时这一条线程并不是程序原先运行代码的线程（主线程），而是我们远程创建的新线程，故设置出来的硬件断点仅对这条用于初始化dll的新线程有效。 正确的做法应该是枚举线程，对每一条线程均设置上硬件断点。
```cpp
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    {
        // DebugBreak();
        printf("hUser32:%p\n", hUser32);
        printf("hook:%p\n", hookaddr);

        AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)ExceptionHandler);
        SetHBToAllThread();     // 为所有线程设置硬件断点
        break;
    }
    case DLL_THREAD_ATTACH:
    {
        // 为新创建的线程设置硬件断点
        SetHwBreakpoint(GetCurrentThread());
    }
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

void SetHwBreakpoint(HANDLE hThread)
{
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_ALL;
    GetThreadContext(hThread, &ctx);
    ctx.Dr0 = hookaddr;
    ctx.Dr7 = 0x1;
    if (SetThreadContext(hThread, &ctx) == FALSE)
        printf("SetHwBreakpoint Error:%d\n", GetLastError());
}
// 枚举线程，并对每一条已存在的线程设置硬件断点
void SetHBToAllThread() {
    HANDLE hThreadShot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
    THREADENTRY32* threadInfo = new THREADENTRY32;
    HANDLE hThread = NULL;

    threadInfo->dwSize = sizeof(THREADENTRY32);
    int cnt = 0;

    while (Thread32Next(hThreadShot, threadInfo) != FALSE)
    {
        if (GetCurrentProcessId() == threadInfo->th32OwnerProcessID)
        {
            cnt++;
            printf("ThreadId:%x\n", threadInfo->th32ThreadID);
            hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadInfo->th32ThreadID);
            SetHwBreakpoint(hThread);
            CloseHandle(hThread);
        }
    }
    CloseHandle(hThreadShot);
}
```

---

# 六、关于veh hook的对抗

既然这种方式那么隐蔽，那么假如我们调试的程序采用了类似的hook或者反调试手段，应该怎么处理呢？实际上处理的方式有两种：
- 再编写一个VEH异常处理函数。veh是异常处理链，系统每次都先调用最顶层的那个，再根据最顶层那个的返回值来决定是否调下一个。我们只要再注册一个异常处理函数，返回处理成功不调用下一个，就能把之前的veh顶下去
- OD 设置系统断点断下, 再下断 AddVectoredExceptionHandler


---

> 版权声明©：
>
> 本文为 CHA.ATY 的原创文章，遵循 [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) 许可证进行授权，转载请附上原文出处链接及本声明。
>
> 作者：CHA.ATY
>
> 邮箱：2165150141@qq.com