---
title: 检测-重写API
date: 2023-11-06 11:34
author: CHA.ATY
tags:
  - C
  - Windows
  - 检测
---

![](https://img.shields.io/badge/C-17-green.svg) ![](https://img.shields.io/badge/C++-17-green.svg)
![](https://img.shields.io/badge/visual_studio-2019-green.svg)
![](https://img.shields.io/badge/Windows10-22H2_19045.3570-green.svg)

# 一、前言

一般软件或则游戏中，代码段的页面属性为不可写的时候，我们可以调用 VirtualProtect 或则 VirtualProtectEx  修改页面属性，就可以修改和hook代码段了。

但是有的时候我们发现 VirtualProtect 函数怎么调用都一直失败，例如：天堂W。查看参数也没有错误，那么就有一种可能，该函数被Hook被检测了。所以我们要，绕过VirtualProtect & VirtualProtectEx 检测修改代码段。

---

# 二、VirtualProtect流程

首先先来了解下该函数到内核的执行流程 kernel32.VirtualProtect -> kernelbase.VirtualProtect -> ntdll.NtProtectVirtualMemory -> 进内核
  
我们来观察下 X86 和 X64 中的代码流程,如下：

## X86（KDXY 为例）
kernel32.VirtualProtect
```c
759504C0 >  8BFF            mov     edi, edi            
759504C2    55              push    ebp             
759504C3    8BEC            mov     ebp, esp           
759504C5    5D              pop     ebp           
759504C6  - FF25 90139B75   jmp     dword ptr [<&api-ms-win-core-memory-l1-1-0.VirtualProtect>]          ; KernelBa.VirtualProtect
```

调用 kernelBase.VirtualProtect
```c
76514DB0 >  8BFF            mov     edi, edi            
76514DB2    55              push    ebp            
76514DB3    8BEC            mov     ebp, esp           
76514DB5    51              push    ecx             
76514DB6    51              push    ecx            
76514DB7    8B45 0C         mov     eax, dword ptr [ebp+C]            
76514DBA    56              push    esi           
76514DBB    FF75 14         push    dword ptr [ebp+14]            
76514DBE    8945 FC         mov     dword ptr [ebp-4], eax           
76514DC1    FF75 10         push    dword ptr [ebp+10]            
76514DC4    8B45 08         mov     eax, dword ptr [ebp+8]            
76514DC7    8945 F8         mov     dword ptr [ebp-8], eax           
76514DCA    8D45 FC         lea     eax, dword ptr [ebp-4]            
76514DCD    50              push    eax            
76514DCE    8D45 F8         lea     eax, dword ptr [ebp-8]            
76514DD1    50              push    eax           
76514DD2    6A FF           push    -1            
76514DD4    FF15 48175D76   call    dword ptr [<&ntdll.NtProtectVirtualMemory>]                ; ntdll.ZwProtectVirtualMemory            
76514DDA    8BF0            mov     esi, eax           
76514DDC    85F6            test    esi, esi            
76514DDE    0F88 24F60200   js      76544408            
76514DE4    33C0            xor     eax, eax           
76514DE6    40              inc     eax           
76514DE7    5E              pop     esi           
76514DE8    C9              leave           
76514DE9    C2 1000         retn    10
```

调用 ntdll.NtProtectVirtualMemory
```c
77912ED0 >  B8 50000000     mov     eax, 50            
77912ED5    BA B0899277     mov     edx, 779289B0            
77912EDA    FFD2            call    edx           
77912EDC    C2 1400         retn    14            
77912EDF    90              nop
```

然后就进内核了，以上步骤换一个 X86 游戏或则软件也是一样的。

## X64(TD为例)
kernel32.VirtualProtect
```c
00007FFAA741BC7 | 48:FF25 D15B0600        | jmp qword ptr ds:[<&VirtualProtect>]         |
```
kernelBase.VirtualProtect

```c
00007FFAA5D84DA | 48:8BC4                 | mov rax,rsp                                  |            
                 
00007FFAA5D84DA | 48:8958 18              | mov qword ptr ds:[rax+0x18],rbx              |            
                 
00007FFAA5D84DA | 55                      | push rbp                                     |            
                 
00007FFAA5D84DA | 56                      | push rsi                                     |            
                 
00007FFAA5D84DA | 57                      | push rdi                                     |            
                 
00007FFAA5D84DA | 48:83EC 30              | sub rsp,0x30                                 |            
                 
00007FFAA5D84DA | 49:8BF1                 | mov rsi,r9                                   |            
                 
00007FFAA5D84DB | 4C:8948 D8              | mov qword ptr ds:[rax-0x28],r9               |            
                 
00007FFAA5D84DB | 45:8BC8                 | mov r9d,r8d                                  |            
                 
00007FFAA5D84DB | 48:8950 08              | mov qword ptr ds:[rax+0x8],rdx               |            
                 
00007FFAA5D84DB | 41:8BE8                 | mov ebp,r8d                                  |            
                 
00007FFAA5D84DB | 48:8948 10              | mov qword ptr ds:[rax+0x10],rcx              |            
                 
00007FFAA5D84DC | 4C:8D40 08              | lea r8,qword ptr ds:[rax+0x8]                |            
                 
00007FFAA5D84DC | 48:83C9 FF              | or rcx,0xFFFFFFFFFFFFFFFF                    |            
                 
00007FFAA5D84DC | 48:8D50 10              | lea rdx,qword ptr ds:[rax+0x10]              |            
                 
00007FFAA5D84DC | 48:FF15 72EE1500        | call qword ptr ds:[<&NtProtectVirtualMemory> |            
                 
00007FFAA5D84DD | 0F1F4400 00             | nop dword ptr ds:[rax+rax],eax               |            
                 
00007FFAA5D84DD | 33DB                    | xor ebx,ebx                                  |            
                 
00007FFAA5D84DD | 8BF8                    | mov edi,eax                                  |            
                 
00007FFAA5D84DD | 85C0                    | test eax,eax                                 |            
                 
00007FFAA5D84DE | 0F88 81FD0400           | js kernelbase.7FFAA5DD4B68                   |            
                 
00007FFAA5D84DE | BB 01000000             | mov ebx,0x1                                  |            
                 
00007FFAA5D84DE | 8BC3                    | mov eax,ebx                                  |            
                 
00007FFAA5D84DE | 48:8B5C24 60            | mov rbx,qword ptr ss:[rsp+0x60]              |            
                 
00007FFAA5D84DF | 48:83C4 30              | add rsp,0x30                                 |            
                 
00007FFAA5D84DF | 5F                      | pop rdi                                      |            
                 
00007FFAA5D84DF | 5E                      | pop rsi                                      |            
                 
00007FFAA5D84DF | 5D                      | pop rbp                                      |            
                 
00007FFAA5D84DF | C3                      | ret                                          |
```

ntdll.NtProtectVirtualMemory
```c
00007FFAA862D93 | 4C:8BD1                 | mov r10,rcx                                  |            
                 
00007FFAA862D93 | B8 50000000             | mov eax,0x50                                 | 50:'P'           
                 
00007FFAA862D93 | F60425 0803FE7F 01      | test byte ptr ds:[0x7FFE0308],0x1            |            
                 
00007FFAA862D94 | 75 03                   | jne ntdll.7FFAA862D945                       |            
                 
00007FFAA862D94 | 0F05                    | syscall                                      |            
                 
00007FFAA862D94 | C3                      | ret                                          |            
                 
00007FFAA862D94 | CD 2E                   | int 0x2E                                     |            
                 
00007FFAA862D94 | C3                      | ret                                          |            
                 
00007FFAA862D94 | 0F1F8400 00000000       | nop dword ptr ds:[rax+rax],eax               |
```

以上都是X86  和X64 正常情况下的代码。我们到 天堂W 里看一眼发现如下:  

kernel32.VirtualProtect
```c
00007FFAA741BC7 | 48:FF25 D15B0600        | jmp qword ptr ds:[<&VirtualProtect>]         |
```
kernelBase.VirtualProtect
```c
00007FFAA5D84DA | E9 69A2F2FF             | jmp 0x7FFAA5CAF00E                           |====破坏了前7字节            
                 
00007FFAA5D84DA | 58                      | pop rax                                      |            
                 
00007FFAA5D84DA | 1855 56                 | sbb byte ptr ss:[rbp+0x56],dl                |            
                 
00007FFAA5D84DA | 57                      | push rdi                                     |            
                 
00007FFAA5D84DA | 48:83EC 30              | sub rsp,0x30                                 |            
                 
00007FFAA5D84DA | 49:8BF1                 | mov rsi,r9                                   |            
                 
00007FFAA5D84DB | 4C:8948 D8              | mov qword ptr ds:[rax-0x28],r9               |            
                 
00007FFAA5D84DB | 45:8BC8                 | mov r9d,r8d                                  |            
                 
00007FFAA5D84DB | 48:8950 08              | mov qword ptr ds:[rax+0x8],rdx               |            
                 
00007FFAA5D84DB | 41:8BE8                 | mov ebp,r8d                                  |            
                 
00007FFAA5D84DB | 48:8948 10              | mov qword ptr ds:[rax+0x10],rcx              |            
                 
00007FFAA5D84DC | 4C:8D40 08              | lea r8,qword ptr ds:[rax+0x8]                |            
                 
00007FFAA5D84DC | 48:83C9 FF              | or rcx,0xFFFFFFFFFFFFFFFF                    |            
                 
00007FFAA5D84DC | 48:8D50 10              | lea rdx,qword ptr ds:[rax+0x10]              |            
                 
00007FFAA5D84DC | 48:FF15 72EE1500        | call qword ptr ds:[<&NtProtectVirtualMemory> |            
                 
00007FFAA5D84DD | 0F1F4400 00             | nop dword ptr ds:[rax+rax],eax               |            
                 
00007FFAA5D84DD | 33DB                    | xor ebx,ebx                                  |            
                 
00007FFAA5D84DD | 8BF8                    | mov edi,eax                                  |            
                 
00007FFAA5D84DD | 85C0                    | test eax,eax                                 |            
                 
00007FFAA5D84DE | 0F88 81FD0400           | js kernelbase.7FFAA5DD4B68                   |            
                 
00007FFAA5D84DE | BB 01000000             | mov ebx,0x1                                  |            
                 
00007FFAA5D84DE | 8BC3                    | mov eax,ebx                                  |            
                 
00007FFAA5D84DE | 48:8B5C24 60            | mov rbx,qword ptr ss:[rsp+0x60]              |            
                 
00007FFAA5D84DF | 48:83C4 30              | add rsp,0x30                                 |            
                 
00007FFAA5D84DF | 5F                      | pop rdi                                      |            
                 
00007FFAA5D84DF | 5E                      | pop rsi                                      |            
                 
00007FFAA5D84DF | 5D                      | pop rbp                                      |            
                 
00007FFAA5D84DF | C3                      | ret                                          |
```

ntdll.NtProtectVirtualMemory
```c
00007FFAA862D93 | E9 1F17F6FF             | jmp 0x7FFAA858F054                           | 头部====破坏了8字节            
                 
00007FFAA862D93 | 0000                    | add byte ptr ds:[rax],al                     |             
                 
00007FFAA862D93 | 00F6                    | add dh,dh                                    |            
                 
00007FFAA862D93 | 04 25                   | add al,0x25                                  |            
                 
00007FFAA862D93 | 0803                    | or byte ptr ds:[rbx],al                      |            
                 
00007FFAA862D93 | FE                      | ???                                          |            
                 
00007FFAA862D93 | 7F 01                   | jg ntdll.7FFAA862D941                        |            
                 
00007FFAA862D94 | 75 03                   | jne ntdll.7FFAA862D945                       |            
                 
00007FFAA862D94 | 0F05                    | syscall                                      |====进内核            
                 
00007FFAA862D94 | C3                      | ret                                          |            
                 
00007FFAA862D94 | CD 2E                   | int 0x2E                                     |
```

int 2E 中断处理程序把 EAX 里的值作为查找表中的索引，去找到最终的目标函数。这个表就是系统服务表SST。
```c
00007FFAA862D94 | C3                      | ret                                          |            
                 
00007FFAA862D94 | 0F1F8400 00000000       | nop dword ptr ds:[rax+rax],eax               |
```

我们发现了函数头部都有 hook 这种执行 VirtualProtecrt 就是必然失败的。因为天堂W的 kernelBase.VirtualProtect 和 ntdll.NtProtectVirtualMemory 头部被hook了，可以通过重写函数达到绕过效果。

---

# 三、重写 ntdll.NtProtectVirtualMemory 函数

**1. 进入内核函数 原封不动照抄过来就可以,ntdll.NtProtectVirtualMemory  5个参数.**

**X86**
```c
DWORD g_dwSsdt = (DWORD)GetModuleHandleA("ntdll.dll") + 0x84FC0;
DWORD g_addr = (DWORD)GetModuleHandleA("逆向.dll") + 0x2F162;//hook 地址
__declspec(naked) void NewNtProtectVirtualMemory(DWORD a,PVOID BaseAddress, ULONG ProtectSize, ULONG NewProtect, PULONG OldProtect)
{
        __asm {
 
                mov eax,0x50
                mov edx,g_dwSsdt
                call edx
                ret 0x14
        }
}
```

**X64**
```c
extern "C" DWORD newVirtualProtect( QWORD a, QWORD** BaseAddress, QWORD* ProtectSize, QWORD NewProtect, DWORD* OldProtect);
newVirtualProtect proc
 
mov r10,rcx
mov eax,50h
syscall
ret
 
newVirtualProtect endp
```

**2.直接调用即可**

**X86**
```c
void CTESTDIALOG::OnBnClickedButton1()
{
        通用_输出调试信息2("逆向:内核地址:%X\r\n", g_dwSsdt);
        通用_输出调试信息2("逆向:修改地址:%X\r\n", g_addr);
 
        DWORD old = 0;
        DWORD dwRet = 0;
        PDWORD p4 = &old;//页面原属性
        ULONG p3 = PAGE_WRITECOPY;
        PVOID p11 = (PVOID)g_addr;
        PVOID* p1 = &p11;
        DWORD p22 = 0x20;
        PULONG p2 = &p22;
        __asm {
                push p4
                push p3
                push p2
                push p1
                push 0xFFFFFFFF
                mov eax, NewNtProtectVirtualMemory
                call eax
                mov dwRet,eax
        }
        通用_输出调试信息2("逆向:页面属性修改返回:%X\r\n", dwRet);
 
        *(BYTE*)g_addr = 0xEB;
 
        p4 = &old;
        p3 = old;
        p11 = (PVOID)g_addr;
        p1 = &p11;
        p22 = 0x20;
        p2 = &p22;
        __asm {
                push p4
                push p3
                push p2
                push p1
                push 0xFFFFFFFF
                mov eax, NewNtProtectVirtualMemory
                call eax
                mov dwRet, eax
        }        
}
```

**X64**
```c
void CTestDialog::OnBnClickedButton4()
 
{
        __try
        {
                QWORD addr = 0x00007FF7870024F7; 
 
                DWORD old = 0;
 
                DWORD a = VirtualProtect((PVOID)addr, 100, PAGE_EXECUTE_READWRITE, &old);
 
                通用_输出调试信息("修改页面属性结果: %d", a);
 
                *(BYTE*)addr = 0xCC;
 
 
 
                a = VirtualProtect((PVOID)addr, 100, old, &old);
 
                通用_输出调试信息("修改页面属性结果: %d", a);
 
        }
 
        __except (1)
 
        {
                通用_输出调试信息("VirtualProtect异常");
        }
}
void CTestDialog::OnBnClickedButton5()
{
        __try
        {
 
                QWORD* addr = (QWORD*)0x00007FF7870024F7;
 
                DWORD old = 0;
 
                QWORD* p11 = addr;
 
                QWORD** p1 = &p11;        
 
                QWORD p22 = 0x100;//这地方写DWORD 看看会有什么样的错误和坑,学习调试
 
                QWORD* p2 = &p22;
 
                DWORD a = newVirtualProtect( 0xFFFFFFFFFFFFFFFF,p1, p2, PAGE_EXECUTE_READWRITE, &old);
 
                通用_输出调试信息("修改页面属性结果: %d", a);
 
                *(BYTE*)addr = 0xCC;
 
                a = newVirtualProtect(0xFFFFFFFFFFFFFFFF,p1, p2, old, &old);
 
                通用_输出调试信息("修改页面属性结果: %d", a);
        }
        __except (1)
        {
                通用_输出调试信息("newVirtualProtect异常");
        }
}
```

---

> 版权声明©：
>
> 本文为 CHA.ATY 的原创文章，遵循 [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/) 许可证进行授权，转载请附上原文出处链接及本声明。
>
> 作者：CHA.ATY
>
> 邮箱：2165150141@qq.com