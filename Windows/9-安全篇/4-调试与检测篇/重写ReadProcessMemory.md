---
title: 重写WriteProcessMemory、ReadProcessMemory
date: 2023-11-04 20:29
author: CHA.ATY
tags:
  - Windows
  - 内核驱动
  - 反调试
category: 技术分享
---

![](https://img.shields.io/badge/C-17-green.svg) ![](https://img.shields.io/badge/C++-17-green.svg)
![](https://img.shields.io/badge/visual_studio-2019-green.svg)
![](https://img.shields.io/badge/Windows10-22H2_19045.3570-green.svg)

# 一、前言

重写API的意义：自己实现API，可以防3环HOOK API的检测。

**R3环API分析的重要性**：
1. Windows所提供给R3环的API，实质就是对操作系统接口的封装，其实现部分都是在R0实现的。
2. 很多恶意程序会利用钩子来钩取这些API，从而达到截取内容，修改数据的意图。
3. 重写ReadProcessMemory之后，这就会加大恶意代码截获的难度。
4. 当然，对于自己来说也有很多弊端，比如只能在指定的操作系统中运行(32位与64位操作系统，其运行ReadProcessMemory的执行动作是不一样的，在64位运行32位程序，其中间会调用wow64cpu.dll来进行转换)

注意：vs 内联汇编不支持 sysenter 指令，可以用 \_emit 代替。

自己编写 WriteProcessMemory 函数（不使用任何DLL，直接调用0环函数）并在代码中使用。

```c
// 读写内存_中断门和快速调用实现.cpp : 定义控制台应用程序的入口点。
//
 
#include "stdafx.h"
#include <Windows.h>
 
// 读进程内存(中断门调用)
BOOL WINAPI HbgReadProcessMemory_INT(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesRead)
{
	LONG NtStatus;
	__asm
	{
		// 直接模拟 KiIntSystemCall
		lea edx,hProcess; // 要求 edx 存储最后入栈的参数
		mov eax, 0xBA;
		int 0x2E;
		mov NtStatus, eax;
	}
	if (lpNumberOfBytesRead != NULL)
	{
		*lpNumberOfBytesRead = nSize;		
	}
	// 错误检查
	if (NtStatus < 0)
	{
		return FALSE;
	}
	return TRUE;
}
 
// 读进程内存(快速调用)
BOOL WINAPI HbgReadProcessMemory_FAST(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesRead)
{
	LONG NtStatus;
	__asm
	{
		// 模拟 ReadProcessMemory
		lea eax,nSize;
		push eax;
		push nSize;
		push lpBuffer;
		push lpBaseAddress;
		push hProcess;
		sub esp, 0x04; // 模拟 ReadProcessMemory 里的 CALL NtReadVirtualMemory
		// 模拟 NtReadVirtualMemory
		mov eax, 0xBA;
		push NtReadVirtualMemoryReturn; // 模拟 NtReadVirtualMemory 函数里的 CALL [0x7FFE0300]
		// 模拟 KiFastSystemCall
		mov edx, esp;
		_emit 0x0F; // sysenter 
		_emit 0x34;
NtReadVirtualMemoryReturn:		
		add esp, 0x18; // 模拟 NtReadVirtualMemory 返回到 ReadProcessMemory 时的 RETN 0x14
		mov NtStatus, eax;
	}
	if (lpNumberOfBytesRead != NULL)
	{
		*lpNumberOfBytesRead = nSize;		
	}
	// 错误检查
	if (NtStatus < 0)
	{
		return FALSE;
	}
	return TRUE;
}
 
// 写进程内存(中断门调用)
BOOL WINAPI HbgWriteProcessMemory_INT(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesWritten)
{
	LONG NtStatus;
	__asm
	{
		lea edx,hProcess;
		mov eax, 0x115;
		int 0x2E;
		mov NtStatus, eax;
	}
	if (lpNumberOfBytesWritten != NULL)
	{
		*lpNumberOfBytesWritten = nSize;		
	}
	// 错误检查
	if (NtStatus < 0)
	{
		return FALSE;
	}
	return TRUE;
}
 
// 写进程内存(快速调用)
BOOL WINAPI HbgWriteProcessMemory_FAST(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesWritten)
{
	LONG NtStatus;
	__asm
	{
		// 模拟 WriteProcessMemory
		lea eax,nSize;
		push eax;
		push nSize;
		push lpBuffer;
		push lpBaseAddress;
		push hProcess;
		sub esp, 0x04; // 模拟 WriteProcessMemory 里的 CALL NtWriteVirtualMemory
		// 模拟 NtWriteVirtualMemory
		mov eax, 0x115;
		push NtWriteVirtualMemoryReturn; // 模拟 NtWriteVirtualMemory 函数里的 CALL [0x7FFE0300]
		// 模拟 KiFastSystemCall
		mov edx, esp;
		_emit 0x0F; // sysenter 
		_emit 0x34;
NtWriteVirtualMemoryReturn:		
		add esp, 0x18; // 模拟 NtWriteVirtualMemory 返回到 WriteProcessMemory 时的 RETN 0x14
		mov NtStatus, eax;
	}
	if (lpNumberOfBytesWritten != NULL)
	{
		*lpNumberOfBytesWritten = nSize;		
	}
	// 错误检查
	if (NtStatus < 0)
	{
		return FALSE;
	}
	return TRUE;
}
 
// 提权函数：提升为DEBUG权限
BOOL EnableDebugPrivilege()
{
	HANDLE hToken;
	BOOL fOk=FALSE;
	if(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount=1;
		LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&tp.Privileges[0].Luid);
 
		tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(tp),NULL,NULL);
 
		fOk=(GetLastError()==ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return fOk;
}
 
int _tmain(int argc, _TCHAR* argv[])
{
	EnableDebugPrivilege();
 
	DWORD pid,addr,dwRead,dwWritten;
	char buff[20] = {0};
	printf("依次输入PID和要读的线性地址(均为16进制)...\n");
	scanf("%x %x", &pid, &addr);
	getchar();
 
	// 测试两个版本的 ReadProcessMemory
	HbgReadProcessMemory_INT(OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid),(LPCVOID)addr,buff,4,&dwRead);
	printf("读取了%d个字节，内容是: \"%s\"\n", dwRead, buff);
	HbgReadProcessMemory_FAST(OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid),(LPCVOID)(addr+4),buff,4,&dwRead);
	printf("读取了%d个字节，内容是: \"%s\"\n", dwRead, buff);
	
	// 测试两个版本的 WriteProcessMemory
	HbgWriteProcessMemory_INT(OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid),(LPCVOID)addr,"##",2,&dwWritten);
	printf("写入了%d字节.\n", dwWritten);
	HbgWriteProcessMemory_FAST(OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid),(LPCVOID)(addr+4),"**",2,&dwWritten);
	printf("写入了%d字节.\n", dwWritten);
 
	// 再次读取，验证写入是否成功
	HbgReadProcessMemory_INT(OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid),(LPCVOID)addr,buff,4,&dwRead);
	printf("读取了%d个字节，内容是: \"%s\"\n", dwRead, buff);
	HbgReadProcessMemory_FAST(OpenProcess(PROCESS_ALL_ACCESS,FALSE,pid),(LPCVOID)(addr+4),buff,4,&dwRead);
	printf("读取了%d个字节，内容是: \"%s\"\n", dwRead, buff);
 
	printf("bye!\n");
	getchar();
	return 0;
}
```

```c
#include<stdio.h>
#include<windows.h>

BOOL EnableDebugPrivilege()
{
	HANDLE hToken;
	BOOL fOk=FALSE;
	if(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount=1;
		LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&tp.Privileges[0].Luid);
		
		tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(tp),NULL,NULL);
		
		fOk=(GetLastError()==ERROR_SUCCESS);
		CloseHandle(hToken);
	}
    return fOk;
}


__declspec(naked) void KiFastSystemCall()
{
	__asm
	{
		mov edx,esp;
		_emit 0x0F; // sysenter 
		_emit 0x34;
	}
}

__declspec(naked) void KiFastSystemCall2NtWriteVirtualMemory()
{
	
	__asm
	{
		mov eax, 115h;
		lea edx, [KiFastSystemCall];
		call edx;
		retn 14h;
	}
}

__declspec(naked) void KiIntSystemCall()
{
	__asm
	{
		lea edx,[esp+8];
		int 2Eh;
		ret;
	}
}

__declspec(naked) void KiIntSystemCall2NtWriteVirtualMemory()
{
	
	__asm
	{
		mov eax, 115h;
		lea edx, [KiIntSystemCall];
		call edx;
		retn 14h;
	}
}


int main(int argc, char* argv[])
{
	DWORD dwWritten;
	DWORD dwProcessPid;
	HANDLE hProcess;
	DWORD dwAddr;
	unsigned char shellcode[] = { 
		0x33, 0xC9, 0x64, 0x8B, 0x41, 0x30, 0x8B, 0x40, 0x0C, 0x8B, 0x70, 0x14, 0xAD, 0x96, 0xAD, 0x8B,
		0x58, 0x10, 0x8B, 0x53, 0x3C, 0x03, 0xD3, 0x8B, 0x52, 0x78, 0x03, 0xD3, 0x8B, 0x72, 0x20, 0x03,
		0xF3, 0x33, 0xC9, 0x41, 0xAD, 0x03, 0xC3, 0x81, 0x38, 0x47, 0x65, 0x74, 0x50, 0x75, 0xF4, 0x81,
		0x78, 0x04, 0x72, 0x6F, 0x63, 0x41, 0x75, 0xEB, 0x81, 0x78, 0x08, 0x64, 0x64, 0x72, 0x65, 0x75,
		0xE2, 0x8B, 0x72, 0x24, 0x03, 0xF3, 0x66, 0x8B, 0x0C, 0x4E, 0x49, 0x8B, 0x72, 0x1C, 0x03, 0xF3,
		0x8B, 0x14, 0x8E, 0x03, 0xD3, 0x33, 0xC9, 0x53, 0x52, 0x51, 0x68, 0x61, 0x72, 0x79, 0x41, 0x68,
		0x4C, 0x69, 0x62, 0x72, 0x68, 0x4C, 0x6F, 0x61, 0x64, 0x54, 0x53, 0xFF, 0xD2, 0x83, 0xC4, 0x0C,
		0x59, 0x50, 0x51, 0x68, 0x2E, 0x64, 0x6C, 0x6C, 0x68, 0x65, 0x6C, 0x33, 0x32, 0x68, 0x6B, 0x65,
		0x72, 0x6E, 0x54, 0xFF, 0xD0, 0x83, 0xC4, 0x0C, 0x59, 0x8B, 0x54, 0x24, 0x04, 0x52, 0x33, 0xC9,
		0x51, 0xB9, 0x78, 0x65, 0x63, 0x61, 0x51, 0x83, 0x6C, 0x24, 0x03, 0x61, 0x68, 0x57, 0x69, 0x6E,
		0x45, 0x54, 0x50, 0xFF, 0xD2, 0x83, 0xC4, 0x08, 0x59, 0x33, 0xC9, 0x33, 0xDB, 0x51, 0x68, 0x2E,
		0x65, 0x78, 0x65, 0x68, 0x63, 0x61, 0x6C, 0x63, 0x68, 0x6D, 0x33, 0x32, 0x5C, 0x68, 0x79, 0x73,
		0x74, 0x65, 0x68, 0x77, 0x73, 0x5C, 0x53, 0x68, 0x69, 0x6E, 0x64, 0x6F, 0x68, 0x43, 0x3A, 0x5C,
		0x57, 0x8B, 0xDC, 0x6A, 0x0A, 0x53, 0xFF, 0xD0, 0x83, 0xC4, 0x1C, 0x59, 0x33, 0xC9, 0x33, 0xDB,
		0x8B, 0x44, 0x24, 0x0C, 0x8B, 0x14, 0x24, 0xB9, 0x65, 0x73, 0x73, 0x61, 0x51, 0x83, 0x6C, 0x24,
		0x03, 0x61, 0x68, 0x50, 0x72, 0x6F, 0x63, 0x68, 0x45, 0x78, 0x69, 0x74, 0x54, 0x50, 0xFF, 0xD2,
		0x33, 0xC9, 0x51, 0xFF, 0xD0 };
	
	EnableDebugPrivilege();
	printf("Injection Pid: ");
	scanf("%d", &dwProcessPid);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS,FALSE,dwProcessPid);
	dwAddr = (DWORD)VirtualAllocEx(hProcess,0,0x1000,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
	// WriteProcessMemory(hProcess,pAddr,shellcode,0x105,&dwWritten);
	
	// KiFastSystemCall2NtWriteVirtualMemory
	// KiIntSystemCall2NtWriteVirtualMemory
	__asm
	{
		pushad;
		pushfd;
		lea eax, [dwWritten];
		push eax;
		push 0x105;
		lea ebx, [shellcode];
		push ebx;
		push dwAddr;
		push hProcess;
		call KiFastSystemCall2NtWriteVirtualMemory;
		//call KiIntSystemCall2NtWriteVirtualMemory;
		popfd;
		popad;
	}
	CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)dwAddr, 0, 0, 0);
	system("pause");
	return 0;
}
```

```c
// MyReadProcessMemory.cpp : 定义控制台应用程序的入口点。
//

// 通过逆向 kernel32.dll ntdll.dll，自己实现一个 ReadProcessMemory，不使用上述dll
// 意义是防3环HOOK

#include "stdafx.h"
#include <Windows.h>

BOOL WINAPI HbgReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesRead);
BOOL WINAPI HbgWriteProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesWritten);
BOOL EnableDebugPrivilege();
void TestHbgReadProcessMemory();
void TestHbgWriteProcessMemory();


int _tmain(int argc, _TCHAR* argv[])
{
	// 提权
	EnableDebugPrivilege();
	
	// 测试 HbgReadProcessMemory
	//TestHbgReadProcessMemory();

	// 测试 HbgWriteProcessMemory
	TestHbgWriteProcessMemory();

	getchar();
	return 0;
}

// 将 ReadProcessMemory 和 NtReadVirtualMemory 函数的功能进行了整合和简化
BOOL WINAPI HbgReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesRead)
{
	LONG NtStatus;
	__asm
	{
		lea eax,nSize;
		push eax;
		push nSize;
		push lpBuffer;
		push lpBaseAddress;
		push hProcess;
		sub esp, 0x04; // 模拟 CALL NtReadVirtualMemory 时的压栈
		mov eax, 0xBA;
		mov edx, 0x7FFE0300;
		call dword ptr [edx];
		add esp, 0x18; // 模拟 NtReadVirtualMemory 返回到 ReadProcessMemory 时的 RETN 0x14
		mov NtStatus, eax;
	}
	if (lpNumberOfBytesRead != NULL)
	{
		*lpNumberOfBytesRead = nSize;		
	}
	// 错误检查
	if (NtStatus < 0)
	{
		// 调用 BaseSetLastNTError 获取错误码，这里就偷懒不做了
		return FALSE;
	}
	return TRUE;
}

// 删除了权限检查
BOOL WINAPI HbgWriteProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress, LPVOID lpBuffer, DWORD nSize, LPDWORD lpNumberOfBytesWritten)
{
	LONG NtStatus;
	__asm
	{
		lea eax, nSize;
		push eax; 
		push nSize;
		push lpBuffer;
		push lpBaseAddress;
		push hProcess;
		sub esp, 0x04; // 模拟 CALL NtWriteVirtualMemory 时的压栈
		mov eax, 0x115;
		mov edx, 0x7FFE0300;
		call dword ptr [edx];
		add esp, 0x18; // 模拟 NtReadVirtualMemory 返回到 ReadProcessMemory 时的 RETN 0x14
		mov NtStatus, eax;
	}
	if (lpNumberOfBytesWritten)
	{
		*lpNumberOfBytesWritten = nSize;
	}
	// 错误检查
	if (NtStatus < 0)
	{
		// 调用 BaseSetLastNTError 获取错误码，这里就偷懒不做了
		return FALSE;
	}
	return TRUE;
}

// 提权函数：提升为DEBUG权限
BOOL EnableDebugPrivilege()
{
	HANDLE hToken;
	BOOL fOk=FALSE;
	if(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES,&hToken))
	{
		TOKEN_PRIVILEGES tp;
		tp.PrivilegeCount=1;
		LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&tp.Privileges[0].Luid);

		tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
		AdjustTokenPrivileges(hToken,FALSE,&tp,sizeof(tp),NULL,NULL);

		fOk=(GetLastError()==ERROR_SUCCESS);
		CloseHandle(hToken);
	}
	return fOk;
}

void TestHbgReadProcessMemory()
{
	HANDLE hProcess = NULL;
	DWORD dwRead;
	DWORD pid;
	DWORD address;
	char buf[10] = { 0 };

	// 请求用户输入PID和地址
	printf("请输入要读取数据的进程PID：");
	scanf("%d", &pid);
	getchar();
	printf("请输入要读取的地址（HEX）：");
	scanf("%x", &address);
	getchar();
	// 用户输入
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		printf("打开进程失败 %d\n", GetLastError());
		goto quit;
	}
	if (!HbgReadProcessMemory(hProcess, (LPCVOID)address, buf, 4, &dwRead))
	{
		printf("读取失败.\n");
	}
	else
	{
		printf("读取到的字符串：\"%s\"，读取到的字节数：%d\n", buf, dwRead);
	}
quit:
	CloseHandle(hProcess);
}

void TestHbgWriteProcessMemory()
{
	HANDLE hProcess = NULL;
	DWORD dwRead,dwWritten;
	DWORD pid;
	DWORD address;
	char buf[15] = { 0 };
	
	// 请求用户输入PID和地址
	printf("请输入要读取数据的进程PID：");
	scanf("%d", &pid);
	getchar();
	printf("请输入要读取的地址（HEX）：");
	scanf("%x", &address);
	getchar();
	// 用户输入
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		printf("打开进程失败 %d\n", GetLastError());
		goto quit;
	}
	// 读数据
	if (!HbgReadProcessMemory(hProcess, (LPCVOID)address, buf, 12, &dwRead))
	{
		printf("读取失败.\n");
		goto quit;
	}
	printf("读取到的字符串：\"%s\"，读取到的字节数：%d\n", buf, dwRead);
	// 写数据
	if (!HbgWriteProcessMemory(hProcess, (LPCVOID)address, "1234", 4, &dwWritten))
	{
		printf("写入失败.\n");
		goto quit;
	}
	printf("写入了 %d 字节，尝试再次读取...\n", dwWritten);
	// 读数据
	if (!HbgReadProcessMemory(hProcess, (LPCVOID)address, buf, 12, &dwRead))
	{
		printf("读取失败.\n");
		goto quit;
	}
	printf("读取到的字符串：\"%s\"，读取到的字节数：%d\n", buf, dwRead);
	
quit:
	CloseHandle(hProcess);
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