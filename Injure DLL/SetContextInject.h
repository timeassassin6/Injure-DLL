#pragma once
#include "StdAfx.h"

HMODULE GetModuleHandleInProcess(SIZE_T pid, const char* ModuleName);
BOOL InjectDllToProcessBySetContext(SIZE_T pid, char* szDllFullPath);
DWORD ProcesstoPid(char* Processname);
typedef struct _DATA_SHELLCODE //声明存放shellcode的结构体
{
	BYTE shellcode[0x30];//调用LoadLibrary加载Dll的shellcode
	ULONG_PTR addrofLoadlibraryA;//目标进程中Loadlibrary的函数地址
	PBYTE lpdllpath;//待注入DLL路径在目标进程中的指针
	ULONG_PTR ori_rip;//注入完成后需要跳转的位置，目标程序正常执行应该执行的位置
	CHAR DllPath[MAX_PATH];//待注入DLL路径
}INJECT_DATA;