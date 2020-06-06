#include <stdio.h>
#include <windows.h>
#include <TLHELP32.h>
#include <psapi.h>

struct _DATA_SHELLCODE //声明存放shellcode的结构体
{
	BYTE shellcode[0x30];//调用LoadLibrary加载Dll的shellcode
	ULONG_PTR addrofLoadlibraryA;//目标进程中Loadlibrary的函数地址
	PBYTE lpdllpath;//待注入DLL所在路径
	ULONG ori_rip;//注入完成后需要跳转的位置，目标程序正常执行应该执行的位置 
}DATA_SHELLCODE;

HMODULE GetModuleHandleInProcess(SIZE_T pid, LPWSTR ModulePath)
{
	HMODULE *ModuleArray;
	size_t ModuleArraySize = 100;
	ModuleArray = new HMODULE[ModuleArraySize];
	DWORD NumberOfModule;
	LPWSTR lpBaseName;
	//打开目标进程
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
	//遍历目标进程中所有模块，得到模块句柄
	if(!EnumProcessModules(hProcess,ModuleArray,ModuleArraySize*sizeof(HANDLE), &NumberOfModule))
		printf("EnumProcessModules失败\n");
	NumberOfModule /= sizeof(HANDLE);
	for (size_t i = 0; i < NumberOfModule; i++)
	{
		GetModuleBaseName(hProcess, ModuleArray[i], lpBaseName, MAX_PATH);
		if (lpBaseName == ModulePath)
		{
			return ModuleArray[i];
		}
	}
	printf("未发现要查找的DLL\n");
	return 0;
}

BOOL InjectDllToProcessBySetContext(SIZE_T pid)
{
	SIZE_T count = 0;
	SIZE_T TidTable[MAX_PATH];
	THREADENTRY32 ThreadEntry;
	HANDLE hThread;//存储临时线程句柄
	CONTEXT context;//存储临时线程CONTEXT
	
	//初始化_DATA_SHELLCODE结构体

	//获取目标进程中Loadlibrary的函数地址

	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (Thread32First(hThreadSnap, &ThreadEntry))
	{
		do
		{
			if (ThreadEntry.th32OwnerProcessID == pid)
			{
				TidTable[count++] = ThreadEntry.th32ThreadID;
			}

		} while (Thread32Next(hThreadSnap, &ThreadEntry));
	}
	for (count; count > 0; count--)
	{
		hThread = OpenThread(THREAD_ALL_ACCESS, NULL, TidTable[count]);
		GetThreadContext(hThread, &context);
		context.rip
	}


}
