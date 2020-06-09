#include "StdAfx.h"
using namespace std;
#ifdef _WIN64
EXTERN_C VOID ShellCodeFun64(VOID);
#else
VOID ShellCodeFun(VOID);
#endif

struct _DATA_SHELLCODE //声明存放shellcode的结构体
{
	BYTE shellcode[0x30];//调用LoadLibrary加载Dll的shellcode
	ULONG_PTR addrofLoadlibraryA;//目标进程中Loadlibrary的函数地址
	PBYTE lpdllpath;//待注入DLL路径在目标进程中的指针
	ULONG ori_rip;//注入完成后需要跳转的位置，目标程序正常执行应该执行的位置
	CHAR DllPath[MAX_PATH];//待注入DLL路径
}ShellCode;

HMODULE GetModuleHandleInProcess(SIZE_T pid, const char* ModuleName)
{
	HMODULE ModuleArray[1024];
	DWORD NumberOfModule;
	CHAR lpBaseName[MAX_PATH];
	//打开目标进程
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
	if (!hProcess)
	{
		cout << "OpenProcess Failed" << endl;
		return 0;
	}
	//遍历目标进程中所有模块，得到模块句柄
	if (!EnumProcessModules(hProcess, ModuleArray, sizeof(ModuleArray), &NumberOfModule))
	{
		cout << "EnumProcessModules失败" << endl;
		return 0; 
	}
	//句柄数量=字节数量/HANDLE长度
	NumberOfModule /= sizeof(HANDLE);
	//遍历模块句柄名称，找到需要的模块
	for (size_t i = 0; i < NumberOfModule; i++)
	{
		cout << ModuleArray[i] << endl;
		//根据模块句柄获得句柄名
		if (!GetModuleBaseNameA(hProcess, ModuleArray[i], lpBaseName, sizeof(lpBaseName)/sizeof(CHAR)))
		{
			cout << "GetModuleBaseName Failed,Error coed:" << GetLastError() << endl;
			continue;
		}
		//Debug Output:
		printf("%s\n", lpBaseName);
		//printf("%s\n", (const char*)lpBaseName);
		//printf("%s\n", ModuleName);
		/*cout << lpBaseName << endl; */                                            
		if (strcmp((const char*)lpBaseName, ModuleName)==0)
		{
			CloseHandle(hProcess);
			return ModuleArray[i];
		}
	}
	cout << "未发现要查找的DLL\n" << endl;
	exit(1);
}

VOID PrepareShellcode(BYTE* pOutShellcode)
{
	BYTE *pShellcodeStart, *pShellcodeEnd;
	int ShellcodeSize = 0;

	//asm文件中定义的函数起始地址作为ShellCode的起始地址
	pShellcodeStart = (BYTE*)ShellCodeFun64;
	pShellcodeEnd = pShellcodeStart;

	//找到Shellcode的结尾，确定Shellcode的长度
	while (memcpy(pShellcodeEnd, "\x90\x90\x90\x90\x90", 5) != 0)
	{
		pShellcodeEnd++;
	}
	ShellcodeSize = pShellcodeEnd - pShellcodeStart;

	//Shellcode复制到指定的缓冲区中
	memcpy(pOutShellcode, pShellcodeStart, ShellcodeSize);
}

BOOL InjectDllToProcessBySetContext(SIZE_T pid)
{
	SIZE_T count = 0;
	SIZE_T TidTable[MAX_PATH];
	THREADENTRY32 ThreadEntry;
	HANDLE hThread;//存储临时线程句柄
	CONTEXT context;//存储临时线程CONTEXT
	
	//得到目标进程中LoadLibraryA函数的地址
	ULONG_PTR uKernelBaseInTargetProc = (ULONG_PTR)GetModuleHandleInProcess(18528, "KERNEL32.DLL");
	ULONG_PTR uKernelBaseInCurProc = (ULONG_PTR)GetModuleHandleA("kernel32.dll");
	ULONG_PTR uLoadLibraryAddrInCurProc = (ULONG_PTR)GetProcAddress((HMODULE)uKernelBaseInTargetProc, "LoadLibraryA");
	ULONG_PTR uLoadLibraryAddrInTargetProc = uLoadLibraryAddrInCurProc - uKernelBaseInCurProc + uKernelBaseInTargetProc;
	//printf("[*] 目标进程中 LoadLibraryA Addr = 0x%p\n", uLoadLibraryAddrInTargetProc);
	
	//初始化_DATA_SHELLCODE结构体
	ShellCode.addrofLoadlibraryA = uLoadLibraryAddrInTargetProc;

	//遍历线程，寻找属于目标进程中的线程
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

	//遍历所有目标进程中的线程，在线程中切换context，执行shellcode
	for (count; count > 0; count--)
	{
		hThread = OpenThread(THREAD_ALL_ACCESS, NULL, TidTable[count]);
		SuspendThread(hThread);
		GetThreadContext(hThread, &context);
		//context.rip
	}
	return 0;
}
