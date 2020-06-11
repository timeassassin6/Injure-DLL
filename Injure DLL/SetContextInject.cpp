#include "StdAfx.h"
using namespace std;
#ifdef _WIN64
EXTERN_C VOID ShellCodeFun64(VOID);
#else
VOID ShellCodeFun(VOID);
#endif
VOID PrepareShellCode(BYTE* pShellCode);

typedef struct _DATA_SHELLCODE //声明存放shellcode的结构体
{
	BYTE shellcode[0x30];//调用LoadLibrary加载Dll的shellcode
	ULONG_PTR addrofLoadlibraryA;//目标进程中Loadlibrary的函数地址
	PBYTE lpdllpath;//待注入DLL路径在目标进程中的指针
	ULONG_PTR ori_rip;//注入完成后需要跳转的位置，目标程序正常执行应该执行的位置
	CHAR DllPath[MAX_PATH];//待注入DLL路径
}INJECT_DATA;

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
		exit(1);
	}
	//遍历目标进程中所有模块，得到模块句柄
	if (!EnumProcessModules(hProcess, ModuleArray, sizeof(ModuleArray), &NumberOfModule))
	{
		cout << "EnumProcessModules失败" << endl;
		exit(1);
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
	while (memcmp(pShellcodeEnd, "\x90\x90\x90\x90\x90", 5) != 0)
	{
		pShellcodeEnd++;
	}
	ShellcodeSize = pShellcodeEnd - pShellcodeStart;

	//Shellcode复制到指定的缓冲区中
	memcpy(pOutShellcode, pShellcodeStart, ShellcodeSize);
}

BOOL InjectDllToProcessBySetContext(SIZE_T pid, char* szDllFullPath)
{
	SIZE_T count = 0;
	SIZE_T TidTable[MAX_PATH] = { 0 };
	THREADENTRY32 ThreadEntry;
	ThreadEntry.dwSize = sizeof(THREADENTRY32);
	HANDLE hThread;//存储临时线程句柄
	CONTEXT context;//存储临时线程CONTEXT
	PBYTE lpData = NULL;
	struct _DATA_SHELLCODE Data;

	//得到目标进程中LoadLibraryA函数的地址
	ULONG_PTR uKernelBaseInTargetProc = (ULONG_PTR)GetModuleHandleInProcess(pid, "KERNEL32.DLL");
	ULONG_PTR uKernelBaseInCurProc = (ULONG_PTR)GetModuleHandleA("kernel32.dll");
	ULONG_PTR uLoadLibraryAddrInCurProc = (ULONG_PTR)GetProcAddress((HMODULE)uKernelBaseInTargetProc, "LoadLibraryA");
	ULONG_PTR uLoadLibraryAddrInTargetProc = uLoadLibraryAddrInCurProc - uKernelBaseInCurProc + uKernelBaseInTargetProc;
	//printf("[*] 目标进程中 LoadLibraryA Addr = 0x%p\n", uLoadLibraryAddrInTargetProc);

	//遍历线程，寻找属于目标进程中的线程
	HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (!hThreadSnap)
	{
		cout << "CreateToolhelp32Snapshot Failed." << endl;
		exit(1);
	}
	if (!Thread32First(hThreadSnap, &ThreadEntry))
	{
		printf("Thread32First,ErrCode:%d",GetLastError());  // Show cause of failure
		CloseHandle(hThreadSnap);
		exit(1);
	}
	do
	{
			if (ThreadEntry.th32OwnerProcessID == pid)
				TidTable[count++] = ThreadEntry.th32ThreadID;
	}
	while (Thread32Next(hThreadSnap, &ThreadEntry));

	CloseHandle(hThreadSnap);

	//打开目标进程
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
	if (!hProcess)
	{
		cout << "OpenProcess Failed." << endl;
		exit(1);
	}

	//遍历所有目标进程中的线程，在线程中切换context，执行shellcode
	while (count > 0)
	{
		count = count - 1;
		printf("Tid:%d\n", TidTable[count]);
		hThread = OpenThread(THREAD_ALL_ACCESS, NULL, TidTable[count]);
		if (!hThread)
		{
			cout << "OpenThread Failed." << endl;
			exit(1);
		}
		SuspendThread(hThread);
		ZeroMemory(&context, sizeof(CONTEXT));
		context.ContextFlags = CONTEXT_FULL;
		if (!GetThreadContext(hThread, &context))
		{
			printf("[-] 无法获取线程 %d 的Context!\n", TidTable[count]);
			CloseHandle(hThread);
			continue;
		}
			   		
		//在目标进程中申请存放Shellcode的内存
		lpData = (PBYTE)VirtualAllocEx(hProcess, NULL, 1000, MEM_COMMIT, PAGE_READWRITE);
		if (lpData == NULL)
		{
			printf("[-] 在目标进程申请内存失败!\n");
			CloseHandle(hThread);
			continue;
		}

		//初始化_DATA_SHELLCODE结构体
		ZeroMemory(&Data, sizeof(_DATA_SHELLCODE));
		PrepareShellcode(Data.shellcode);
		strcpy_s(Data.DllPath, szDllFullPath);
		Data.addrofLoadlibraryA = uLoadLibraryAddrInTargetProc;
		Data.lpdllpath = lpData + FIELD_OFFSET(_DATA_SHELLCODE, DllPath);
#ifdef _WIN64
		Data.ori_rip = context.Rip;
#else
		Data.ori_rip = context.eip
#endif
		//将DATA_SHELLCODE写入目标进程内存中
		if (!WriteProcessMemory(hProcess, lpData, &Data, sizeof(Data), NULL))
		{
			printf("[-] 在目标进程写入内存失败!\n");
			CloseHandle(hThread);
			exit(1);
		}

		//修改context.Rip
		context.Rip = (DWORD64)lpData;

		//重新设置Context,激活暂停的线程
		if (!SetThreadContext(hThread, &context))
		{
			printf("[-] 无法设置线程 %d 的Context!\n", TidTable[count]);
			CloseHandle(hThread);
			continue;
		}
		DWORD dwSuspendCnt = ResumeThread(hThread);
		cout << dwSuspendCnt << endl;
		if (dwSuspendCnt == (DWORD)-1)
		{
			printf("[-] 恢复线程 %d 失败!\n", TidTable[count]);
			CloseHandle(hThread);
			continue;
		}		
		CloseHandle(hThread);
		SleepEx(1000, NULL);
	}
	CloseHandle(hProcess);
	printf("[*] 操作全部完毕.\n");
	return 0;
}

DWORD ProcesstoPid(char* Processname) //查找指定进程的PID(Process ID)
{
	HANDLE hProcessSnap = NULL;
	DWORD ProcessId = 0;
	PROCESSENTRY32 pe32 = { 0 };
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //打开进程快照
	if (hProcessSnap == (HANDLE)-1)
	{
		printf("\nCreateToolhelp32Snapshot() Error: %d", GetLastError());
		return 0;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hProcessSnap, &pe32)) //开始枚举进程
	{
		do
		{
			if (!_stricmp(Processname, pe32.szExeFile)) //判断是否和提供的进程名相等，是，返回进程的ID
			{
				ProcessId = pe32.th32ProcessID;
				break;
			}
		} while (Process32Next(hProcessSnap, &pe32)); //继续枚举进程
	}
	else
	{
		printf("\nProcess32First() Error: %d", GetLastError());
		return 0;
	}
	CloseHandle(hProcessSnap); //关闭系统进程快照的句柄
	cout << "ProcessId:" << ProcessId << endl;
	return ProcessId;
}
