#include "StdAfx.h"
using namespace std;
#ifdef _WIN64
EXTERN_C VOID ShellCodeFun64(VOID);
#else
VOID ShellCodeFun(VOID);
#endif
VOID PrepareShellCode(BYTE* pShellCode);

typedef struct _DATA_SHELLCODE //�������shellcode�Ľṹ��
{
	BYTE shellcode[0x30];//����LoadLibrary����Dll��shellcode
	ULONG_PTR addrofLoadlibraryA;//Ŀ�������Loadlibrary�ĺ�����ַ
	PBYTE lpdllpath;//��ע��DLL·����Ŀ������е�ָ��
	ULONG_PTR ori_rip;//ע����ɺ���Ҫ��ת��λ�ã�Ŀ���������ִ��Ӧ��ִ�е�λ��
	CHAR DllPath[MAX_PATH];//��ע��DLL·��
}INJECT_DATA;

HMODULE GetModuleHandleInProcess(SIZE_T pid, const char* ModuleName)
{
	HMODULE ModuleArray[1024];
	DWORD NumberOfModule;
	CHAR lpBaseName[MAX_PATH];
	//��Ŀ�����
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
	if (!hProcess)
	{
		cout << "OpenProcess Failed" << endl;
		exit(1);
	}
	//����Ŀ�����������ģ�飬�õ�ģ����
	if (!EnumProcessModules(hProcess, ModuleArray, sizeof(ModuleArray), &NumberOfModule))
	{
		cout << "EnumProcessModulesʧ��" << endl;
		exit(1);
	}
	//�������=�ֽ�����/HANDLE����
	NumberOfModule /= sizeof(HANDLE);
	//����ģ�������ƣ��ҵ���Ҫ��ģ��
	for (size_t i = 0; i < NumberOfModule; i++)
	{
		cout << ModuleArray[i] << endl;
		//����ģ������þ����
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
	cout << "δ����Ҫ���ҵ�DLL\n" << endl;
	exit(1);
}

VOID PrepareShellcode(BYTE* pOutShellcode)
{
	BYTE *pShellcodeStart, *pShellcodeEnd;
	int ShellcodeSize = 0;

	//asm�ļ��ж���ĺ�����ʼ��ַ��ΪShellCode����ʼ��ַ
	pShellcodeStart = (BYTE*)ShellCodeFun64;
	pShellcodeEnd = pShellcodeStart;

	//�ҵ�Shellcode�Ľ�β��ȷ��Shellcode�ĳ���
	while (memcmp(pShellcodeEnd, "\x90\x90\x90\x90\x90", 5) != 0)
	{
		pShellcodeEnd++;
	}
	ShellcodeSize = pShellcodeEnd - pShellcodeStart;

	//Shellcode���Ƶ�ָ���Ļ�������
	memcpy(pOutShellcode, pShellcodeStart, ShellcodeSize);
}

BOOL InjectDllToProcessBySetContext(SIZE_T pid, char* szDllFullPath)
{
	SIZE_T count = 0;
	SIZE_T TidTable[MAX_PATH] = { 0 };
	THREADENTRY32 ThreadEntry;
	ThreadEntry.dwSize = sizeof(THREADENTRY32);
	HANDLE hThread;//�洢��ʱ�߳̾��
	CONTEXT context;//�洢��ʱ�߳�CONTEXT
	PBYTE lpData = NULL;
	struct _DATA_SHELLCODE Data;

	//�õ�Ŀ�������LoadLibraryA�����ĵ�ַ
	ULONG_PTR uKernelBaseInTargetProc = (ULONG_PTR)GetModuleHandleInProcess(pid, "KERNEL32.DLL");
	ULONG_PTR uKernelBaseInCurProc = (ULONG_PTR)GetModuleHandleA("kernel32.dll");
	ULONG_PTR uLoadLibraryAddrInCurProc = (ULONG_PTR)GetProcAddress((HMODULE)uKernelBaseInTargetProc, "LoadLibraryA");
	ULONG_PTR uLoadLibraryAddrInTargetProc = uLoadLibraryAddrInCurProc - uKernelBaseInCurProc + uKernelBaseInTargetProc;
	//printf("[*] Ŀ������� LoadLibraryA Addr = 0x%p\n", uLoadLibraryAddrInTargetProc);

	//�����̣߳�Ѱ������Ŀ������е��߳�
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

	//��Ŀ�����
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
	if (!hProcess)
	{
		cout << "OpenProcess Failed." << endl;
		exit(1);
	}

	//��������Ŀ������е��̣߳����߳����л�context��ִ��shellcode
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
			printf("[-] �޷���ȡ�߳� %d ��Context!\n", TidTable[count]);
			CloseHandle(hThread);
			continue;
		}
			   		
		//��Ŀ�������������Shellcode���ڴ�
		lpData = (PBYTE)VirtualAllocEx(hProcess, NULL, 1000, MEM_COMMIT, PAGE_READWRITE);
		if (lpData == NULL)
		{
			printf("[-] ��Ŀ����������ڴ�ʧ��!\n");
			CloseHandle(hThread);
			continue;
		}

		//��ʼ��_DATA_SHELLCODE�ṹ��
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
		//��DATA_SHELLCODEд��Ŀ������ڴ���
		if (!WriteProcessMemory(hProcess, lpData, &Data, sizeof(Data), NULL))
		{
			printf("[-] ��Ŀ�����д���ڴ�ʧ��!\n");
			CloseHandle(hThread);
			exit(1);
		}

		//�޸�context.Rip
		context.Rip = (DWORD64)lpData;

		//��������Context,������ͣ���߳�
		if (!SetThreadContext(hThread, &context))
		{
			printf("[-] �޷������߳� %d ��Context!\n", TidTable[count]);
			CloseHandle(hThread);
			continue;
		}
		DWORD dwSuspendCnt = ResumeThread(hThread);
		cout << dwSuspendCnt << endl;
		if (dwSuspendCnt == (DWORD)-1)
		{
			printf("[-] �ָ��߳� %d ʧ��!\n", TidTable[count]);
			CloseHandle(hThread);
			continue;
		}		
		CloseHandle(hThread);
		SleepEx(1000, NULL);
	}
	CloseHandle(hProcess);
	printf("[*] ����ȫ�����.\n");
	return 0;
}

DWORD ProcesstoPid(char* Processname) //����ָ�����̵�PID(Process ID)
{
	HANDLE hProcessSnap = NULL;
	DWORD ProcessId = 0;
	PROCESSENTRY32 pe32 = { 0 };
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //�򿪽��̿���
	if (hProcessSnap == (HANDLE)-1)
	{
		printf("\nCreateToolhelp32Snapshot() Error: %d", GetLastError());
		return 0;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32);
	if (Process32First(hProcessSnap, &pe32)) //��ʼö�ٽ���
	{
		do
		{
			if (!_stricmp(Processname, pe32.szExeFile)) //�ж��Ƿ���ṩ�Ľ�������ȣ��ǣ����ؽ��̵�ID
			{
				ProcessId = pe32.th32ProcessID;
				break;
			}
		} while (Process32Next(hProcessSnap, &pe32)); //����ö�ٽ���
	}
	else
	{
		printf("\nProcess32First() Error: %d", GetLastError());
		return 0;
	}
	CloseHandle(hProcessSnap); //�ر�ϵͳ���̿��յľ��
	cout << "ProcessId:" << ProcessId << endl;
	return ProcessId;
}
