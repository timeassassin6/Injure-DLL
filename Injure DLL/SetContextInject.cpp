#include "StdAfx.h"
using namespace std;
#ifdef _WIN64
EXTERN_C VOID ShellCodeFun64(VOID);
#else
VOID ShellCodeFun(VOID);
#endif

struct _DATA_SHELLCODE //�������shellcode�Ľṹ��
{
	BYTE shellcode[0x30];//����LoadLibrary����Dll��shellcode
	ULONG_PTR addrofLoadlibraryA;//Ŀ�������Loadlibrary�ĺ�����ַ
	PBYTE lpdllpath;//��ע��DLL·����Ŀ������е�ָ��
	ULONG ori_rip;//ע����ɺ���Ҫ��ת��λ�ã�Ŀ���������ִ��Ӧ��ִ�е�λ��
	CHAR DllPath[MAX_PATH];//��ע��DLL·��
}ShellCode;

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
		return 0;
	}
	//����Ŀ�����������ģ�飬�õ�ģ����
	if (!EnumProcessModules(hProcess, ModuleArray, sizeof(ModuleArray), &NumberOfModule))
	{
		cout << "EnumProcessModulesʧ��" << endl;
		return 0; 
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
	while (memcpy(pShellcodeEnd, "\x90\x90\x90\x90\x90", 5) != 0)
	{
		pShellcodeEnd++;
	}
	ShellcodeSize = pShellcodeEnd - pShellcodeStart;

	//Shellcode���Ƶ�ָ���Ļ�������
	memcpy(pOutShellcode, pShellcodeStart, ShellcodeSize);
}

BOOL InjectDllToProcessBySetContext(SIZE_T pid)
{
	SIZE_T count = 0;
	SIZE_T TidTable[MAX_PATH];
	THREADENTRY32 ThreadEntry;
	HANDLE hThread;//�洢��ʱ�߳̾��
	CONTEXT context;//�洢��ʱ�߳�CONTEXT
	
	//�õ�Ŀ�������LoadLibraryA�����ĵ�ַ
	ULONG_PTR uKernelBaseInTargetProc = (ULONG_PTR)GetModuleHandleInProcess(18528, "KERNEL32.DLL");
	ULONG_PTR uKernelBaseInCurProc = (ULONG_PTR)GetModuleHandleA("kernel32.dll");
	ULONG_PTR uLoadLibraryAddrInCurProc = (ULONG_PTR)GetProcAddress((HMODULE)uKernelBaseInTargetProc, "LoadLibraryA");
	ULONG_PTR uLoadLibraryAddrInTargetProc = uLoadLibraryAddrInCurProc - uKernelBaseInCurProc + uKernelBaseInTargetProc;
	//printf("[*] Ŀ������� LoadLibraryA Addr = 0x%p\n", uLoadLibraryAddrInTargetProc);
	
	//��ʼ��_DATA_SHELLCODE�ṹ��
	ShellCode.addrofLoadlibraryA = uLoadLibraryAddrInTargetProc;

	//�����̣߳�Ѱ������Ŀ������е��߳�
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

	//��������Ŀ������е��̣߳����߳����л�context��ִ��shellcode
	for (count; count > 0; count--)
	{
		hThread = OpenThread(THREAD_ALL_ACCESS, NULL, TidTable[count]);
		SuspendThread(hThread);
		GetThreadContext(hThread, &context);
		//context.rip
	}
	return 0;
}
