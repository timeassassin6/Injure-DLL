#include <stdio.h>
#include <windows.h>
#include <TLHELP32.h>
#include <psapi.h>

struct _DATA_SHELLCODE //�������shellcode�Ľṹ��
{
	BYTE shellcode[0x30];//����LoadLibrary����Dll��shellcode
	ULONG_PTR addrofLoadlibraryA;//Ŀ�������Loadlibrary�ĺ�����ַ
	PBYTE lpdllpath;//��ע��DLL����·��
	ULONG ori_rip;//ע����ɺ���Ҫ��ת��λ�ã�Ŀ���������ִ��Ӧ��ִ�е�λ�� 
}DATA_SHELLCODE;

HMODULE GetModuleHandleInProcess(SIZE_T pid, LPWSTR ModulePath)
{
	HMODULE *ModuleArray;
	size_t ModuleArraySize = 100;
	ModuleArray = new HMODULE[ModuleArraySize];
	DWORD NumberOfModule;
	LPWSTR lpBaseName;
	//��Ŀ�����
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
	//����Ŀ�����������ģ�飬�õ�ģ����
	if(!EnumProcessModules(hProcess,ModuleArray,ModuleArraySize*sizeof(HANDLE), &NumberOfModule))
		printf("EnumProcessModulesʧ��\n");
	NumberOfModule /= sizeof(HANDLE);
	for (size_t i = 0; i < NumberOfModule; i++)
	{
		GetModuleBaseName(hProcess, ModuleArray[i], lpBaseName, MAX_PATH);
		if (lpBaseName == ModulePath)
		{
			return ModuleArray[i];
		}
	}
	printf("δ����Ҫ���ҵ�DLL\n");
	return 0;
}

BOOL InjectDllToProcessBySetContext(SIZE_T pid)
{
	SIZE_T count = 0;
	SIZE_T TidTable[MAX_PATH];
	THREADENTRY32 ThreadEntry;
	HANDLE hThread;//�洢��ʱ�߳̾��
	CONTEXT context;//�洢��ʱ�߳�CONTEXT
	
	//��ʼ��_DATA_SHELLCODE�ṹ��

	//��ȡĿ�������Loadlibrary�ĺ�����ַ

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
