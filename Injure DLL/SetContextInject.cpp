#include <stdio.h>
#include <windows.h>
#include <TLHELP32.h>

struct _DATA_SHELLCODE //�������shellcode�Ľṹ��
{
	BYTE shellcode[0x30];
	ULONG_PTR addrofLoadlibraryA;
	PBYTE lpdllpath;
	ULONG ori_rip;
}DATA_SHELLCODE;

BOOL InjectDllToProcessBySetContext(SIZE_T pid)
{
	SIZE_T count = 0;
	SIZE_T TidTable[MAX_PATH];
	THREADENTRY32 ThreadEntry;
	HANDLE hThread;//�洢��ʱ�߳̾��
	CONTEXT context;//�洢��ʱ�߳�CONTEXT
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
