#include <stdio.h>
#include <windows.h>
#include <TLHELP32.h>

struct _DATA_SHELLCODE //声明存放shellcode的结构体
{
	BYTE shellcode[0x30];
	ULONG_PTR addrofLoadlibraryA;
	PBYTE lpdllpath;
	ULONG ori_eip;
}DATA_SHELLCODE;

BOOL InjectDllToProcessBySetContext(SIZE_T pid)
{
	SIZE_T TidTable[MAX_PATH];
	CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);

}
