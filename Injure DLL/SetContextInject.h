#pragma once
#include "StdAfx.h"

HMODULE GetModuleHandleInProcess(SIZE_T pid, const char* ModuleName);
BOOL InjectDllToProcessBySetContext(SIZE_T pid, char* szDllFullPath);
DWORD ProcesstoPid(char* Processname);
typedef struct _DATA_SHELLCODE //�������shellcode�Ľṹ��
{
	BYTE shellcode[0x30];//����LoadLibrary����Dll��shellcode
	ULONG_PTR addrofLoadlibraryA;//Ŀ�������Loadlibrary�ĺ�����ַ
	PBYTE lpdllpath;//��ע��DLL·����Ŀ������е�ָ��
	ULONG_PTR ori_rip;//ע����ɺ���Ҫ��ת��λ�ã�Ŀ���������ִ��Ӧ��ִ�е�λ��
	CHAR DllPath[MAX_PATH];//��ע��DLL·��
}INJECT_DATA;