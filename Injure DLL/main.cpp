#include "StdAfx.h"
using namespace std;

int main()
{
	CHAR* ProcessName = (CHAR*)"HostProc64.exe";
	CHAR* DllPath = (CHAR*)"C:\\Users\\lihaodong\\Desktop\\��������������ļ�\\PEDIY_BOOK4_v2\\PEDIY_BOOK4_v2\\chap12\\MsgDll\\x64_Release\\MsgDll64.dll";
	int Pid = ProcesstoPid(ProcessName);
	InjectDllToProcessBySetContext(Pid, DllPath);
	return 0;
}