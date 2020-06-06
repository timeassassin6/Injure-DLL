#include <stdio.h>
#include <windows.h>

int main()
{
	ULONG_PTR uKernelBaseInTargetProc = GetModuleHandleInProcess(dwPid, "kernel32.dll");
	ULONG_PTR uKernelBaseInCurProc = (ULONG_PTR)GetModuleHandle("kernel32.dll");
	ULONG_PTR uLoadLibraryAddrInCurProc = (ULONG_PTR)GetProcAddress((HMODULE)uKernelBaseInTargetProc, "LoadLibraryA");
	ULONG_PTR uLoadLibraryAddrInTargetProc = uLoadLibraryAddrInCurProc - uKernelBaseInCurProc + uKernelBaseInTargetProc;
	printf("[*] Ŀ������� LoadLibraryA Addr = 0x%p\n", uLoadLibraryAddrInTargetProc);
}