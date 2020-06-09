#pragma once
#include "StdAfx.h"

HMODULE GetModuleHandleInProcess(SIZE_T pid, const char* ModuleName);
BOOL InjectDllToProcessBySetContext(SIZE_T pid);