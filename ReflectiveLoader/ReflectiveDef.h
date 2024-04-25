#pragma once
#include <windows.h>

template<class T>
struct Reflective_Param
{
    T DllBuffer;
    T DllLength;
    T pfnNtAllocateVirtualMemory;
    T pfnLdrLoadDll;
    T pfnGetProcedureAddress;
    T pfnRtlInitAnsiString;
    T pfnRtlAnsiStringToUnicodeString;
    T pfnRtlFreeUnicodeString;
};
