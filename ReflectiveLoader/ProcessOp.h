#pragma once
#include <windows.h>

typedef __int64 ADDR_T;

class ProcessOp
{
protected:
    HANDLE m_hProcess;

public:
    ProcessOp(HANDLE hProcess)
        : m_hProcess(hProcess)
    {

    }
    ~ProcessOp()
    {

    }

public:
    virtual BOOL VirtualAllocExT(ADDR_T& lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
    {
        lpAddress = reinterpret_cast<ADDR_T>(VirtualAllocEx(m_hProcess, reinterpret_cast<LPVOID>(lpAddress), dwSize, flAllocationType, flProtect));
        return lpAddress != 0;
    }

    virtual BOOL VirtualFreeExT(ADDR_T lpAddress, SIZE_T dwSize, DWORD dwFreeType)
    {
        return VirtualFreeEx(m_hProcess, reinterpret_cast<LPVOID>(lpAddress), dwSize, dwFreeType);
    }

    virtual BOOL ReadProcessMemoryT(ADDR_T lpAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
    {
        return ReadProcessMemory(m_hProcess, reinterpret_cast<LPCVOID>(lpAddress), lpBuffer, nSize, lpNumberOfBytesRead);
    }

    virtual BOOL WriteProcessMemoryT(ADDR_T lpAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
    {
        return WriteProcessMemory(m_hProcess, reinterpret_cast<LPVOID>(lpAddress), lpBuffer, nSize, lpNumberOfBytesWritten);
    }

    virtual BOOL VirtualProtectExT(ADDR_T lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect)
    {
        return VirtualProtectEx(m_hProcess, reinterpret_cast<LPVOID>(lpAddress), dwSize, flNewProtect, lpflOldProtect);
    }

    virtual ADDR_T GetModuleHandleT(LPCWSTR lpModuleName)
    {
        return reinterpret_cast<ADDR_T>(GetModuleHandle(lpModuleName));
    }
     
    virtual ADDR_T GetProcAddressT(ADDR_T hModule, LPCSTR lpProcName)
    {
        return reinterpret_cast<ADDR_T>(GetProcAddress(reinterpret_cast<HMODULE>(hModule), lpProcName));
    }

    virtual BOOL CreateRemoteThreadT(
        HANDLE& hThread, 
        ADDR_T lpStartAddress, 
        ADDR_T lpParameter, 
        DWORD dwCreationFlags, 
        DWORD access = THREAD_ALL_ACCESS)
    {
        hThread = CreateRemoteThread(
            m_hProcess,
            NULL,
            0,
            reinterpret_cast<PTHREAD_START_ROUTINE>(lpStartAddress),
            reinterpret_cast<LPVOID>(lpParameter),
            dwCreationFlags,
            NULL);

        return hThread != NULL;
    }

    virtual BOOL QueueUserAPCT(HANDLE hThread, ADDR_T lpStartAddress, ADDR_T lpParameter)
    {
        return QueueUserAPC(reinterpret_cast<PAPCFUNC>(lpStartAddress), hThread, static_cast<ULONG_PTR>(lpParameter));
    }
};

