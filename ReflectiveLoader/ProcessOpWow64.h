#pragma once
#include "ProcessOp.h"
#include "wow64ext/wow64ext.h"
class ProcessOpWow64 : public ProcessOp
{
public:
	ProcessOpWow64(HANDLE hProcess)
		: ProcessOp(hProcess)
	{

	}

	~ProcessOpWow64()
	{

	}

public:
	BOOL VirtualAllocExT(ADDR_T& lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
	{
		lpAddress = VirtualAllocEx64(m_hProcess, lpAddress, dwSize, flAllocationType, flProtect);
		return lpAddress != NULL;
	}


	BOOL VirtualFreeExT(ADDR_T lpAddress, SIZE_T dwSize, DWORD dwFreeType)
	{
		return VirtualFreeEx64(m_hProcess, lpAddress, dwSize, dwFreeType);
	}


	BOOL ReadProcessMemoryT(ADDR_T lpAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead)
	{
		return ReadProcessMemory64(m_hProcess, lpAddress, lpBuffer, nSize, lpNumberOfBytesRead);
	}


	BOOL WriteProcessMemoryT(ADDR_T lpAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
	{
		return WriteProcessMemory64(m_hProcess, lpAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
	}


	BOOL VirtualProtectExT(ADDR_T lpAddress, SIZE_T dwSize, DWORD flNewProtect, DWORD* lpflOldProtect)
	{
		return VirtualProtectEx64(m_hProcess, lpAddress, dwSize, flNewProtect, lpflOldProtect);
	}


	ADDR_T GetModuleHandleT(LPCWSTR lpModuleName)
	{
		return GetModuleHandle64(lpModuleName);
	}


	ADDR_T GetProcAddressT(ADDR_T hModule, LPCSTR lpProcName)
	{
		return GetProcAddress64(hModule, lpProcName);
	}


	BOOL CreateRemoteThreadT(
		HANDLE& hThread, 
		ADDR_T lpStartAddress, 
		ADDR_T lpParameter, 
		DWORD dwCreationFlags, 
		DWORD access = THREAD_ALL_ACCESS)
	{
		DWORD64 hModule = getNTDLL64();
		static ADDR_T pfnNtCreateThreadEx = NULL;
		if (!hModule)
			return FALSE;
		
		pfnNtCreateThreadEx = GetProcAddress64(hModule, "NtCreateThreadEx");
		if (pfnNtCreateThreadEx == NULL)
			return FALSE;

		DWORD64 hThd2 = NULL;

        NTSTATUS status = static_cast<NTSTATUS>(X64Call(
			pfnNtCreateThreadEx, 11, (DWORD64)&hThd2, (DWORD64)access, 0ull,
            (DWORD64)m_hProcess, (DWORD64)lpStartAddress, (DWORD64)lpParameter, 0ull,
            0ull, 0x1000ull, 0x100000ull, 0ull
		));
	
		hThread = reinterpret_cast<HANDLE>(hThd2);
		return status == 0;
	}

    virtual BOOL QueueUserAPCT(HANDLE hThread, ADDR_T lpStartAddress, ADDR_T lpParameter)
    {

        DWORD64 hModule = getNTDLL64();
        static ADDR_T pfnNtQueueApcThread = NULL;
        if (!hModule)
            return FALSE;

        pfnNtQueueApcThread = GetProcAddress64(hModule, "NtQueueApcThread");
        if (pfnNtQueueApcThread == NULL)
            return FALSE;

        NTSTATUS status = static_cast<NTSTATUS>(X64Call(
			pfnNtQueueApcThread, 5, 
			(DWORD64)hThread, (DWORD64)lpStartAddress, (DWORD64)lpParameter, 0ull, 0ull
		));

        return status == 0;
    }

};

