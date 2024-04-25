#pragma once
#include "ProcessOpWow64.h"

#define SYSTEM_ARCH_UNKNOWN                 0
#define SYSTEM_ARCH_X86                     1
#define SYSTEM_ARCH_X64                     2

#define PROCESS_ARCH_UNKNOWN                0
#define PROCESS_ARCH_X86                    1
#define PROCESS_ARCH_X64                    2

#define INJECT_TYPE_UNKNOWN                 0
#define INJECT_TYPE_NORMAL                  1
#define INJECT_TYPE_WOW64                   2

#ifdef _WIN64
#define CurrentArch PROCESS_ARCH_X64
#else
#define CurrentArch PROCESS_ARCH_X86
#endif

typedef void (WINAPI* GetNativeSystemInfo_Type)(LPSYSTEM_INFO);
typedef BOOL(WINAPI* IsWow64Process_Type) (HANDLE, PBOOL);

struct Enviroment_Info
{
    DWORD dwSystemArch;
    DWORD dwSourceProcessArch;
    DWORD dwTargetProcessArch;
    DWORD dwInjectType;

    Enviroment_Info()
    {
        dwSystemArch = SYSTEM_ARCH_UNKNOWN;
        dwSourceProcessArch = PROCESS_ARCH_UNKNOWN;
        dwTargetProcessArch = PROCESS_ARCH_UNKNOWN;
        dwInjectType = INJECT_TYPE_UNKNOWN;
    }
};

class ProcessOpWrapper
{
public:
    ProcessOpWrapper(HANDLE hProcess)
        : m_pImpl(NULL),
        m_bInitSuccessed(FALSE)
	{
        DuplicateHandle(GetCurrentProcess(), 
            hProcess, 
            GetCurrentProcess(), 
            &m_hProcess, 
            NULL, 
            NULL, 
            DUPLICATE_SAME_ACCESS);

        m_bInitSuccessed = InitArchEnviroment();

        if (m_bInitSuccessed)
        {
            if (m_EnviromentInfo.dwInjectType == INJECT_TYPE_NORMAL)
            {
                m_pImpl = new ProcessOp(m_hProcess);
            }
            else if (m_EnviromentInfo.dwInjectType == INJECT_TYPE_WOW64)
            {
                m_pImpl = static_cast<ProcessOp*>(new ProcessOpWow64(m_hProcess));
            }
        }
	}

	~ProcessOpWrapper()
	{
        if (m_pImpl)
        {
            delete m_pImpl;
            m_pImpl = NULL;
        }

        if (m_hProcess)
        {
            CloseHandle(m_hProcess);
        }
	}

    DWORD GetInjectType()
    {
        return m_EnviromentInfo.dwInjectType;
    }

    DWORD GetTargetArch()
    {
        return m_EnviromentInfo.dwTargetProcessArch;
    }

	ProcessOp* operator ->()
	{
        return m_pImpl;
	}

    operator bool() const
    {
        return m_pImpl != NULL;
    }

protected:
	BOOL InitArchEnviroment()
	{
        HANDLE hProcess = NULL;
        BOOL bRet = FALSE;

        SYSTEM_INFO sysInfo = { 0 };
        BOOL Isx64 = FALSE;

        HMODULE hModule = GetModuleHandleW(L"kernel32.dll");
        if (hModule == NULL)
            return FALSE;

        GetNativeSystemInfo_Type pfnGetNativeSystemInfo = (GetNativeSystemInfo_Type)GetProcAddress(hModule, "GetNativeSystemInfo");
        if (pfnGetNativeSystemInfo == NULL)
            return FALSE;

        pfnGetNativeSystemInfo(&sysInfo);
        switch (sysInfo.wProcessorArchitecture)
        {
        case PROCESSOR_ARCHITECTURE_IA64:
        case PROCESSOR_ARCHITECTURE_AMD64:
            Isx64 = TRUE;
            break;
        case PROCESSOR_ARCHITECTURE_INTEL:
            Isx64 = FALSE;
            break;
        default:
            return FALSE;
        }

        m_EnviromentInfo.dwSourceProcessArch = CurrentArch;
        m_EnviromentInfo.dwTargetProcessArch = PROCESS_ARCH_X86;
        if (Isx64)
        {
            IsWow64Process_Type pfnIsWow64Process = (IsWow64Process_Type)GetProcAddress(hModule, "IsWow64Process");
            if (pfnIsWow64Process == NULL)
                return FALSE;

            BOOL bIsWow64 = FALSE;
            if (!pfnIsWow64Process(m_hProcess, &bIsWow64))
            {
                return FALSE;
            }

            if (!bIsWow64)
                m_EnviromentInfo.dwTargetProcessArch = PROCESS_ARCH_X64;
        }


        if (m_EnviromentInfo.dwSourceProcessArch == m_EnviromentInfo.dwTargetProcessArch)
        {
            //x86 -> x86  ||  x64 -> x64
            m_EnviromentInfo.dwInjectType = INJECT_TYPE_NORMAL;
        }
        else if (m_EnviromentInfo.dwSourceProcessArch == PROCESS_ARCH_X86
            && m_EnviromentInfo.dwTargetProcessArch == PROCESS_ARCH_X64)
        {
            //x86 -> x64
            m_EnviromentInfo.dwInjectType = INJECT_TYPE_WOW64;
        }
        else
        {
            //x64 -> x86
            m_EnviromentInfo.dwInjectType = INJECT_TYPE_UNKNOWN;
        }

        return TRUE;
	}

private:
    BOOL m_bInitSuccessed;
    HANDLE m_hProcess;
    Enviroment_Info m_EnviromentInfo;
	ProcessOp* m_pImpl;
};