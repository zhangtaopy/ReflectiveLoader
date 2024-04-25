#include "ReflectiveInjector.h"
#include "ProcessOp.h"

#define ReflectiveExportName "?rl@"

#define DEREF( name )*(UINT_PTR *)(name)
#define DEREF_64( name )*(DWORD64 *)(name)
#define DEREF_32( name )*(DWORD *)(name)
#define DEREF_16( name )*(WORD *)(name)
#define DEREF_8( name )*(BYTE *)(name)

ReflectiveInjector::ReflectiveInjector()
{

}

ReflectiveInjector::~ReflectiveInjector()
{

}

BOOL ReflectiveInjector::ApcInject(DWORD dwPid, DWORD dwTid, LPCWSTR lpModuleName)
{
    HANDLE hProcess = NULL;

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
    if (hProcess == NULL)
        return FALSE;

    do 
    {
        ProcessOpWrapper ProcessHelper(hProcess);
        if(!ProcessHelper)
            break;

        ADDR_T ReflectiveLoaderAddr = NULL;
        ADDR_T ParamAddr = NULL;
        if(!_MapFileAndParamToRemote(ProcessHelper, lpModuleName, ReflectiveLoaderAddr, ParamAddr)
            || ReflectiveLoaderAddr == NULL)
            break;

        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwTid);
        if(hThread == NULL)
            break;
        ProcessHelper->QueueUserAPCT(hThread, ReflectiveLoaderAddr, ParamAddr);

        CloseHandle(hThread);

    } while (0);

    if (hProcess)
    {
        CloseHandle(hProcess);
        hProcess = NULL;
    }

    return TRUE;
}

BOOL ReflectiveInjector::RemoteThreadInject(DWORD dwPid, LPCWSTR lpModuleName)
{
    HANDLE hProcess = NULL;

    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
    if (hProcess == NULL)
        return FALSE;

    do
    {
        ProcessOpWrapper ProcessHelper(hProcess);
        if (!ProcessHelper)
            break;

        ADDR_T ReflectiveLoaderAddr = NULL;
        ADDR_T ParamAddr = NULL;
        if (!_MapFileAndParamToRemote(ProcessHelper, lpModuleName, ReflectiveLoaderAddr, ParamAddr)
            || ReflectiveLoaderAddr == NULL)
            break;

        HANDLE hThread = NULL;
        if(!ProcessHelper->CreateRemoteThreadT(hThread, ReflectiveLoaderAddr, ParamAddr, 0))
            break;

    } while (0);

    if (hProcess)
    {
        CloseHandle(hProcess);
        hProcess = NULL;
    }

    return TRUE;
}

DWORD Rva2Offset(DWORD dwRva, UINT_PTR uiBaseAddress, BOOL is64)
{
    WORD wIndex = 0;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;
    PIMAGE_NT_HEADERS32 pNtHeaders32 = NULL;
    PIMAGE_NT_HEADERS64 pNtHeaders64 = NULL;

    if (is64) {
        pNtHeaders64 = (PIMAGE_NT_HEADERS64)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

        pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders64->OptionalHeader) + pNtHeaders64->FileHeader.SizeOfOptionalHeader);

        if (dwRva < pSectionHeader[0].PointerToRawData)
            return dwRva;

        for (wIndex = 0; wIndex < pNtHeaders64->FileHeader.NumberOfSections; wIndex++)
        {
            if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
                return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
        }
    }
    else {
        pNtHeaders32 = (PIMAGE_NT_HEADERS32)(uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew);

        pSectionHeader = (PIMAGE_SECTION_HEADER)((UINT_PTR)(&pNtHeaders32->OptionalHeader) + pNtHeaders32->FileHeader.SizeOfOptionalHeader);

        if (dwRva < pSectionHeader[0].PointerToRawData)
            return dwRva;

        for (wIndex = 0; wIndex < pNtHeaders32->FileHeader.NumberOfSections; wIndex++)
        {
            if (dwRva >= pSectionHeader[wIndex].VirtualAddress && dwRva < (pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].SizeOfRawData))
                return (dwRva - pSectionHeader[wIndex].VirtualAddress + pSectionHeader[wIndex].PointerToRawData);
        }
    }

    return 0;
}

DWORD GetReflectiveLoaderOffset(const VOID* lpReflectiveDllBuffer)
{
    UINT_PTR uiBaseAddress = 0;
    UINT_PTR uiExportDir = 0;
    UINT_PTR uiNameArray = 0;
    UINT_PTR uiAddressArray = 0;
    UINT_PTR uiNameOrdinals = 0;
    DWORD dwCounter = 0;
    BOOL is64 = 0;
    DWORD dwIdx = 0;

    uiBaseAddress = (UINT_PTR)lpReflectiveDllBuffer;

    // get the File Offset of the modules NT Header
    uiExportDir = uiBaseAddress + ((PIMAGE_DOS_HEADER)uiBaseAddress)->e_lfanew;

    // process a PE file based on its architecture
    if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x010B) // PE32
    {
        is64 = FALSE;
        // uiNameArray = the address of the modules export directory entry
        uiNameArray = (UINT_PTR) & ((PIMAGE_NT_HEADERS32)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    }
    else if (((PIMAGE_NT_HEADERS)uiExportDir)->OptionalHeader.Magic == 0x020B) // PE64
    {
        is64 = TRUE;
        // uiNameArray = the address of the modules export directory entry
        uiNameArray = (UINT_PTR) & ((PIMAGE_NT_HEADERS64)uiExportDir)->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    }
    else
    {
        return 0;
    }

    // get the File Offset of the export directory
    uiExportDir = uiBaseAddress + Rva2Offset(((PIMAGE_DATA_DIRECTORY)uiNameArray)->VirtualAddress, uiBaseAddress, is64);

    // get the File Offset for the array of name pointers
    uiNameArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNames, uiBaseAddress, is64);

    // get the File Offset for the array of addresses
    uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress, is64);

    // get the File Offset for the array of name ordinals
    uiNameOrdinals = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfNameOrdinals, uiBaseAddress, is64);

    // get a counter for the number of exported functions...
    dwCounter = ((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->NumberOfNames;

    // loop through all the exported functions to find the ReflectiveLoader
    while (dwCounter--)
    {
        char* cpExportedFunctionName = (char*)(uiBaseAddress + Rva2Offset(DEREF_32(uiNameArray), uiBaseAddress, is64));

        if(_strnicmp(cpExportedFunctionName, ReflectiveExportName, strlen(ReflectiveExportName)) == 0)
        {
            // get the File Offset for the array of addresses
            uiAddressArray = uiBaseAddress + Rva2Offset(((PIMAGE_EXPORT_DIRECTORY)uiExportDir)->AddressOfFunctions, uiBaseAddress, is64);

            // use the functions name ordinal as an index into the array of name pointers
            uiAddressArray += (DEREF_16(uiNameOrdinals) * sizeof(DWORD));

            // return the RVA to the ReflectiveLoader() functions code...
            return Rva2Offset(DEREF_32(uiAddressArray), uiBaseAddress, is64);
        }

        // get the next exported function name
        uiNameArray += sizeof(DWORD);

        // get the next exported function name ordinal
        uiNameOrdinals += sizeof(WORD);
    }

    return 0;
}

BOOL ReflectiveInjector::_MapFileAndParamToRemote(
    ProcessOpWrapper& ProcessHelper,
    LPCWSTR lpModuleName,
    ADDR_T& ReflectiveLoaderAddr,
    ADDR_T& ParamAddr)
{
    if (!ProcessHelper || !lpModuleName)
        return FALSE;

    TOKEN_PRIVILEGES tp = { 0 };
    HANDLE hToken = NULL;
    BOOL bRet = FALSE;
    PVOID buffer = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    do
    {
        if (::OpenProcessToken((HANDLE)-1, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        {
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

            tp.Privileges[0].Luid.LowPart = 20;
            tp.Privileges[0].Luid.HighPart = 0;

            ::AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, NULL);
            ::CloseHandle(hToken);
        }

        hFile = ::CreateFile(lpModuleName, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        if (INVALID_HANDLE_VALUE == hFile)
            break;

        DWORD FileSize = ::GetFileSize(hFile, NULL);
        if (INVALID_FILE_SIZE == FileSize)
            break;

        buffer = ::VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buffer)
        {
            break;
        }

        DWORD read = 0;
        if (!::ReadFile(hFile, buffer, FileSize, &read, NULL))
        {
            break;
        }

        PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)buffer;

        if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
        {
            break;
        }

        PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((LPBYTE)buffer + pIDH->e_lfanew);

        if (pINH->Signature != IMAGE_NT_SIGNATURE)
        {
            break;
        }

        if (!(pINH->FileHeader.Characteristics & IMAGE_FILE_DLL))
            break;

        if (ProcessHelper.GetTargetArch() == PROCESS_ARCH_X86)
        {
            if(pINH->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
                break;
        }
        else if (ProcessHelper.GetTargetArch() == PROCESS_ARCH_X64)
        {
            if(pINH->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64)
                break;
        }

        ADDR_T dllbuffer = NULL;
        ProcessHelper->VirtualAllocExT(dllbuffer, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!dllbuffer)
        {
            break;
        }

        DWORD dwReflectiveOffset = GetReflectiveLoaderOffset(buffer);
        if(dwReflectiveOffset == 0)
            break;

        ReflectiveLoaderAddr = dllbuffer + dwReflectiveOffset;

        //复制dll到目标进程
        if (!ProcessHelper->WriteProcessMemoryT(dllbuffer, buffer, FileSize, NULL))
        {
            break;
        }

        //复制参数到目标进程
        ADDR_T mem = NULL;
        ProcessHelper->VirtualAllocExT(mem, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!mem)
        {
            break;
        }

        ParamAddr = mem;

        ADDR_T hNtdll = ProcessHelper->GetModuleHandleT(L"ntdll.dll");
        if (hNtdll == NULL)
            break;

        if (ProcessHelper.GetTargetArch() == PROCESS_ARCH_X64)
        {
            Reflective_Param<ADDR_T> Param = { 0 };
            Param.pfnGetProcedureAddress = ProcessHelper->GetProcAddressT(hNtdll, "LdrGetProcedureAddress");
            Param.pfnLdrLoadDll = ProcessHelper->GetProcAddressT(hNtdll, "LdrLoadDll");
            Param.pfnRtlInitAnsiString = ProcessHelper->GetProcAddressT(hNtdll, "RtlInitAnsiString");
            Param.pfnRtlAnsiStringToUnicodeString = ProcessHelper->GetProcAddressT(hNtdll, "RtlAnsiStringToUnicodeString");
            Param.pfnRtlFreeUnicodeString = ProcessHelper->GetProcAddressT(hNtdll, "RtlFreeUnicodeString");
            Param.pfnNtAllocateVirtualMemory = ProcessHelper->GetProcAddressT(hNtdll, "NtAllocateVirtualMemory");
            Param.DllBuffer = dllbuffer;
            Param.DllLength = FileSize;

            if (Param.pfnGetProcedureAddress == NULL
                || Param.pfnLdrLoadDll == NULL
                || Param.pfnRtlInitAnsiString == NULL
                || Param.pfnRtlAnsiStringToUnicodeString == NULL
                || Param.pfnRtlFreeUnicodeString == NULL
                || Param.pfnNtAllocateVirtualMemory == NULL)
            {
                break;
            }

            if (!ProcessHelper->WriteProcessMemoryT(mem, &Param, sizeof(Param), NULL))
                break;
        }
        else
        {
            Reflective_Param<DWORD> Param = { 0 };
            Param.pfnGetProcedureAddress = (DWORD)ProcessHelper->GetProcAddressT(hNtdll, "LdrGetProcedureAddress");
            Param.pfnLdrLoadDll = (DWORD)ProcessHelper->GetProcAddressT(hNtdll, "LdrLoadDll");
            Param.pfnRtlInitAnsiString = (DWORD)ProcessHelper->GetProcAddressT(hNtdll, "RtlInitAnsiString");
            Param.pfnRtlAnsiStringToUnicodeString = (DWORD)ProcessHelper->GetProcAddressT(hNtdll, "RtlAnsiStringToUnicodeString");
            Param.pfnRtlFreeUnicodeString = (DWORD)ProcessHelper->GetProcAddressT(hNtdll, "RtlFreeUnicodeString");
            Param.pfnNtAllocateVirtualMemory = (DWORD)ProcessHelper->GetProcAddressT(hNtdll, "NtAllocateVirtualMemory");
            Param.DllBuffer = (DWORD)dllbuffer;
            Param.DllLength = FileSize;

            if (Param.pfnGetProcedureAddress == NULL
                || Param.pfnLdrLoadDll == NULL
                || Param.pfnRtlInitAnsiString == NULL
                || Param.pfnRtlAnsiStringToUnicodeString == NULL
                || Param.pfnRtlFreeUnicodeString == NULL
                || Param.pfnNtAllocateVirtualMemory == NULL)
            {
                break;
            }

            if(!ProcessHelper->WriteProcessMemoryT(mem, &Param, sizeof(Param), NULL))
                break;
        }

        bRet = TRUE;

    } while (0);

    if (hFile != INVALID_HANDLE_VALUE)
    {
        ::CloseHandle(hFile);
    }

    if (buffer)
    {
        ::VirtualFree(buffer, 0, MEM_RELEASE);
    }

    return bRet;
}

