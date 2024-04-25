#pragma once
#include "ReflectiveDef.h"
#include <windows.h>
#include <winternl.h>

#define DLLEXPORT __declspec( dllexport )

typedef NTSTATUS(WINAPI* LdrGetProcedureAddressT)(PVOID DllHandle, PANSI_STRING ProcedureName, ULONG ProcedureNumber, FARPROC* ProcedureAddress);
typedef VOID(WINAPI* RtlFreeUnicodeStringT)(PUNICODE_STRING UnicodeString);
typedef  VOID(WINAPI* RtlInitAnsiStringT)(PANSI_STRING DestinationString, PCSZ         SourceString);
typedef NTSTATUS(WINAPI* RtlAnsiStringToUnicodeStringT)(PUNICODE_STRING DestinationString, PCANSI_STRING SourceString, BOOLEAN AllocateDestinationString);
typedef NTSTATUS(WINAPI* LdrLoadDllT)(PWCHAR, PULONG, PUNICODE_STRING, PHANDLE);
typedef NTSTATUS(WINAPI* NtAllocateVirtualMemoryT)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

typedef BOOL(WINAPI* PDLL_MAIN)(HMODULE, ULONG_PTR, PVOID);

DLLEXPORT DWORD WINAPI rl(LPVOID lpParameter)
{
    Reflective_Param<ULONG_PTR>* pReflectiveParam = static_cast<Reflective_Param<ULONG_PTR>*>(lpParameter);
    if (pReflectiveParam == NULL)
        return -1;

    RtlInitAnsiStringT pfnInitAnsiString = (RtlInitAnsiStringT)pReflectiveParam->pfnRtlInitAnsiString;
    RtlAnsiStringToUnicodeStringT pfnRtlAnsiStringToUnicodeString = (RtlAnsiStringToUnicodeStringT)pReflectiveParam->pfnRtlAnsiStringToUnicodeString;
    LdrLoadDllT pfnLdrLoadDll = (LdrLoadDllT)pReflectiveParam->pfnLdrLoadDll;
    LdrGetProcedureAddressT pfnLdrGetProcedureAddress = (LdrGetProcedureAddressT)pReflectiveParam->pfnGetProcedureAddress;
    RtlFreeUnicodeStringT pfnRtlFreeUnicodeString = (RtlFreeUnicodeStringT)pReflectiveParam->pfnRtlFreeUnicodeString;
    NtAllocateVirtualMemoryT pfnNtAllocateVirtualMemory = (NtAllocateVirtualMemoryT)pReflectiveParam->pfnNtAllocateVirtualMemory;

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pReflectiveParam->DllBuffer;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)(pReflectiveParam->DllBuffer + pDosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((ULONG_PTR)pNtHeader + sizeof(IMAGE_NT_HEADERS));

    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
    {
        if ((ULONG_PTR)(pSectionHeader[i].PointerToRawData + pSectionHeader[i].SizeOfRawData) > pReflectiveParam->DllLength)
            return -1;
    }

    int nAlign = pNtHeader->OptionalHeader.SectionAlignment;
    int ImageSize = (pNtHeader->OptionalHeader.SizeOfHeaders + nAlign + 1) / nAlign * nAlign;
    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
    {
        int CodeSize = pSectionHeader[i].Misc.VirtualSize;
        int LoadSize = pSectionHeader[i].SizeOfRawData;
        int MaxSize = (LoadSize > CodeSize) ? (LoadSize) : (CodeSize);

        int SectionSize = (pSectionHeader[i].VirtualAddress + MaxSize + nAlign - 1) / nAlign * nAlign;
        if (ImageSize < SectionSize)
            ImageSize = SectionSize;
    }

    if (ImageSize == 0)
        return -1;

    SIZE_T uSize = ImageSize;
    void* pImage = NULL;
    pfnNtAllocateVirtualMemory((HANDLE)-1, &pImage, 0, &uSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (pImage == NULL)
        return -1;

    int HeaderSize = pNtHeader->OptionalHeader.SizeOfHeaders;
    int SectionSize = pNtHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
    int MoveSize = HeaderSize + SectionSize;
    for (int i = 0; i < MoveSize; i++)
    {
        *((PCHAR)pImage + i) = *((PCHAR)pReflectiveParam->DllBuffer + i);
    }

    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i)
    {
        if (pSectionHeader[i].VirtualAddress == 0 || pSectionHeader[i].SizeOfRawData == 0)continue;
        void* pSectionAddress = (void*)((ULONG_PTR)pImage + pSectionHeader[i].VirtualAddress);
        for (size_t j = 0; j < pSectionHeader[i].SizeOfRawData; j++)
        {
            *((PCHAR)pSectionAddress + j) = *((PCHAR)pReflectiveParam->DllBuffer + pSectionHeader[i].PointerToRawData + j);
        }
    }

    ANSI_STRING ansiStr;
    UNICODE_STRING UnicodeString;
    PIMAGE_BASE_RELOCATION pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pImage 
        + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    DWORD64 delta = (DWORD64)((LPBYTE)pImage - pNtHeader->OptionalHeader.ImageBase);

    while (pIBR->VirtualAddress)
    {
        if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            ULONG_PTR count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PWORD list = (PWORD)(pIBR + 1);

            for (size_t i = 0; i < count; i++)
            {
                if ((list[i] & 0xF000) == 0x3000 || (list[i] & 0xF000) == 0xA000)
                {
                    ULONG_PTR* ptr = (ULONG_PTR*)((LPBYTE)pImage + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
                    *ptr += delta;
                }
            }
        }

        pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
    }


    PIMAGE_IMPORT_DESCRIPTOR pIID = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)pImage 
        + pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (pIID->Characteristics)
    {
        PIMAGE_THUNK_DATA OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)pImage + pIID->OriginalFirstThunk);
        PIMAGE_THUNK_DATA FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)pImage + pIID->FirstThunk);

        char* pName = (char*)pImage + pIID->Name;
        pfnInitAnsiString(&ansiStr, pName);
        pfnRtlAnsiStringToUnicodeString(&UnicodeString, &ansiStr, true);
        HMODULE hModule = NULL;
        pfnLdrLoadDll(NULL, NULL, &UnicodeString, (PHANDLE)&hModule);
        pfnRtlFreeUnicodeString(&UnicodeString);

        if (!hModule)
        {
            return FALSE;
        }

        while (OrigFirstThunk->u1.AddressOfData)
        {
            if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                FARPROC lpFunction = NULL;
                pfnLdrGetProcedureAddress(hModule, NULL, IMAGE_ORDINAL(OrigFirstThunk->u1.Ordinal), &lpFunction);
                if (!lpFunction)
                {
                    return FALSE;
                }

                FirstThunk->u1.Function = (ULONG_PTR)lpFunction;
            }
            else
            {
                FARPROC lpFunction = NULL;
                PIMAGE_IMPORT_BY_NAME pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)pImage + OrigFirstThunk->u1.AddressOfData);
                if (pIBN->Name)
                {
                    pfnInitAnsiString(&ansiStr, (char*)pIBN->Name);
                    pfnLdrGetProcedureAddress(hModule, &ansiStr, 0, &lpFunction);
                }

                if (!lpFunction)
                {
                    return FALSE;
                }
                FirstThunk->u1.Function = (ULONG_PTR)lpFunction;
            }

            OrigFirstThunk++;
            FirstThunk++;
        }

        pIID++;
    }

    PDLL_MAIN EntryPoint = (PDLL_MAIN)((LPBYTE)pImage + pNtHeader->OptionalHeader.AddressOfEntryPoint);
    if (EntryPoint)
    {
        return EntryPoint((HMODULE)pImage, DLL_PROCESS_ATTACH, NULL); // Call the entry point
    }

    return -1;
}