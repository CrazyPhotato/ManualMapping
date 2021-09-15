#include <Windows.h>
#include <winternl.h>
#include <atlstr.h>
#include <tlhelp32.h>
#include <iostream>
#include <stdio.h>
#include <conio.h>

#include "resource.h"

#define ManualMapping_x86 0 // x86 ���μ��� Ÿ�� define
#define ManualMapping_x64 1 // x64 ���μ��� Ÿ�� define

typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI* PDLL_MAIN)(HMODULE, DWORD, PVOID);

DWORD ResourceSize = 0;

// ManualMapping �ÿ� ���� ������
typedef struct _MANUALMMAPSTRUCT
{
    PVOID ImageBase;
    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_BASE_RELOCATION pBaseRelocation;
    PIMAGE_IMPORT_DESCRIPTOR pImportDirectory;
    pLoadLibraryA pfnLoadLibraryA;
    pGetProcAddress pfnGetProcAddress;
}MANUALMAPSTRUCT, * PMANULAMP_STRUCT;

// ���� �Ŵ��� �� ������� DLL�� �ε��ϴ� �ڵ�
DWORD WINAPI Routine_ManualMap(PVOID ManualMapArg)
{
    PMANULAMP_STRUCT ManualMapStruct;

    HMODULE hModule;
    DWORD index, count;
    UINT_PTR Function, delta;

    PDWORD ptr;
    PWORD list;

    PIMAGE_BASE_RELOCATION pBaseReloc;
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
    PIMAGE_IMPORT_BY_NAME pImportByName;
    PIMAGE_THUNK_DATA FirstThunk, OrigFirstThunk;

    PDLL_MAIN EntryPoint;

    ManualMapStruct = (PMANULAMP_STRUCT)ManualMapArg;

    // IMAGE_BASE_RELOCATION ������ ������ ���
    if (ManualMapStruct->pBaseRelocation->VirtualAddress && ManualMapStruct->pBaseRelocation->SizeOfBlock)
    {
        // ���ġ�� ���� delta���� ȹ��
        // ���ο� ImageBase���� ���� ImageBase���� �� == delta
        DWORD_PTR Delta = (DWORD_PTR)((LPBYTE)ManualMapStruct->ImageBase - ManualMapStruct->pNtHeaders->OptionalHeader.ImageBase);

        pBaseReloc = ManualMapStruct->pBaseRelocation;

        while (pBaseReloc->VirtualAddress)
        {
            // Relocation 
            LPBYTE VirtualAddress = (LPBYTE)ManualMapStruct->ImageBase + pBaseReloc->VirtualAddress;
            LPWORD RelocEntry = (LPWORD)((LPBYTE)pBaseReloc + sizeof(IMAGE_BASE_RELOCATION));
            DWORD Count = (pBaseReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

            while (Count--)
            {
                // Relocation Type / Offset �� ȹ��
                WORD Type = (*RelocEntry & 0xf000) >> 12;
                WORD Offset = *RelocEntry & 0xfff;

                   // ��Ʈ�� ���� Type üũ
                if (Type == IMAGE_REL_BASED_HIGHLOW) // 32��Ʈ�� ��� Type�� �ش� ��
                    *(DWORD*)(VirtualAddress + Offset) += (DWORD)Delta;

                else if (Type == IMAGE_REL_BASED_DIR64) // 64��Ʈ�� ��� Type�� �ش� ��
                    *(ULONGLONG*)(VirtualAddress + Offset) += (ULONGLONG)Delta;

                RelocEntry++;
            }
            pBaseReloc = (PIMAGE_BASE_RELOCATION)((LPBYTE)pBaseReloc + pBaseReloc->SizeOfBlock);
        }
    }

    pImportDescriptor = ManualMapStruct->pImportDirectory;

    // Resolve IAT
    // OriginalFirstThunk == "Import Name Table RVA"
    // FirstThunk == "Import Address Table RVA"
    while (pImportDescriptor->Characteristics)
    {
        OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualMapStruct->ImageBase + pImportDescriptor->OriginalFirstThunk);
        FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualMapStruct->ImageBase + pImportDescriptor->FirstThunk);

        // IMPORT Directory Table
        hModule = ManualMapStruct->pfnLoadLibraryA((LPCSTR)ManualMapStruct->ImageBase + pImportDescriptor->Name);

        if (!hModule)
        {
            return FALSE;
        }

        while (OrigFirstThunk->u1.AddressOfData)
        {
            // Data�� 0x800000000���� Ŭ ��� Ordinal ������ ����.
            // Ordinal üũ
            if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                // Import by ordinal

                Function = (UINT_PTR)ManualMapStruct->pfnGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

                if (!Function)
                {
                    return FALSE;
                }

                FirstThunk->u1.Function = Function;
            }

            // Ordinal�� �ƴ� ���, RVA ���� ������
            else
            {

                pImportByName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualMapStruct->ImageBase + OrigFirstThunk->u1.AddressOfData);
                Function = (UINT_PTR)ManualMapStruct->pfnGetProcAddress(hModule, (LPCSTR)pImportByName->Name);

                if (!Function)
                {
                    return FALSE;
                }

                FirstThunk->u1.Function = Function;
            }

            OrigFirstThunk++;
            FirstThunk++;
        }

        pImportDescriptor++;
    }

    if (ManualMapStruct->pNtHeaders->OptionalHeader.AddressOfEntryPoint)
    {
        EntryPoint = (PDLL_MAIN)((LPBYTE)ManualMapStruct->ImageBase + ManualMapStruct->pNtHeaders->OptionalHeader.AddressOfEntryPoint);

        // Entry ȣ��
        return EntryPoint((HMODULE)ManualMapStruct->ImageBase, DLL_PROCESS_ATTACH, NULL);
    }

    return TRUE;
}

DWORD WINAPI Routine_ManualMap_Stub()
{
    return 0;
}
PVOID WINAPI GetResources()
{
    // ���ҽ��� ������
    // �������� DLL�� ��� ���ҽ��� ������������ �Լ�
    HRSRC hResource;
    HGLOBAL hData;
    PVOID pResource;
    DWORD FileSize, NumWritten;
    HANDLE hFile;
#if ManualMapping_x86
    if (!(hResource = FindResource(NULL, MAKEINTRESOURCE(IDR_RT_MANIFEST1), MAKEINTRESOURCE(24))))
    {
        printf("\nError : Not Found Resource...\n");
        return FALSE;
    }
#elif ManualMapping_x64
    if (!(hResource = FindResource(NULL, MAKEINTRESOURCE(IDR_RT_MANIFEST2), MAKEINTRESOURCE(24))))
    {
        printf("\nError : Not Found Resource...\n");
        return FALSE;
    }
#endif

    // printf("hResource : 0x%08x\n", hResource);
    if (!(ResourceSize = SizeofResource(NULL, hResource)))
    {
        printf("\nError : Failed to Get ResourceSize\n");
        return FALSE;
    }
    if (!(hData = LoadResource(NULL, hResource)))
    {
        printf("\nError : Failed LoadResource\n");
        return FALSE;
    }
    // printf("hData : 0x%08x\n", hData);
    if (!(pResource = LockResource(hData)))
    {
        printf("\nError : Failed LockResource\n");
        return FALSE;
    }
    return pResource;
}
int InjectDLL(DWORD PID)
{
    // ���ҽ��� ������ DLL, TargetProcess�� �ε�� DLL, ManualMapping�� ���� ����
    PVOID InjectedDLL_ImageBase, LoadedDLL, ManualMap_Mem;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;

    HANDLE hProcess, hThread;
    MANUALMAPSTRUCT ManualInject;
    DWORD ExitCode;


    // �������� DLL ���ҽ��� ȹ��
    InjectedDLL_ImageBase = GetResources();
    if (!InjectedDLL_ImageBase)
    {
        printf("\nError : Failed to Get Resource\n");
        return -1;
    }
    pDosHeader = (PIMAGE_DOS_HEADER)InjectedDLL_ImageBase;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("\nError : Invalid Executable Image\n");
        return -1;
    }

    pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)InjectedDLL_ImageBase + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("\nError : Invalid PE Header\n");
        return -1;
    }

    if (!(pNtHeaders->FileHeader.Characteristics & IMAGE_FILE_DLL))
    {
        printf("\nError : The Image is not DLL\n");
        return -1;

    }

    // �������� Ÿ�� ���μ��� open
    printf("\nOpening Target Process\n");
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProcess)
    {
        printf("\nError : Failed to Open Target Process (ErrorCode : %d)\n", GetLastError());
        CloseHandle(hProcess);
        return -1;
    }

    // Ÿ�� ���μ����� �Ŵ���� DLL�� ���� �޸� �Ҵ�
    printf("\nAllocating Memory for the DLL\n");
    LoadedDLL = VirtualAllocEx(hProcess, NULL, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!LoadedDLL)
    {
        printf("\nError : Failed to Allocate Memory for the DLL (ErrorCode : %d)\n", GetLastError());
        VirtualFreeEx(hProcess, LoadedDLL, 0, MEM_RESERVE);
        CloseHandle(hProcess);
        return -1;
    }
    printf("\nInjected Module Address : 0x%p\n", LoadedDLL);

    // �Ŵ������ DLL�� PE ����� �Ҵ�� �޸� ������ �ۼ�
    printf("\nCopying Headers to Target Process\n");
    if (!WriteProcessMemory(hProcess, LoadedDLL, InjectedDLL_ImageBase, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL))
    {
        printf("\nError : Failed to WriteMemory into Target Process (ErrorCode : %d)\n", GetLastError());
        VirtualFreeEx(hProcess, LoadedDLL, 0, MEM_RESERVE);
        CloseHandle(hProcess);
        return -1;
    }

    // �Ŵ������ DLL�� ���� ����� �Ҵ�� �޸� ������ �ۼ�
    pSectionHeader = (PIMAGE_SECTION_HEADER)(pNtHeaders + 1);
    printf("\nCopying SectionHeaders to Target Process\n");
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
    {
        WriteProcessMemory(hProcess, (PVOID)((LPBYTE)LoadedDLL + pSectionHeader[i].VirtualAddress), (PVOID)((LPBYTE)InjectedDLL_ImageBase + pSectionHeader[i].PointerToRawData), pSectionHeader[i].SizeOfRawData, NULL);
    }

    // �Ŵ������ ���� �δ� �ڵ带 �ۼ��� �޸� ���� �Ҵ�
    printf("\nCopying LoaderCode to Target Process\n");
    ManualMap_Mem = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!ManualMap_Mem)
    {
        printf("\nError : Failed to Allocate Memory for the LoaderCode (ErrorCode : %d)\n", GetLastError());
        VirtualFreeEx(hProcess, LoadedDLL, 0, MEM_RESERVE);
        CloseHandle(hProcess);
        return -1;
    }
    printf("\nManualMapp Structure Address : 0x%p\n", ManualMap_Mem);

    memset(&ManualInject, 0, sizeof(MANUALMAPSTRUCT));

    ManualInject.ImageBase = LoadedDLL;
    ManualInject.pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)LoadedDLL + pDosHeader->e_lfanew);

    // Base Relocation�� ������ ���
    if ((PIMAGE_BASE_RELOCATION)((LPBYTE)LoadedDLL + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) != 0)
    {
        ManualInject.pBaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)LoadedDLL + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    }
    ManualInject.pImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)LoadedDLL + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    ManualInject.pfnLoadLibraryA = LoadLibraryA;
    ManualInject.pfnGetProcAddress = GetProcAddress;

    // ManualMap_Mem == ManualMapping�� ���� ���Ǵ� ����ü�� �δ��� �ڵ尡 ����Ǵ� �޸�
    WriteProcessMemory(hProcess, ManualMap_Mem, &ManualInject, sizeof(MANUALMAPSTRUCT), NULL);

    DWORD pJmpCode = NULL;
    DWORD LoaderCodeSize = 0;

    // Loader Code �Լ� ũ��
    LoaderCodeSize = (DWORD)Routine_ManualMap_Stub - (DWORD)Routine_ManualMap;

    // Manual Mapping �ڵ带 ManualInjection ����ü ���� �޸� ��ġ�� ����
    if (*((PBYTE)*Routine_ManualMap) == 0xE9)
    {
        pJmpCode = (DWORD)(PDWORD)Routine_ManualMap + (DWORD)(*(PDWORD)((PBYTE)Routine_ManualMap + 1)) + 0x5;
        WriteProcessMemory(hProcess, (PVOID)((PMANULAMP_STRUCT)ManualMap_Mem + 1), (PVOID)pJmpCode, LoaderCodeSize, NULL);
    }
    else
        WriteProcessMemory(hProcess, (PVOID)((PMANULAMP_STRUCT)ManualMap_Mem + 1), Routine_ManualMap, LoaderCodeSize, NULL);

    _getch();

    printf("\nExecuting Loader Code.\n");
    hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((PMANULAMP_STRUCT)ManualMap_Mem + 1), ManualMap_Mem, 0, NULL);

    if (!hThread)
    {
        printf("\nError : Unable to Execute Loader Code (ErrorCode : %d)\n", GetLastError());
        VirtualFreeEx(hProcess, ManualMap_Mem, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, LoadedDLL, 0, MEM_RELEASE);

        CloseHandle(hProcess);
        return -1;
    }

    WaitForSingleObject(hThread, INFINITE);
    GetExitCodeThread(hThread, &ExitCode);

    if (!ExitCode)
    {
        VirtualFreeEx(hProcess, ManualMap_Mem, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, LoadedDLL, 0, MEM_RELEASE);

        CloseHandle(hThread);
        CloseHandle(hProcess);
        return -1;
    }

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, ManualMap_Mem, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return 1;
}

// PID ȹ��
BOOL WINAPI ProcessNameToId(LPCWSTR ProcessName, PULONG pid)
{
    PROCESSENTRY32 ProcessEntry32 = { 0, };
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (!hSnap)
    {
        printf("\nError: CreateToolhelp32Snapshot Invalide Handle (%d)\n", GetLastError());
        CloseHandle(hSnap);
        return FALSE;
    }

    ProcessEntry32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnap, &ProcessEntry32))
    {
        printf("\nError: Process32First Error (%d)\n", GetLastError());
        CloseHandle(hSnap);
        return FALSE;
    }

    do
    {
        if (wcsstr(ProcessEntry32.szExeFile, ProcessName))
        {
            *pid = ProcessEntry32.th32ProcessID;

            return TRUE;
        }
    } while (Process32Next(hSnap, &ProcessEntry32));

    return FALSE;
}
unsigned long WaitForProcess(LPCWSTR ProcessName)
{
    unsigned long PID = 0;
    while (INFINITE)
    {
        if (ProcessNameToId(ProcessName, &PID))
        {
            break;
        }
    }
    return PID;
}

int main()
{
    // ���μ��� PID�� ������ ��ƾ
    printf("Wait For Process....\n");

    // TargetProcess ����
#if ManualMapping_x86
    unsigned long pid = WaitForProcess(L"PEview.exe");
#elif ManualMapping_x64
    unsigned long pid = WaitForProcess(L"ProcessHacker.exe");
#endif
    InjectDLL(pid);
}