#include <Windows.h>
#include <winternl.h>
#include <atlstr.h>
#include <tlhelp32.h>
#include <iostream>
#include <stdio.h>
#include <conio.h>

#include "resource.h"

#define ManualMapping_x86 0 // x86 프로세스 타겟 define
#define ManualMapping_x64 1 // x64 프로세스 타겟 define

typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI* PDLL_MAIN)(HMODULE, DWORD, PVOID);

DWORD ResourceSize = 0;

// ManualMapping 시에 사용될 데이터
typedef struct _MANUALMMAPSTRUCT
{
    PVOID ImageBase;
    PIMAGE_NT_HEADERS pNtHeaders;
    PIMAGE_BASE_RELOCATION pBaseRelocation;
    PIMAGE_IMPORT_DESCRIPTOR pImportDirectory;
    pLoadLibraryA pfnLoadLibraryA;
    pGetProcAddress pfnGetProcAddress;
}MANUALMAPSTRUCT, * PMANULAMP_STRUCT;

// 실제 매뉴얼 맵 방식으로 DLL을 로드하는 코드
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

    // IMAGE_BASE_RELOCATION 섹션이 존재할 경우
    if (ManualMapStruct->pBaseRelocation->VirtualAddress && ManualMapStruct->pBaseRelocation->SizeOfBlock)
    {
        // 재배치를 위한 delta값을 획득
        // 새로운 ImageBase값과 기존 ImageBase값의 차 == delta
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
                // Relocation Type / Offset 값 획득
                WORD Type = (*RelocEntry & 0xf000) >> 12;
                WORD Offset = *RelocEntry & 0xfff;

                   // 비트에 따른 Type 체크
                if (Type == IMAGE_REL_BASED_HIGHLOW) // 32비트의 경우 Type이 해당 값
                    *(DWORD*)(VirtualAddress + Offset) += (DWORD)Delta;

                else if (Type == IMAGE_REL_BASED_DIR64) // 64비트의 경우 Type이 해당 값
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
            // Data가 0x800000000보다 클 경우 Ordinal 값으로 사용됨.
            // Ordinal 체크
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

            // Ordinal이 아닐 경우, RVA 값을 가져옴
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

        // Entry 호출
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
    // 리소스를 가져옴
    // 인젝션할 DLL이 담긴 리소스를 가져오기위한 함수
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
    // 리소스로 가져올 DLL, TargetProcess에 로드될 DLL, ManualMapping에 사용될 인자
    PVOID InjectedDLL_ImageBase, LoadedDLL, ManualMap_Mem;
    PIMAGE_DOS_HEADER pDosHeader = NULL;
    PIMAGE_NT_HEADERS pNtHeaders = NULL;
    PIMAGE_SECTION_HEADER pSectionHeader = NULL;

    HANDLE hProcess, hThread;
    MANUALMAPSTRUCT ManualInject;
    DWORD ExitCode;


    // 인젝션할 DLL 리소스를 획득
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

    // 인젝션할 타겟 프로세스 open
    printf("\nOpening Target Process\n");
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProcess)
    {
        printf("\nError : Failed to Open Target Process (ErrorCode : %d)\n", GetLastError());
        CloseHandle(hProcess);
        return -1;
    }

    // 타겟 프로세스에 매뉴얼맵 DLL을 위한 메모리 할당
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

    // 매뉴얼맵할 DLL의 PE 헤더를 할당된 메모리 공간에 작성
    printf("\nCopying Headers to Target Process\n");
    if (!WriteProcessMemory(hProcess, LoadedDLL, InjectedDLL_ImageBase, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL))
    {
        printf("\nError : Failed to WriteMemory into Target Process (ErrorCode : %d)\n", GetLastError());
        VirtualFreeEx(hProcess, LoadedDLL, 0, MEM_RESERVE);
        CloseHandle(hProcess);
        return -1;
    }

    // 매뉴얼맵할 DLL의 섹션 헤더를 할당된 메모리 공간에 작성
    pSectionHeader = (PIMAGE_SECTION_HEADER)(pNtHeaders + 1);
    printf("\nCopying SectionHeaders to Target Process\n");
    for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
    {
        WriteProcessMemory(hProcess, (PVOID)((LPBYTE)LoadedDLL + pSectionHeader[i].VirtualAddress), (PVOID)((LPBYTE)InjectedDLL_ImageBase + pSectionHeader[i].PointerToRawData), pSectionHeader[i].SizeOfRawData, NULL);
    }

    // 매뉴얼맵을 위한 로더 코드를 작성할 메모리 공간 할당
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

    // Base Relocation이 존재할 경우
    if ((PIMAGE_BASE_RELOCATION)((LPBYTE)LoadedDLL + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress) != 0)
    {
        ManualInject.pBaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)LoadedDLL + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    }
    ManualInject.pImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)LoadedDLL + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    ManualInject.pfnLoadLibraryA = LoadLibraryA;
    ManualInject.pfnGetProcAddress = GetProcAddress;

    // ManualMap_Mem == ManualMapping을 위해 사용되는 구조체와 로더의 코드가 저장되는 메모리
    WriteProcessMemory(hProcess, ManualMap_Mem, &ManualInject, sizeof(MANUALMAPSTRUCT), NULL);

    DWORD pJmpCode = NULL;
    DWORD LoaderCodeSize = 0;

    // Loader Code 함수 크기
    LoaderCodeSize = (DWORD)Routine_ManualMap_Stub - (DWORD)Routine_ManualMap;

    // Manual Mapping 코드를 ManualInjection 구조체 다음 메모리 위치에 저장
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

// PID 획득
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
    // 프로세스 PID를 얻어오는 루틴
    printf("Wait For Process....\n");

    // TargetProcess 지정
#if ManualMapping_x86
    unsigned long pid = WaitForProcess(L"PEview.exe");
#elif ManualMapping_x64
    unsigned long pid = WaitForProcess(L"ProcessHacker.exe");
#endif
    InjectDLL(pid);
}