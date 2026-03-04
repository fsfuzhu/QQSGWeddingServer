#include "HideModule.h"

#ifndef _DEBUG

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _PEB_LDR_DATA
{
    ULONG       Length;
    BOOLEAN     Initialized;
    PVOID       SsHandle;
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY  InLoadOrderModuleList;
    LIST_ENTRY  InMemoryOrderModuleList;
    LIST_ENTRY  InInitializationOrderModuleList;
    void* BaseAddress;
    void* EntryPoint;
    ULONG       SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG       Flags;
    SHORT       LoadCount;
    SHORT       TlsIndex;
    HANDLE      SectionHandle;
    ULONG       CheckSum;
    ULONG       TimeDateStamp;
}LDR_MODULE, * PLDR_MODULE;

int GetModuleSize(HMODULE hModule)
{
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((DWORD)hModule + pDosHeader->e_lfanew);
    return pNtHeader->OptionalHeader.SizeOfImage;
}

LPVOID AllocMemory(DWORD a1, SIZE_T a2)
{
    return VirtualAlloc((LPVOID)a1, a2, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

BOOL __stdcall UninstallModule(HMODULE a1, SIZE_T dwSize)
{
    auto pImage = AllocMemory(0, dwSize);
    auto pCode = AllocMemory(0, 100);
    memmove(pImage, a1, dwSize);
    auto pZwUnmapViewOfSection = GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwUnmapViewOfSection");
    auto pZwAllocateVirtualMemory = GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwAllocateVirtualMemory");
    auto pRtlMoveMemory = GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlMoveMemory");
    BYTE bCode[] = { 85, 139, 236, 255, 117, 20, 106, 255, 255, 85, 8, 133, 192, 117, 49, 106, 64, 104, 0, 48, 0, 0, 141, 69, 24, 80, 106, 0, 141, 69, 20, 80, 106, 255, 255, 85, 12, 133, 192, 117, 23, 255, 117, 24, 255, 117, 28, 255, 117, 20, 255, 85, 16, 184, 1, 0, 0, 0, 137, 236, 93, 194, 24, 0, 49, 192, 235, 246 };
    memmove(pCode, bCode, sizeof(bCode));
    auto bResult = ((BOOL(__stdcall*)(LPVOID, LPVOID, LPVOID, HMODULE, SIZE_T, LPVOID))pCode)(pZwUnmapViewOfSection, pZwAllocateVirtualMemory, pRtlMoveMemory, a1, dwSize, pImage);
    VirtualFree(pImage, 0, MEM_RELEASE);
    VirtualFree(pCode, 0, MEM_RELEASE);
    return bResult;

}

void HideModule2(HMODULE hMod)
{
    PLIST_ENTRY Head, Cur;
    PPEB_LDR_DATA ldr;
    PLDR_MODULE ldm;

    __asm {
        mov eax, fs: [0x30]
        mov ecx, [eax + 0x0c]
        mov ldr, ecx
    }
    Head = &(ldr->InLoadOrderModuleList);
    Cur = Head->Flink;
    do
    {
        ldm = CONTAINING_RECORD(Cur, LDR_MODULE, InLoadOrderModuleList);

        if (hMod == ldm->BaseAddress)
        {
            ldm->InLoadOrderModuleList.Blink->Flink = ldm->InLoadOrderModuleList.Flink;
            ldm->InLoadOrderModuleList.Flink->Blink = ldm->InLoadOrderModuleList.Blink;
            ldm->InInitializationOrderModuleList.Blink->Flink = ldm->InInitializationOrderModuleList.Flink;
            ldm->InInitializationOrderModuleList.Flink->Blink = ldm->InInitializationOrderModuleList.Blink;
            ldm->InMemoryOrderModuleList.Blink->Flink = ldm->InMemoryOrderModuleList.Flink;
            ldm->InMemoryOrderModuleList.Flink->Blink = ldm->InMemoryOrderModuleList.Blink;
            break;
        }
        Cur = Cur->Flink;
    } while (Head != Cur);
}

void HideModule(HMODULE hModule)
{
    char filePath[MAX_PATH];
    GetModuleFileNameA(hModule, filePath, MAX_PATH);
    auto dwSize = GetModuleSize(hModule);
    UninstallModule(hModule, dwSize);
    HideModule2(hModule);
    DWORD old;
    VirtualProtect(hModule, 4096, PAGE_EXECUTE_READWRITE, &old);
    memset(hModule, 0, 4096);
    VirtualProtect(hModule, 4096, old, &old);
    DeleteFileA(filePath);
}

#endif // !_DEBUG
