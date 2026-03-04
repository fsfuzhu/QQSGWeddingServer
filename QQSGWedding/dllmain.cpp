#include "Globals.h"
#include "Memory.h"
#include "MainLoop.h"
#include "ProxyRelay.h"

#ifdef _DEBUG
#include "UI.h"

int main()
{
    LoadWindow();
    MSG msg;
    while (GetMessageA(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessageA(&msg);
    }

    return 0;
}
#else
#include "HideModule.h"

// === dbgcore.dll 代理转发 ===
struct dbgcore_dll {
    HMODULE dll;
    FARPROC OrignalMiniDumpReadDumpStream;
    FARPROC OrignalMiniDumpWriteDump;
} dbgcore;

extern "C" {
    __declspec(naked) void FakeMiniDumpReadDumpStream() { _asm { jmp[dbgcore.OrignalMiniDumpReadDumpStream] } }
    __declspec(naked) void FakeMiniDumpWriteDump() { _asm { jmp[dbgcore.OrignalMiniDumpWriteDump] } }
}

void e_load()
{
    char path[MAX_PATH];
    memcpy(path + GetSystemDirectoryA(path, MAX_PATH - 13), "\\dbgcore.dll", 14);
    dbgcore.dll = LoadLibraryA(path);
    if (!dbgcore.dll)
    {
        MessageBoxA(0, "Cannot load original dbgcore.dll library", "Proxy", MB_ICONERROR);
        ExitProcess(0);
    }
    dbgcore.OrignalMiniDumpReadDumpStream = GetProcAddress(dbgcore.dll, "MiniDumpReadDumpStream");
    dbgcore.OrignalMiniDumpWriteDump = GetProcAddress(dbgcore.dll, "MiniDumpWriteDump");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved) {
    if (dwReason == DLL_PROCESS_DETACH) {
        ProxyRelayCleanup();
    }
    if (dwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        e_load();
        HideModule(hModule);

        DWORD virtualTable = 0xDC630C;
        DWORD old;
        VirtualProtect((LPVOID)virtualTable, 4, PAGE_EXECUTE_READWRITE, &old);
        Asm_WriteMemory<DWORD>(virtualTable, (DWORD)MyFunInpawn);
        VirtualProtect((LPVOID)virtualTable, 4, old, &old);
    }
    return TRUE;
}
#endif // _DEBUG
