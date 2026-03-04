#pragma once

#include <windows.h>

#ifndef _DEBUG
int GetModuleSize(HMODULE hModule);
LPVOID AllocMemory(DWORD a1, SIZE_T a2);
BOOL __stdcall UninstallModule(HMODULE a1, SIZE_T dwSize);
void HideModule2(HMODULE hMod);
void HideModule(HMODULE hModule);
#endif
