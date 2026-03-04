#pragma once

#include <windows.h>

// 主tick函数 (替换原始虚表函数)
char __fastcall MyFunInpawn(DWORD* thisObj, void* _EDX, DWORD* a2);

// 帧率限制补丁
void PatchFrameLimit(int frameTimeMs);
void RestoreFrameLimit();
