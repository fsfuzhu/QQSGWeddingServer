#include "MainLoop.h"
#include "Globals.h"
#include "GameData.h"
#include "UI.h"
#include "Wedding.h"
#include "RecvHook.h"
#include "ProxyRelay.h"
#include "Navigation.h"

// === 帧率限制补丁 ===
// sub_801AB0 帧率限制器:
//   ADDR_FRAME_TIME_PATCH: and edi,-9; add edi,25  → framerate ? 16ms : 25ms (帧时间)
//   ADDR_SLEEP_PATCH: push ebp; call Sleep    → Sleep(10) 前台 / Sleep(1) 后台
// 补丁策略: 替换帧时间为固定值 + NOP掉Sleep调用
static BYTE g_origFrameTime[6] = { 0 };  // ADDR_FRAME_TIME_PATCH 原始字节备份
static BYTE g_origSleep[7] = { 0 };      // ADDR_SLEEP_PATCH 原始字节备份
static bool g_frameLimitPatched = false;

void PatchFrameLimit(int frameTimeMs)
{
    if (frameTimeMs <= 0) { RestoreFrameLimit(); return; }
    if (frameTimeMs > 255) frameTimeMs = 255;

    DWORD old1, old2;

    // 补丁1: 帧时间 — 替换 and edi,-9; add edi,25 为 mov edi,N; nop
    VirtualProtect((void*)ADDR_FRAME_TIME_PATCH, 6, PAGE_EXECUTE_READWRITE, &old1);
    if (!g_frameLimitPatched)
        memcpy(g_origFrameTime, (void*)ADDR_FRAME_TIME_PATCH, 6);
    BYTE patchFrame[] = { 0xBF, (BYTE)frameTimeMs, 0x00, 0x00, 0x00, 0x90 };
    memcpy((void*)ADDR_FRAME_TIME_PATCH, patchFrame, 6);
    VirtualProtect((void*)ADDR_FRAME_TIME_PATCH, 6, old1, &old1);

    // 补丁2: 移除Sleep — NOP掉 push ebp; call [Sleep]
    VirtualProtect((void*)ADDR_SLEEP_PATCH, 7, PAGE_EXECUTE_READWRITE, &old2);
    if (!g_frameLimitPatched)
        memcpy(g_origSleep, (void*)ADDR_SLEEP_PATCH, 7);
    memset((void*)ADDR_SLEEP_PATCH, 0x90, 7);
    VirtualProtect((void*)ADDR_SLEEP_PATCH, 7, old2, &old2);

    g_frameLimitPatched = true;
}

void RestoreFrameLimit()
{
    if (!g_frameLimitPatched) return;
    DWORD old;

    VirtualProtect((void*)ADDR_FRAME_TIME_PATCH, 6, PAGE_EXECUTE_READWRITE, &old);
    memcpy((void*)ADDR_FRAME_TIME_PATCH, g_origFrameTime, 6);
    VirtualProtect((void*)ADDR_FRAME_TIME_PATCH, 6, old, &old);

    VirtualProtect((void*)ADDR_SLEEP_PATCH, 7, PAGE_EXECUTE_READWRITE, &old);
    memcpy((void*)ADDR_SLEEP_PATCH, g_origSleep, 7);
    VirtualProtect((void*)ADDR_SLEEP_PATCH, 7, old, &old);

    g_frameLimitPatched = false;
}

char __fastcall MyFunInpawn(DWORD* thisObj, void* _EDX, DWORD* a2)
{
    static bool first = true;

    if (first)
    {
        LoadWindow();
        GameHwnd = (int)FindWindowA("QQSGWinClass", NULL);
        // PatchFrameLimit(1);  // 帧率补丁已屏蔽，不再使用
        RecvHook::Install(); // 安装收包 hook (保留用于调试)
        ProxyRelayInit();    // 初始化代理中继 (connect hook + TEA key relay)
        WeddingInit();       // 注册 WCDW handler
        first = false;
    }

    if (GetInPawn() == 0)
    {
        return Funcs::originalFunction(thisObj, a2);
    }

    // 代理中继 (TEA key / player info / game time → 云服务器)
    ProxyRelayTick();

    // 挤线状态机
    NavigationTick();

    // 婚礼逻辑 (仅抢贵族婚期)
    WeddingTick();

    return Funcs::originalFunction(thisObj, a2);
}
