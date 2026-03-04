#include "RecvHook.h"
#include <cstdio>
#include <cstring>

// =====================================================================
// Hook 目标: sub_594450
//   地址: 0x594450
//   签名: char __cdecl sub_594450(int packetType, int packetData)
//   前5字节: 56 8B 74 24 08 (push esi; mov esi,[esp+8])
// =====================================================================

static const DWORD HOOK_ADDR   = 0x594450;
static const int   HOOK_LEN    = 5;           // 替换的字节数
static const DWORD HOOK_RETURN = HOOK_ADDR + HOOK_LEN;  // 0x594455

// === 状态 ===
static BYTE  g_origBytes[HOOK_LEN] = { 0 };
static bool  g_installed = false;
static BYTE* g_trampoline = nullptr;

// === 触发信号 ===
static volatile bool g_weddingTrigger = false;
static volatile int  g_lastWeddingType = 0;

// === 倒计时 (来自 4374 包) ===
// 4374 包格式: [DWORD target_sec] [BYTE flag1] [BYTE flag2]
// 服务器时间(ms): *(int64*)(*(DWORD*)0x1351788 + 832)
// 剩余时间 = target_sec * 1000 - server_time_ms
static volatile DWORD g_targetTimeSec = 0;
static volatile bool  g_hasCountdown = false;
static const DWORD ADDR_TIME_BASE = 0x1351788;

// === UI 控件 ===
static HWND g_hLogList    = NULL;
static HWND g_hStatusLabel = NULL;

// === 日志环形缓冲区 (主线程单写单读, 无需锁) ===
struct LogEntry {
    DWORD tick;
    int   packetType;
};
static const int MAX_LOG_ENTRIES = 64;
static LogEntry g_logBuffer[MAX_LOG_ENTRIES];
static volatile int g_logWriteIdx = 0;
static int g_logReadIdx = 0;

// =====================================================================
// 婚礼包类型判断
// =====================================================================
static bool IsWeddingPacket(int type)
{
    switch (type)
    {
    case 4370: case 4372: case 4374: case 4376:
    case 4381: case 4383: case 4384: case 4392: case 4394:
        return true;
    default:
        return false;
    }
}

// =====================================================================
// 辅助: 读取服务器时间 (毫秒)
// 来源: *(int64*)(*(DWORD*)0x1351788 + 832)
// sub_6072D0 中用 sub_D6B700(此值, 1000) 转为秒
// =====================================================================
static __int64 ReadServerTimeMs()
{
    DWORD base = *(DWORD*)ADDR_TIME_BASE;
    if (base == 0) return 0;
    return *(__int64*)(base + 832);
}

// =====================================================================
// 收包处理回调 (__cdecl, 从 naked hook 中调用)
// 注意: 此函数在 sub_594450 执行前被调用, 尽量轻量
// =====================================================================
static void __cdecl OnRecvPacket(int packetType, int packetData)
{
    if (!IsWeddingPacket(packetType))
        return;

    // 设置触发标志
    g_lastWeddingType = packetType;
    g_weddingTrigger = true;

    // 4374 特殊处理: 提取倒计时目标时间
    if (packetType == 4374 && packetData != 0)
    {
        DWORD targetSec = *(DWORD*)packetData;
        if (targetSec > 0)
        {
            g_targetTimeSec = targetSec;
            g_hasCountdown = true;
        }
    }

    // 写入环形日志缓冲区
    int idx = g_logWriteIdx % MAX_LOG_ENTRIES;
    g_logBuffer[idx].tick = GetTickCount();
    g_logBuffer[idx].packetType = packetType;
    g_logWriteIdx++;
}

// =====================================================================
// Naked hook 函数 (替换 sub_594450 入口)
//
// 入口栈布局: [返回地址] [packetType] [packetData]
// =====================================================================
static __declspec(naked) void HookedDispatch()
{
    __asm
    {
        // 保存 caller-saved 寄存器
        push eax
        push ecx
        push edx

        // 调用 OnRecvPacket(packetType, packetData)
        // 栈: [edx][ecx][eax][ret_addr][packetType][packetData]
        //      +0   +4   +8   +12       +16         +20
        push dword ptr [esp + 20]   // packetData
        push dword ptr [esp + 20]   // packetType (原 +16, 已 push 1项 → +20)
        call OnRecvPacket
        add  esp, 8

        // 恢复寄存器
        pop edx
        pop ecx
        pop eax

        // 跳转到 trampoline (执行原始前5字节 → 返回原函数继续)
        jmp dword ptr [g_trampoline]
    }
}

// =====================================================================
// 安装 Hook
// =====================================================================
void RecvHook::Install()
{
    if (g_installed) return;

    // 1. 分配 trampoline 可执行内存 (原始5字节 + JMP rel32 = 10字节)
    g_trampoline = (BYTE*)VirtualAlloc(NULL, 32, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_trampoline) return;

    // 2. 构建 trampoline: 复制原始5字节 + JMP 回 HOOK_RETURN
    memcpy(g_trampoline, (void*)HOOK_ADDR, HOOK_LEN);
    g_trampoline[HOOK_LEN] = 0xE9;  // JMP rel32
    DWORD trampolineJmpAddr = (DWORD)(g_trampoline + HOOK_LEN + 5);
    *(DWORD*)(g_trampoline + HOOK_LEN + 1) = HOOK_RETURN - trampolineJmpAddr;

    // 3. 备份原始字节
    memcpy(g_origBytes, (void*)HOOK_ADDR, HOOK_LEN);

    // 4. 写入 JMP hook 到 sub_594450 入口
    DWORD oldProtect;
    VirtualProtect((void*)HOOK_ADDR, HOOK_LEN, PAGE_EXECUTE_READWRITE, &oldProtect);

    BYTE jmpPatch[5];
    jmpPatch[0] = 0xE9;  // JMP rel32
    *(DWORD*)(jmpPatch + 1) = (DWORD)HookedDispatch - (HOOK_ADDR + 5);
    memcpy((void*)HOOK_ADDR, jmpPatch, HOOK_LEN);

    VirtualProtect((void*)HOOK_ADDR, HOOK_LEN, oldProtect, &oldProtect);

    g_installed = true;
}

// =====================================================================
// 卸载 Hook
// =====================================================================
void RecvHook::Uninstall()
{
    if (!g_installed) return;

    // 恢复原始字节
    DWORD oldProtect;
    VirtualProtect((void*)HOOK_ADDR, HOOK_LEN, PAGE_EXECUTE_READWRITE, &oldProtect);
    memcpy((void*)HOOK_ADDR, g_origBytes, HOOK_LEN);
    VirtualProtect((void*)HOOK_ADDR, HOOK_LEN, oldProtect, &oldProtect);

    // 释放 trampoline
    if (g_trampoline)
    {
        VirtualFree(g_trampoline, 0, MEM_RELEASE);
        g_trampoline = nullptr;
    }

    g_installed = false;
}

// =====================================================================
// 触发信号接口
// =====================================================================
bool RecvHook::ConsumeWeddingTrigger()
{
    if (g_weddingTrigger)
    {
        g_weddingTrigger = false;
        return true;
    }
    return false;
}

int RecvHook::GetLastWeddingPacketType()
{
    return g_lastWeddingType;
}

// =====================================================================
// UI 控件绑定
// =====================================================================
void RecvHook::SetLogListBox(HWND hListBox)
{
    g_hLogList = hListBox;
}

void RecvHook::SetStatusLabel(HWND hStatic)
{
    g_hStatusLabel = hStatic;
}

// =====================================================================
// 倒计时接口
// =====================================================================
bool RecvHook::HasCountdown()
{
    return g_hasCountdown && g_targetTimeSec > 0;
}

__int64 RecvHook::GetRemainingMs()
{
    if (!g_hasCountdown || g_targetTimeSec == 0)
        return -1;

    __int64 serverMs = ReadServerTimeMs();
    if (serverMs <= 0)
        return -1;

    __int64 targetMs = (__int64)g_targetTimeSec * 1000;
    return targetMs - serverMs;
}

void RecvHook::ClearCountdown()
{
    g_hasCountdown = false;
    g_targetTimeSec = 0;
}

// =====================================================================
// 刷新日志到 UI (在主线程 WeddingTick 中调用, 避免在 hook 中操作 UI)
// =====================================================================
void RecvHook::FlushLogToUI()
{
    if (!g_hLogList) return;

    while (g_logReadIdx < g_logWriteIdx)
    {
        int idx = g_logReadIdx % MAX_LOG_ENTRIES;

        char buf[80];
        sprintf(buf, "[%u] Type:%d", g_logBuffer[idx].tick, g_logBuffer[idx].packetType);
        SendMessageA(g_hLogList, LB_ADDSTRING, 0, (LPARAM)buf);
        g_logReadIdx++;

        // 限制日志条数 (保留最近 100 条)
        int count = (int)SendMessageA(g_hLogList, LB_GETCOUNT, 0, 0);
        while (count > 100)
        {
            SendMessageA(g_hLogList, LB_DELETESTRING, 0, 0);
            count--;
        }
    }

    // 自动滚动到底部
    int count = (int)SendMessageA(g_hLogList, LB_GETCOUNT, 0, 0);
    if (count > 0)
        SendMessageA(g_hLogList, LB_SETTOPINDEX, count - 1, 0);
}
