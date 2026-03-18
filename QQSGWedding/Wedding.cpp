#include "Wedding.h"
#include "Globals.h"
#include "GameData.h"
#include "ProxyRelay.h"
#include "RecvHook.h"
#include "../../GameOffsets.h"
#include <cstdio>

// === 婚礼倒计时状态 (来自 proxy WCDW 消息) ===
static volatile DWORD g_weddingTargetSec = 0;   // 目标时间 (游戏时间秒)
static volatile bool  g_hasWeddingCountdown = false;

// === 读取游戏服务器时间 (毫秒) ===
static __int64 ReadServerTimeMs()
{
    DWORD base = *(DWORD*)ADDR_TIMER_OBJ;
    if (base == 0) return 0;
    __try {
        return *(__int64*)(base + 832);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// === WCDW Handler: 从 proxy 收到婚礼倒计时时间戳 ===
// payload: [4B target_sec BE]
static void OnWCDW(const BYTE* payload, int payloadLen)
{
    if (payloadLen < 4) return;

    // BE u32
    DWORD targetSec = ((DWORD)payload[0] << 24)
                    | ((DWORD)payload[1] << 16)
                    | ((DWORD)payload[2] << 8)
                    |  (DWORD)payload[3];

    g_weddingTargetSec = targetSec;
    g_hasWeddingCountdown = true;
}

// === 初始化婚礼模块 (注册 handler, 在 ProxyRelayInit 之后调用) ===
void WeddingInit()
{
    ProxyRelayRegisterHandler("WCDW", OnWCDW);
}

// === 直接发包预约婚期 (包头4364, 4字节时间戳) ===
void SendReserveWeddingDate()
{
    char sDate[16] = { 0 };
    GetWindowTextA(Edit_hwnd_WeddingDate, sDate, 16);
    int dateYMD = atoi(sDate);
    if (dateYMD < 20000101) return;

    struct tm t = { 0 };
    t.tm_year = dateYMD / 10000 - 1900;
    t.tm_mon = dateYMD % 10000 / 100 - 1;
    t.tm_mday = dateYMD % 100;
    t.tm_isdst = -1;
    int timestamp = (int)mktime(&t);
    if (timestamp <= 0) return;

    Funcs::SendPacket(*(DWORD*)Offsets::SendPacket_ECX, 4364, (int)&timestamp, 4);
}

// =====================================================================
// 主 Tick (每帧调用)
// =====================================================================
void WeddingTick()
{
    // === 倒计时显示 (基于 proxy 下发的 WCDW + 游戏内存时间) ===
    if (Static_WeddingCountdown)
    {
        static DWORD lastCountdownUpdate = 0;
        DWORD now = GetTickCount();
        if (now - lastCountdownUpdate >= 100)
        {
            lastCountdownUpdate = now;

            if (g_hasWeddingCountdown && g_weddingTargetSec > 0)
            {
                __int64 serverMs = ReadServerTimeMs();
                if (serverMs <= 0)
                {
                    SetWindowTextA(Static_WeddingCountdown, "游戏时间读取失败");
                }
                else
                {
                    __int64 targetMs = (__int64)g_weddingTargetSec * 1000;
                    __int64 remainMs = targetMs - serverMs;

                    if (remainMs > 0)
                    {
                        char buf[64];
                        sprintf(buf, "%.1fs", remainMs / 1000.0);
                        SetWindowTextA(Static_WeddingCountdown, buf);
                    }
                    else
                    {
                        char buf[64];
                        sprintf(buf, "已结束 (%.1fs)", -remainMs / 1000.0);
                        SetWindowTextA(Static_WeddingCountdown, buf);

                        if (remainMs < -5000)
                        {
                            g_hasWeddingCountdown = false;
                            g_weddingTargetSec = 0;
                        }
                    }
                }
            }
            else
            {
                SetWindowTextA(Static_WeddingCountdown, "等待服务器下发...");
            }
        }
    }

    // === 刷新收包日志到 UI ===
    RecvHook::FlushLogToUI();

    // === 抢婚期逻辑 (定时发包, 包4364) ===
    if (CheckBox_hwnd_AutoWeddingDate && IsCheckBoxChecked(CheckBox_hwnd_AutoWeddingDate))
    {
        static DWORD lastWeddingDateTime = 0;
        DWORD currentTime = GetTickCount();
        char sInterval[16] = { 0 };
        GetWindowTextA(Edit_hwnd_WeddingInterval, sInterval, 16);
        int interval = atoi(sInterval);
        if (currentTime - lastWeddingDateTime >= (DWORD)interval)
        {
            SendReserveWeddingDate();
            lastWeddingDateTime = currentTime;
        }
    }
}
