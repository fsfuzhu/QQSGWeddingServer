#include "Wedding.h"
#include "Globals.h"
#include "GameData.h"
#include <cstdio>

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
