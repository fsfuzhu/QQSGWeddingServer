#pragma once

#include "GameTypes.h"

// === HMENU 常量 ===
enum {
    HMENU_Login = 300,
    HMENU_StartSqueeze = 140,
    HMENU_SyncWedding = 141,
};

// === HWND 句柄 ===
extern HWND hwnd_MainWindow;
extern HWND hwnd_LoginWindow;
extern HWND Edit_hwnd_SingleCode;
extern HWND Button_hwnd_Login;
extern HWND CheckBox_hwnd_AutoWeddingDate;
extern HWND Edit_hwnd_WeddingDate, Edit_hwnd_WeddingInterval;

// === 婚礼爆发 UI 句柄 ===
extern HWND Edit_hwnd_BurstStart, Edit_hwnd_BurstPerMs;
extern HWND Button_hwnd_SyncWedding;

// === 婚礼倒计时 UI 句柄 ===
extern HWND Static_WeddingCountdown;

// === 挤线 UI 句柄 ===
extern HWND Edit_hwnd_LineX, Edit_hwnd_LineY, Edit_hwnd_TargetLine;
extern HWND Button_StartLineSqueeze, Static_LineStatus, Static_CurrentLine;

// === 控制标志 ===
extern int GameHwnd;

// === 挤线状态变量 ===
extern LineSqueezeState lsState;
extern ULONGLONG lsStateTime;
extern int lsTargetLine;
extern int lsTargetX, lsTargetY;
extern int lsSwitchRetryCount;
extern ULONGLONG lsLastSqueezeTime;
extern ULONGLONG lsLastNavTime;
