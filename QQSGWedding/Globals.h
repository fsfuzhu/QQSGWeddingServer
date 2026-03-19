#pragma once

#include "GameTypes.h"

// === HMENU 常量 ===
enum {
    HMENU_Login = 300,
    HMENU_StartSqueeze = 140,
    HMENU_SyncWedding = 141,
    HMENU_NpcTrigger = 142,
    HMENU_GentleToggle = 143,
};

// === HWND 句柄 ===
extern HWND hwnd_MainWindow;
extern HWND hwnd_LoginWindow;
extern HWND Edit_hwnd_SingleCode;
extern HWND Button_hwnd_Login;
extern HWND CheckBox_hwnd_AutoWeddingDate;
extern HWND Edit_hwnd_WeddingDate, Edit_hwnd_WeddingInterval;

// === 婚礼爆发 UI 句柄 (两段式) ===
extern HWND Edit_hwnd_GentleInterval, Edit_hwnd_GentleCount;
extern HWND Button_hwnd_GentleToggle;
extern HWND Edit_hwnd_AggressiveStart, Edit_hwnd_AggressiveInterval, Edit_hwnd_AggressiveCount;
extern HWND Button_hwnd_SyncWedding;

// === 婚礼倒计时 UI 句柄 ===
extern HWND Static_WeddingCountdown;

// === NPC触发 UI 句柄 ===
extern HWND Edit_hwnd_NpcTriggerCount;
extern HWND Button_NpcTrigger;
extern HWND Static_NpcTriggerProgress;

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
