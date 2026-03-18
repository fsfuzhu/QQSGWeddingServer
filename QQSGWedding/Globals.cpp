#include "Globals.h"

// === Funcs 命名空间定义 ===
namespace Funcs
{
    OriginalFuncType originalFunction = (OriginalFuncType)ADDR_ORIGINAL_FUNCTION;
    SendPacketType SendPacket = (SendPacketType)ADDR_SEND_PACKET;
    LuaType Lua = (LuaType)ADDR_LUA;
}

// === HWND 句柄 ===
HWND hwnd_MainWindow = 0;
HWND hwnd_LoginWindow = 0;
HWND Edit_hwnd_SingleCode = 0;
HWND Button_hwnd_Login = 0;
HWND CheckBox_hwnd_AutoWeddingDate = 0;
HWND Edit_hwnd_WeddingDate = 0, Edit_hwnd_WeddingInterval = 0;

// === 婚礼爆发 UI 句柄 ===
HWND Edit_hwnd_BurstStart = 0, Edit_hwnd_BurstPerMs = 0;
HWND Button_hwnd_SyncWedding = 0;

// === 婚礼倒计时 UI 句柄 ===
HWND Static_WeddingCountdown = 0;

// === 挤线 UI 句柄 ===
HWND Edit_hwnd_LineX = 0, Edit_hwnd_LineY = 0, Edit_hwnd_TargetLine = 0;
HWND Button_StartLineSqueeze = 0, Static_LineStatus = 0, Static_CurrentLine = 0;

// === 控制标志 ===
int GameHwnd = 0;

// === 挤线状态变量 ===
LineSqueezeState lsState = LS_IDLE;
ULONGLONG lsStateTime = 0;
int lsTargetLine = 1;
int lsTargetX = 0, lsTargetY = 0;
int lsSwitchRetryCount = 0;
ULONGLONG lsLastSqueezeTime = 0;
ULONGLONG lsLastNavTime = 0;
