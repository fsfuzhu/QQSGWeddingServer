#include "Globals.h"

// === Funcs 命名空间定义 ===
namespace Funcs
{
    OriginalFuncType originalFunction = (OriginalFuncType)0x7AC7B0;
    SendPacketType SendPacket = (SendPacketType)0x173D98E;
    LuaType Lua = (LuaType)0xACF6B0;
}

// === HWND 句柄 ===
HWND hwnd_MainWindow = 0;
HWND hwnd_LoginWindow = 0;
HWND Edit_hwnd_SingleCode = 0;
HWND Button_hwnd_Login = 0;
HWND CheckBox_hwnd_AutoWeddingDate = 0;
HWND Edit_hwnd_WeddingDate = 0, Edit_hwnd_WeddingInterval = 0;

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
