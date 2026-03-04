#include "Navigation.h"
#include "Globals.h"
#include "GameData.h"

void MoveToPosition(int x, int y)
{
    int mapId = GetMapID();
    char luaCode[256];
    sprintf_s(luaCode, "Map_AutoWalkByMapIdXY(%d, %d, %d)", mapId, x, y);
    InvokeLua(luaCode);
}

void StopAutoWalk()
{
    InvokeLua("StopAutoWalk()");
}

void ChangeServerLine(int line)
{
    char code[] = { 0,0,1,0,0,0,27 };
    *(char*)(code) = (char)line;
    Funcs::SendPacket(*(DWORD*)Offsets::SendPacket_ECX, 0x427, (int)code, 6);
}

// === 挤线状态机tick ===
void NavigationTick()
{
    if (lsState == LS_IDLE || GetInPawn() == 0)
        return;

    ULONGLONG now = GetTickCount64();
    int curLine = GetCurrentServerLine();

    // 实时更新当前线路显示
    if (Static_CurrentLine)
    {
        char lineStr[16];
        sprintf_s(lineStr, "%d", curLine);
        SetWindowTextA(Static_CurrentLine, lineStr);
    }

    switch (lsState)
    {
    case LS_SQUEEZE_NAV:
    {
        if (curLine == lsTargetLine)
        {
            // 挤线成功!
            StopAutoWalk();
            lsState = LS_IDLE;
            char statusMsg[64];
            sprintf_s(statusMsg, "成功切到%d线(共%d次)!", lsTargetLine, lsSwitchRetryCount);
            SetWindowTextA(Static_LineStatus, statusMsg);
            SetWindowTextA(Button_StartLineSqueeze, "开始挤线");
        }
        else
        {
            // 每100ms发一次挤线包
            if (now - lsLastSqueezeTime >= 100)
            {
                ChangeServerLine(lsTargetLine);
                lsSwitchRetryCount++;
                lsLastSqueezeTime = now;

                char statusMsg[64];
                sprintf_s(statusMsg, "挤线中... 第%d次 当前%d线", lsSwitchRetryCount, curLine);
                SetWindowTextA(Static_LineStatus, statusMsg);
            }

            // 每300ms重新寻路 (持续导航)
            if ((lsTargetX > 0 || lsTargetY > 0) && now - lsLastNavTime >= 300)
            {
                MoveToPosition(lsTargetX, lsTargetY);
                lsLastNavTime = now;
            }
        }
        break;
    }
    default:
        break;
    }
}
