#pragma once

#include <windows.h>
#include <vector>
#include <sstream>
#include <algorithm>
#include <cmath>
#include <string>
#include <set>
#include <fstream>
#include <ctime>

// HAP SDK
#include "HAP_SDK.h"

// Function pointer types
typedef int(__thiscall* LuaType)(DWORD thisObj, int a2, int a3);
typedef int(__thiscall* SendPacketType)(DWORD thisObj, int head, int code, int len);
typedef char(__thiscall* OriginalFuncType)(DWORD* thisObj, DWORD* a2);

namespace Offsets
{
    const DWORD Base = 0x1351660;
    const DWORD CLogicModule = 0x4;
    const DWORD CQQSGGameMap = 0xC;
    const DWORD CGameObjMgr = 0x14;
    const DWORD Unknow_1 = 0xC;
    const DWORD CUIData = 0x0;
    const DWORD CGuildMgr = 0x18;
    const DWORD CSkillPack = 0x20;
    const DWORD CItemPack = 0x24;
    const DWORD CStoragePack = 0x28;
    const DWORD CCCoolDownMgr = 0x34;
    const DWORD CAccelBarMgr = 0x38;
    const DWORD CTeamMgr = 0x58;
    const DWORD CMasterAutoFarmingMgr = 0x154;
    const DWORD CMaster = 0x2A0;
    const DWORD PlayerOwnMaxHP = 0x8854;
    const DWORD PlayerExtraMaxHP = 0x905C;
    const DWORD PlayerCurrentHP = 0x8858;
    const DWORD PlayerOwnMaxMP = 0x885C;
    const DWORD PlayerExtraMaxMP = 0x9060;
    const DWORD PlayerCurrentMP = 0x8860;
    const DWORD PlayerNation = 0x8874;
    const DWORD PlayerPKStatus = 0x1F8;
    const DWORD PlayerLevel = 0x8A08;
    const DWORD PlayerCurrentPrimordialSpiritAddr = 0x8A24;
    const DWORD PlayerCurrentPrimordialSpiritName = 0x8A38;
    const DWORD PlayerMovementStatus = 0x200;
    const DWORD PlayerArmyName = 0x8958 + 0x44;
    const DWORD BabyTABSelectStatus = 0x10D0;
    const DWORD AutoSelectBabyStatus = 0x10D4;
    const DWORD UnRefreshPosBase = 0x428;
    const DWORD PlayerCareerNameBase = 0x8A14;
    const DWORD PlayerCareerName = 0x74;
    const DWORD PlayerName = 0x87D0;
    const DWORD MonsterName = 0x87F0;
    const DWORD CPlyShopName = 0x11C;
    const DWORD NPCName = 0x87C4;
    const DWORD IgnoreChaos = 0x8684;
    const DWORD IgnoreBlackScreen_1 = 0x1DC;
    const DWORD IgnoreBlackScreen_2 = 0x200;
    const DWORD Ignore_BlackScreen = 0x4ACCD1;
    const DWORD BackpackItemStartBase = 0x4F0;
    const DWORD BackpackItemEndBase = 0x4F4;
    const DWORD BackpackItemID = 0x8;
    const DWORD BackpackItemName = 0x44;
    const DWORD PlayerID = 0x70;
    const DWORD IgnoreForcedLock = 0x4B2241;
    const DWORD IgnoreForcedLock2 = 0x4D7763;

    const DWORD SendPacket_ECX = 0x1363DD0;
}

namespace Funcs
{
    extern OriginalFuncType originalFunction;
    extern SendPacketType SendPacket;
    extern LuaType Lua;
}

struct Position
{
    Position() : x(0.f), y(0.f) {}
    Position(float _x, float _y) : x(_x), y(_y) {}
    float x;
    float y;
};

// === 挤线状态机 ===
enum LineSqueezeState {
    LS_IDLE,            // 空闲
    LS_SQUEEZE_NAV,     // 边寻路边挤线
};
