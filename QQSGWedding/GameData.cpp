#include "GameData.h"
#include "Memory.h"
#include "Globals.h"

DWORD GetCQQSGGameMap()
{
    auto Addr = Asm_ReadMemory<DWORD>(Offsets::Base);//8B 40 24 8B 16 C1 E8 08 24 01 8B CE 50 + 0x13
    return Asm_ReadMemory<DWORD>(Addr + Offsets::CQQSGGameMap);
}

DWORD GetCLogicModules()
{
    auto Addr = Asm_ReadMemory<DWORD>(Offsets::Base);
    Addr = Asm_ReadMemory<DWORD>(Addr + Offsets::CLogicModule);
    Addr = Asm_ReadMemory<DWORD>(Addr + Offsets::Unknow_1);
    return Addr;
}

DWORD GetInPawn()
{
    auto Addr = GetCQQSGGameMap();

    return Asm_ReadMemory<DWORD>(Addr + Offsets::CMaster);//83 EC 08 53 56 57 8B F9 8B 8F ???????? 85 C9 +0x8
}

Position GetPlayerPosition(DWORD Entity)
{
    Position pos;
    pos.x = Asm_ReadMemory<int>(Entity + 0x18);
    pos.y = Asm_ReadMemory<int>(Entity + 0x44);

    return pos;
}

Position GetCameraPosition()
{
    auto Addr = GetCQQSGGameMap();
    Position pos;
    pos.x = Asm_ReadMemory<float>(Addr + 0xEC);
    pos.y = Asm_ReadMemory<float>(Addr + 0xF0);
    return pos;
}

DWORD GetPlayerCurrentHP(DWORD Entity)
{
    return Asm_ReadMemory<DWORD>(Entity + Offsets::PlayerCurrentHP);
}

DWORD GetPlayerPKStatus(DWORD Entity)
{
    return Asm_ReadMemory<DWORD>(Entity + Offsets::PlayerPKStatus);
}

bool IsPlayerInBattle()
{
    DWORD entity = GetInPawn();
    if (entity == 0) return false;
    return GetPlayerPKStatus(entity) != 1; // 1=非PK状态(脱战)
}

int GetMapID()
{
    int mapId = Asm_ReadMemory<int>(GetCQQSGGameMap() + 0x138);
    return mapId;
}

// 获取线路管理器 (CLogicModules的第59个Manager)
// IDA来源: sub_643910, sub_647510 均使用 sub_954760(CLogicModule, 59, 1)
DWORD GetLineManager()
{
    DWORD logicModules = GetCLogicModules();
    if (logicModules == 0) return 0;
    return Asm_ReadMemory<DWORD>(logicModules + 59 * 4);  // index 59, offset 0xEC
}

std::string GetWindowTitle() {
    char title[256];
    HWND hwnd = (HWND)GameHwnd;
    if (hwnd != NULL) {
        GetWindowTextA(hwnd, title, sizeof(title));
    }
    else {
        return "No window found";
    }
    return std::string(title);
}

// Function to extract the line number from the window title
int ExtractLineNumber(const std::string& title) {
    size_t pos = title.find_last_of("线"); // Find the last occurrence of "线"
    if (pos != std::string::npos && pos > 0) {
        std::string numberStr = title.substr(pos - 3, 2); // Extract the 2 characters before "线"
        try {
            return std::stoi(numberStr);
        }
        catch (const std::invalid_argument&) {
            return -1;
        }
    }
    return -1;
}

DWORD GetCurrentServerLine()
{
    return ExtractLineNumber(GetWindowTitle());
}

signed int InvokeLua(const char* a2)
{
    DWORD thisInt = *(DWORD*)0x1414AE0;
    thisInt = *(DWORD*)(thisInt + 0x614);
    return Funcs::Lua(thisInt, (int)a2, 0);
}

bool IsCheckBoxChecked(HWND hWndCheckBox) {
    LRESULT result = SendMessage(hWndCheckBox, BM_GETCHECK, 0, 0);
    return (result == BST_CHECKED);
}
