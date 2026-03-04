#pragma once

#include "GameTypes.h"

DWORD GetCQQSGGameMap();
DWORD GetCLogicModules();
DWORD GetInPawn();
Position GetPlayerPosition(DWORD Entity);
Position GetCameraPosition();
DWORD GetPlayerCurrentHP(DWORD Entity);
DWORD GetPlayerPKStatus(DWORD Entity);
bool IsPlayerInBattle();
int GetMapID();
DWORD GetLineManager();
DWORD GetCurrentServerLine();
std::string GetWindowTitle();
int ExtractLineNumber(const std::string& title);
signed int InvokeLua(const char* a2);
bool IsCheckBoxChecked(HWND hWndCheckBox);
