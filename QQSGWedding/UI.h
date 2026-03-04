#pragma once

#include <windows.h>

LRESULT CALLBACK WindowProcedure(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
LRESULT CALLBACK LoginWindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam);
void RegisterAndCreateMainWindow();
void RegisterAndCreateLoginWindow();
void LoadWindow();
