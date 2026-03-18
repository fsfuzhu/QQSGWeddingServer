#include "UI.h"
#include "Globals.h"
#include "GameData.h"
#include "Navigation.h"
#include "ProxyRelay.h"
#include <cstdio>
#include <cstring>

// Enable Common Controls v6 visual styles (Debug EXE only)
#ifdef _DEBUG
#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")
#endif

// Custom font
static HFONT g_hFont = NULL;

static BOOL CALLBACK SetChildFont(HWND hwndChild, LPARAM lParam)
{
    SendMessage(hwndChild, WM_SETFONT, (WPARAM)lParam, TRUE);
    return TRUE;
}

// === 登录逻辑 ===
void invokeLogin(HWND hwnd)
{
    char buffer[256];
    GetWindowTextA(Edit_hwnd_SingleCode, buffer, sizeof(buffer));
    ClientVersion version(2, 0, 1, 7);
    if (HAP_Initialize("15.204.11.218", 18000, version))
    {
        if (HAP_Login(buffer))
        {
            void* pvResult = nullptr;
            size_t pvResultLength = 0;
            uint8_t* pucResult = nullptr;
            size_t pucResultLength = 0;

            HAP_CloudFunction("getLicenseType", &pucResult, &pucResultLength);
            char* licenseType = (char*)pucResult;
            HeapFree(GetProcessHeap(), 0, pucResult);
            pucResult = nullptr;

            if (strstr(licenseType, "SGExternal") == NULL)
            {
                MessageBoxA(hwnd, "不适用此产品", "提示", MB_OK);
                return;
            }

            HAP_GetUserInfo(UserInfoType::ExpireTime, &pvResult, &pvResultLength);
            uint64_t seconds = *static_cast<uint64_t*>(pvResult);
            uint64_t days = seconds / 86400;
            uint64_t hours = (seconds % 86400) / 3600;
            uint64_t minutes = (seconds % 3600) / 60;
            uint64_t second = seconds % 60;
            char msgInfo[256] = { 0 };
            sprintf(msgInfo, "剩余时间:%lld天%lld小时%lld分%lld秒", days, hours, minutes, second);
            MessageBoxA(hwnd, msgInfo, "提示", MB_OK);
            HeapFree(GetProcessHeap(), 0, pvResult);
            pvResult = nullptr;

            ShowWindow(hwnd_LoginWindow, SW_HIDE);
            WritePrivateProfileStringA("Config", "Card", buffer, "C:\\Config.ini");
            RegisterAndCreateMainWindow();
        }
        else
        {
            auto errorCode = HAP_GetLastError();
            char msgInfo[256] = { 0 };
            switch (errorCode)
            {
            case 1:  sprintf(msgInfo, "未设置服务器信息"); break;
            case 2:  sprintf(msgInfo, "连接服务器失败"); break;
            case 3:  sprintf(msgInfo, "发送超时"); break;
            case 4:  sprintf(msgInfo, "接收超时"); break;
            case 5:  sprintf(msgInfo, "无效数据包"); break;
            case 6:  sprintf(msgInfo, "无效密钥"); break;
            case 7:  sprintf(msgInfo, "未知错"); break;
            case 1102: sprintf(msgInfo, "卡密证类型未找到"); break;
            case 1201: sprintf(msgInfo, "卡密证未找到"); break;
            case 1202: sprintf(msgInfo, "卡密证已封禁"); break;
            case 1203: sprintf(msgInfo, "卡密证类型不匹配"); break;
            case 1204: sprintf(msgInfo, "卡密证已过期"); break;
            case 1205: sprintf(msgInfo, "卡密证已过期"); break;
            case 1209: sprintf(msgInfo, "卡密证被强制下线"); break;
            case 1406: sprintf(msgInfo, "客户端版本停止使用"); break;
            case 1407: sprintf(msgInfo, "客户端版本已过期"); break;
            case 1804: sprintf(msgInfo, "服务器内错"); break;
            case 4001: sprintf(msgInfo, "服务器内错"); break;
            case 4002: sprintf(msgInfo, "权限不足"); break;
            case 4003: sprintf(msgInfo, "参数错误"); break;
            case 4004: sprintf(msgInfo, "云函数处理错误"); break;
            case 4006: sprintf(msgInfo, "该用户已禁止登录"); break;
            }
            MessageBoxA(NULL, msgInfo, "提示", MB_OK);
        }
    }
}

// === 登录窗口过程 ===
LRESULT CALLBACK LoginWindowProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
    {
        Edit_hwnd_SingleCode = CreateWindowA(
            "Edit", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
            10, 10, 340, 30,
            hwnd, NULL, NULL, NULL);

        Button_hwnd_Login = CreateWindowA(
            "Button", "登录",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_DEFPUSHBUTTON,
            88, 50, 160, 32,
            hwnd, (HMENU)HMENU_Login, NULL, NULL);

        // 从配置文件中读取卡密
        char buffer[256];
        GetPrivateProfileStringA("Config", "Card", "", buffer, sizeof(buffer), "C:\\Config.ini");
        SetWindowTextA(Edit_hwnd_SingleCode, buffer);

        // 设置字体
        HFONT hFont = CreateFontA(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Microsoft YaHei UI");
        if (hFont)
        {
            EnumChildWindows(hwnd, SetChildFont, (LPARAM)hFont);
        }
        break;
    }
    case WM_COMMAND:
    {
        if (LOWORD(wParam) == HMENU_Login)
        {
            invokeLogin(hwnd);
        }
        break;
    }
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hwnd, message, wParam, lParam);
    }
    return 0;
}

// === 主窗口过程 ===
LRESULT CALLBACK WindowProcedure(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_CREATE:
    {
        // 创建自定义字体
        g_hFont = CreateFontA(-14, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
            DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
            CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Microsoft YaHei UI");

        // === 婚礼设置 ===
        CreateWindowA("Button", "婚礼设置", WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | BS_GROUPBOX,
            5, 5, 435, 105, hwnd, NULL, NULL, NULL);
        CreateWindowA("Static", "提前:", WS_CHILD | WS_VISIBLE,
            15, 27, 35, 20, hwnd, NULL, NULL, NULL);
        Edit_hwnd_BurstStart = CreateWindowA("Edit", "600",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | WS_BORDER,
            50, 25, 50, 24, hwnd, NULL, NULL, NULL);
        CreateWindowA("Static", "ms", WS_CHILD | WS_VISIBLE,
            102, 27, 20, 20, hwnd, NULL, NULL, NULL);

        CreateWindowA("Static", "每ms:", WS_CHILD | WS_VISIBLE,
            125, 27, 40, 20, hwnd, NULL, NULL, NULL);
        Edit_hwnd_BurstPerMs = CreateWindowA("Edit", "10",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER,
            165, 25, 40, 24, hwnd, NULL, NULL, NULL);
        CreateWindowA("Static", "包", WS_CHILD | WS_VISIBLE,
            207, 27, 15, 20, hwnd, NULL, NULL, NULL);

        Button_hwnd_SyncWedding = CreateWindowA("Button", "同步",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD,
            230, 25, 50, 24, hwnd, (HMENU)HMENU_SyncWedding, NULL, NULL);
        CheckBox_hwnd_AutoWeddingDate = CreateWindowA("Button", "抢贵族婚期",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | BS_AUTOCHECKBOX,
            15, 55, 110, 24, hwnd, NULL, NULL, NULL);
        CreateWindowA("Static", "日期:", WS_CHILD | WS_VISIBLE,
            130, 57, 35, 20, hwnd, NULL, NULL, NULL);
        { // 获取今天日期作为默认值
            SYSTEMTIME st;
            GetLocalTime(&st);
            char todayStr[16];
            sprintf(todayStr, "%04d%02d%02d", st.wYear, st.wMonth, st.wDay);
            Edit_hwnd_WeddingDate = CreateWindowA("Edit", todayStr,
                WS_TABSTOP | WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER,
                165, 55, 80, 24, hwnd, NULL, NULL, NULL);
        }
        CreateWindowA("Static", "间隔:", WS_CHILD | WS_VISIBLE,
            255, 57, 35, 20, hwnd, NULL, NULL, NULL);
        Edit_hwnd_WeddingInterval = CreateWindowA("Edit", "100",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER,
            290, 55, 50, 24, hwnd, NULL, NULL, NULL);

        // 倒计时显示行
        CreateWindowA("Static", "倒计时:", WS_CHILD | WS_VISIBLE,
            15, 82, 50, 20, hwnd, NULL, NULL, NULL);
        Static_WeddingCountdown = CreateWindowA("Static", "等待婚礼倒计时...",
            WS_CHILD | WS_VISIBLE | SS_LEFT,
            65, 82, 360, 20, hwnd, NULL, NULL, NULL);

        // === 挤线设置 ===
        CreateWindowA("Button", "挤线设置", WS_CHILD | WS_VISIBLE | WS_CLIPSIBLINGS | BS_GROUPBOX,
            5, 115, 435, 100, hwnd, NULL, NULL, NULL);
        CreateWindowA("Static", "当前线路:", WS_CHILD | WS_VISIBLE,
            15, 135, 65, 20, hwnd, NULL, NULL, NULL);
        Static_CurrentLine = CreateWindowA("Static", "未知", WS_CHILD | WS_VISIBLE,
            80, 135, 50, 20, hwnd, NULL, NULL, NULL);
        CreateWindowA("Static", "坐标X:", WS_CHILD | WS_VISIBLE,
            145, 135, 42, 20, hwnd, NULL, NULL, NULL);
        Edit_hwnd_LineX = CreateWindowA("Edit", "35",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER,
            187, 133, 55, 24, hwnd, NULL, NULL, NULL);
        CreateWindowA("Static", "Y:", WS_CHILD | WS_VISIBLE,
            248, 135, 18, 20, hwnd, NULL, NULL, NULL);
        Edit_hwnd_LineY = CreateWindowA("Edit", "22",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER,
            266, 133, 55, 24, hwnd, NULL, NULL, NULL);
        CreateWindowA("Static", "目标线路:", WS_CHILD | WS_VISIBLE,
            15, 161, 65, 20, hwnd, NULL, NULL, NULL);
        Edit_hwnd_TargetLine = CreateWindowA("Edit", "1",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD | WS_BORDER | ES_NUMBER,
            80, 159, 40, 24, hwnd, NULL, NULL, NULL);
        Button_StartLineSqueeze = CreateWindowA("Button", "开始挤线",
            WS_TABSTOP | WS_VISIBLE | WS_CHILD,
            130, 159, 80, 24, hwnd, (HMENU)HMENU_StartSqueeze, NULL, NULL);
        CreateWindowA("Static", "状态:", WS_CHILD | WS_VISIBLE,
            15, 187, 40, 20, hwnd, NULL, NULL, NULL);
        Static_LineStatus = CreateWindowA("Static", "空闲", WS_CHILD | WS_VISIBLE,
            55, 187, 370, 20, hwnd, NULL, NULL, NULL);

        // 统一设置字体到所有子控件
        if (g_hFont)
        {
            EnumChildWindows(hwnd, SetChildFont, (LPARAM)g_hFont);
        }
        break;
    }

    case WM_COMMAND:
    {
        if (LOWORD(wParam) == HMENU_SyncWedding)
        {
            char sBurstStart[16] = { 0 }, sBurstPerMs[16] = { 0 };
            GetWindowTextA(Edit_hwnd_BurstStart, sBurstStart, 16);
            GetWindowTextA(Edit_hwnd_BurstPerMs, sBurstPerMs, 16);
            int burstStart = atoi(sBurstStart);
            int burstPerMs = atoi(sBurstPerMs);
            if (burstStart < 0) burstStart = 0;
            if (burstStart > 65535) burstStart = 65535;
            if (burstPerMs < 1) burstPerMs = 1;
            if (burstPerMs > 65535) burstPerMs = 65535;
            SendWeddingConfig((WORD)burstStart, (WORD)burstPerMs);
        }
        if (LOWORD(wParam) == HMENU_StartSqueeze)
        {
            if (lsState == LS_IDLE)
            {
                char sX[16] = { 0 }, sY[16] = { 0 }, sLine[16] = { 0 };
                GetWindowTextA(Edit_hwnd_LineX, sX, 16);
                GetWindowTextA(Edit_hwnd_LineY, sY, 16);
                GetWindowTextA(Edit_hwnd_TargetLine, sLine, 16);
                lsTargetX = atoi(sX) * 100;
                lsTargetY = atoi(sY) * 100;
                lsTargetLine = atoi(sLine);

                int curLine = GetCurrentServerLine();
                if (curLine == lsTargetLine)
                {
                    SetWindowTextA(Static_LineStatus, "已在目标线路");
                    break;
                }

                lsState = LS_SQUEEZE_NAV;
                lsStateTime = GetTickCount64();
                lsSwitchRetryCount = 0;
                lsLastSqueezeTime = 0;
                lsLastNavTime = 0;
                SetWindowTextA(Button_StartLineSqueeze, "停止挤线");
                SetWindowTextA(Static_LineStatus, "边寻路边挤线...");

                if (lsTargetX > 0 || lsTargetY > 0)
                {
                    MoveToPosition(lsTargetX, lsTargetY);
                }
            }
            else
            {
                lsState = LS_IDLE;
                lsSwitchRetryCount = 0;
                SetWindowTextA(Button_StartLineSqueeze, "开始挤线");
                SetWindowTextA(Static_LineStatus, "已停止");
                StopAutoWalk();
            }
        }
        break;
    }

    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
    {
        HDC hdc = (HDC)wParam;
        SetBkMode(hdc, TRANSPARENT);
        return (LRESULT)GetSysColorBrush(COLOR_BTNFACE);
    }

    case WM_DESTROY:
    {
        if (g_hFont) { DeleteObject(g_hFont); g_hFont = NULL; }
        PostQuitMessage(0);
        break;
    }
    default:
    {
        return DefWindowProc(hwnd, message, wParam, lParam);
    }
    }
    return 0;
}

// === 注册并创建登录窗口 ===
void RegisterAndCreateLoginWindow()
{
    WNDCLASSA wc = { 0 };
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "QQSGWeddingLogin";
    wc.lpfnWndProc = LoginWindowProc;
    RegisterClassA(&wc);

    hwnd_LoginWindow = CreateWindowA(
        "QQSGWeddingLogin",
        "Login",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 380, 125,
        NULL,
        NULL,
        wc.hInstance,
        NULL
    );

    ShowWindow(hwnd_LoginWindow, SW_SHOWDEFAULT);
}

// === 注册并创建主窗口 ===
void RegisterAndCreateMainWindow()
{
    WNDCLASSA wc = { 0 };
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    wc.hInstance = GetModuleHandleA(NULL);
    wc.lpszClassName = "ZXV";
    wc.lpfnWndProc = WindowProcedure;
    RegisterClassA(&wc);

    // 固定窗口大小
    DWORD dwStyle = WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX;
    int nWidth = 470, nHeight = 275;

    // 居中屏幕
    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);
    int posX = (screenW - nWidth) / 2;
    int posY = (screenH - nHeight) / 2;

    hwnd_MainWindow = CreateWindowA(
        "ZXV",
        "QQSGWedding",
        dwStyle,
        posX, posY, nWidth, nHeight,
        NULL,
        NULL,
        wc.hInstance,
        NULL
    );

    ShowWindow(hwnd_MainWindow, SW_SHOWDEFAULT);
}

// === 加载窗口入口 ===
void LoadWindow()
{
#ifdef _DEBUG
    RegisterAndCreateMainWindow();
#else
    RegisterAndCreateLoginWindow();
#endif
}
