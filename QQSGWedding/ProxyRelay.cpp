// ============================================================
// ProxyRelay.cpp — TEA Key Relay + Connect Hook (tick-based)
//
// Ported from standalone KeyRelay DLL to run non-threaded
// from the game main loop (MyFunInpawn).
// ============================================================

#include "pch.h"

// Winsock headers — safe after pch.h because framework.h defines
// WIN32_LEAN_AND_MEAN which excludes winsock1 from windows.h,
// so winsock2.h can be included without conflict.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdio>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")

#include "ProxyRelay.h"
#include "Globals.h"

// Suppress deprecation warnings for inet_addr etc.
#pragma warning(disable: 4996)

// ============ Game Memory Addresses ============
static constexpr DWORD ADDR_NET_OBJ_PTR   = 0x1363D90;
static constexpr DWORD KEY_OFFSET          = 0x08;
static constexpr DWORD KEY_SIZE            = 16;
static constexpr DWORD ADDR_TIMER_OBJ      = 0x1351788;
static constexpr DWORD FN_GET_GAME_TIME    = 0x8022E0;
static constexpr DWORD ADDR_BASE           = 0x1351620;
static constexpr DWORD OFF_GAME_MAP        = 0x0C;
static constexpr DWORD OFF_MASTER          = 0x2A0;
static constexpr DWORD OFF_PLAYER_X        = 0x18;
static constexpr DWORD OFF_PLAYER_Y        = 0x44;
static constexpr DWORD OFF_PLAYER_HANDLE   = 0x70;
static constexpr DWORD OFF_PLAYER_NAME     = 0x87D0;
static constexpr DWORD PLAYER_NAME_MAX     = 32;

// ============ Config ============
static char s_proxyIP[64]      = "119.91.63.44";  // 固定代理IP
static WORD s_proxyPort        = 19900;
static bool s_redirectEnabled  = true;              // 直接启用重定向
static char s_serverName[32]   = {0};               // 检测到的服务器名称（仅日志用）

// ============ Game Port Detection ============
// Range-based detection covering known game server port patterns.
static bool IsKnownGamePort(WORD port)
{
    // New server (101.89.41.162): 10X00+线号, covers 10100-10999
    if (port >= 10100 && port <= 10999) return true;
    // Old server (113.96.12.40): 12301-12309, 12501-12518
    if (port >= 12301 && port <= 12309) return true;
    if (port >= 12501 && port <= 12518) return true;
    return false;
}

// ============ Runtime State ============
static BYTE      s_currentKey[KEY_SIZE]       = {0};
static BYTE      s_lastName[PLAYER_NAME_MAX + 1] = {0};
static BYTE      s_lastNameLen                = 0;
static SOCKET    s_proxySock                  = INVALID_SOCKET;
static bool      s_initialized               = false;
static bool      s_connectHookInstalled       = false;
static ULONGLONG s_lastTickTime               = 0;

// ============ Connect Hook State ============
typedef int (WSAAPI *PFN_connect)(SOCKET, const struct sockaddr*, int);

static DWORD g_proxyAddr      = 0;   // network byte order
static DWORD g_detectedGameServerAddr = 0;  // auto-detected from connect(), network byte order
static BYTE  s_trampoline[32] = {0};
static BYTE  s_savedBytes[8]  = {0};
static DWORD s_savedLen       = 0;
static BYTE* s_connectAddr    = NULL;

// ============ Logging ============
static void Log(const char* fmt, ...)
{
    char buf[512];
    va_list args;
    va_start(args, fmt);
    int len = _vsnprintf(buf, sizeof(buf) - 1, fmt, args);
    va_end(args);
    if (len > 0) {
        buf[len] = '\0';
        OutputDebugStringA(buf);
    }
}

// ============ Load Config ============
static void LoadProxyConfig()
{
    // IP 已固定写死, 直接设置 g_proxyAddr
    g_proxyAddr = inet_addr(s_proxyIP);
    Log("[ProxyRelay] Config: proxy=%s:%d — redirect ENABLED (hardcoded)\n",
        s_proxyIP, s_proxyPort);
}

// ============ Read TEA Key from Game Memory ============
static bool ReadTEAKey(BYTE* outKey)
{
    DWORD netObj = *(DWORD*)ADDR_NET_OBJ_PTR;
    if (netObj == 0 || netObj == 0xFFFFFFFF)
        return false;

    // Validate vtable pointer (object alive check)
    DWORD vtable = 0;
    __try {
        vtable = *(DWORD*)netObj;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
    if (vtable == 0 || vtable == 0xFFFFFFFF)
        return false;

    // Read 16-byte TEA key
    __try {
        memcpy(outKey, (void*)(netObj + KEY_OFFSET), KEY_SIZE);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }

    // Reject all-zero or all-FF keys
    bool allZero = true, allFF = true;
    for (DWORD i = 0; i < KEY_SIZE; i++) {
        if (outKey[i] != 0x00) allZero = false;
        if (outKey[i] != 0xFF) allFF = false;
    }
    if (allZero || allFF)
        return false;

    return true;
}

// ============ Read Player Pawn Pointer ============
static DWORD ReadPawn()
{
    __try {
        DWORD base = *(DWORD*)ADDR_BASE;
        if (!base) return 0;
        DWORD gameMap = *(DWORD*)(base + OFF_GAME_MAP);
        if (!gameMap) return 0;
        DWORD pawn = *(DWORD*)(gameMap + OFF_MASTER);
        return pawn;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// ============ Read Player Name (GBK) ============
// Returns actual byte length (excluding null terminator)
static BYTE ReadPlayerName(BYTE* out)
{
    DWORD pawn = ReadPawn();
    if (!pawn) return 0;
    __try {
        const BYTE* src = (const BYTE*)(pawn + OFF_PLAYER_NAME);
        BYTE len = 0;
        while (len < PLAYER_NAME_MAX && src[len] != 0) {
            out[len] = src[len];
            len++;
        }
        out[len] = 0;
        return len;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        out[0] = 0;
        return 0;
    }
}

// ============ Read Player Position & Handle ============
static bool ReadPlayerInfo(WORD* x, WORD* y, DWORD* handle)
{
    DWORD pawn = ReadPawn();
    if (!pawn) return false;
    __try {
        int ix = *(int*)(pawn + OFF_PLAYER_X);
        int iy = *(int*)(pawn + OFF_PLAYER_Y);
        *x = (WORD)(ix & 0xFFFF);
        *y = (WORD)(iy & 0xFFFF);
        *handle = *(DWORD*)(pawn + OFF_PLAYER_HANDLE);
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// ============ Read Game Time ============
typedef __int64 (__thiscall *PFN_GetGameTime)(int);
static const PFN_GetGameTime fnGetGameTime = (PFN_GetGameTime)FN_GET_GAME_TIME;

static __int64 ReadGameTime()
{
    DWORD timerObj = *(DWORD*)ADDR_TIMER_OBJ;
    if (!timerObj) return 0;
    __try {
        return fnGetGameTime(timerObj);
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return 0;
    }
}

// ============ x86 Instruction Length Decoder ============
// Covers instructions commonly found at ws2_32!connect prologue
static int GetInstrLen(const BYTE* code)
{
    // mov edi, edi (8B FF) = 2
    if (code[0] == 0x8B && code[1] == 0xFF) return 2;
    // push ebp (55) = 1
    if (code[0] == 0x55) return 1;
    // mov ebp, esp (8B EC) = 2
    if (code[0] == 0x8B && code[1] == 0xEC) return 2;
    // mov esp, ebp (89 E5) = 2
    if (code[0] == 0x89 && code[1] == 0xE5) return 2;
    // push reg (50-57) = 1
    if (code[0] >= 0x50 && code[0] <= 0x57) return 1;
    // sub esp, imm8 (83 EC xx) = 3
    if (code[0] == 0x83 && code[1] == 0xEC) return 3;
    // mov eax, fs:[0] (64 A1 xx xx xx xx) = 6
    if (code[0] == 0x64 && code[1] == 0xA1) return 6;
    // push imm8 (6A xx) = 2
    if (code[0] == 0x6A) return 2;
    // push imm32 (68 xx xx xx xx) = 5
    if (code[0] == 0x68) return 5;
    // mov reg, [esp+x] (8B 44 24 xx) = 4; (8B 4C 24 xx) = 4
    if (code[0] == 0x8B && (code[1] & 0xC7) == 0x44 && code[2] == 0x24) return 4;
    // xor reg, reg (33 C0, 31 C0, etc) = 2
    if ((code[0] == 0x33 || code[0] == 0x31) && (code[1] & 0xC0) == 0xC0) return 2;
    // nop (90) = 1
    if (code[0] == 0x90) return 1;
    // lea (8D ...) simplified
    if (code[0] == 0x8D) {
        if ((code[1] & 0xC0) == 0x40) return 3; // [reg+disp8]
        if ((code[1] & 0xC0) == 0x80) return 6; // [reg+disp32]
        if ((code[1] & 0xC0) == 0x00) return 2; // [reg]
    }
    return 0; // unknown instruction
}

// ============ Protocol: Send Game Server Info (KSRV) ============
// Format: "KSRV" + 4B IP(network byte order) + 2B port(LE) = 10 bytes
// Sends the detected real game server address to the proxy.
// Returns true if sent successfully.
static bool SendGameServerInfo(DWORD ipNetOrder, WORD port)
{
    if (s_proxySock == INVALID_SOCKET) return false;

    char buf[10];
    memcpy(buf, "KSRV", 4);
    memcpy(buf + 4, &ipNetOrder, 4);   // network byte order (as-is from sockaddr)
    memcpy(buf + 8, &port, 2);         // LE u16
    int sent = send(s_proxySock, buf, 10, 0);

    struct in_addr ia;
    ia.s_addr = ipNetOrder;
    if (sent == 10) {
        Log("[ProxyRelay] KSRV sent: %s:%d (ok)\n", inet_ntoa(ia), port);
        return true;
    } else {
        Log("[ProxyRelay] KSRV sent: %s:%d (FAILED, sent=%d err=%d)\n",
            inet_ntoa(ia), port, sent, WSAGetLastError());
        return false;
    }
}

// Forward declarations (defined later, needed by EnsureProxyConnected / HookedConnect)
static void DetectServerFromTitle();
static SOCKET ConnectToProxy();
static bool SendMsg(SOCKET sock, const char* magic, const void* data, int dataLen);

// ============ Ensure Proxy KeyRelay Connected ============
// Called from HookedConnect context when s_proxySock is not yet established.
// Synchronously connects to proxy and sends KREL (TEA key) so that the
// subsequent KSRV can be delivered before redirecting game traffic.
// Returns true if s_proxySock is valid after the call.
static bool EnsureProxyConnected()
{
    if (s_proxySock != INVALID_SOCKET) return true;
    if (s_proxyIP[0] == '\0') return false;

    Log("[ProxyRelay] EnsureProxyConnected: connecting to %s:%d ...\n", s_proxyIP, s_proxyPort);

    s_proxySock = ConnectToProxy();
    if (s_proxySock == INVALID_SOCKET) {
        Log("[ProxyRelay] EnsureProxyConnected: FAILED to connect\n");
        return false;
    }

    Log("[ProxyRelay] EnsureProxyConnected: connected OK\n");

    // Send KREL (TEA key) — proxy needs this to identify the session
    BYTE key[KEY_SIZE];
    if (ReadTEAKey(key)) {
        if (SendMsg(s_proxySock, "KREL", key, KEY_SIZE)) {
            memcpy(s_currentKey, key, KEY_SIZE);
            Log("[ProxyRelay] EnsureProxyConnected: KREL sent\n");
        } else {
            Log("[ProxyRelay] EnsureProxyConnected: KREL send failed\n");
            closesocket(s_proxySock);
            s_proxySock = INVALID_SOCKET;
            return false;
        }
    } else {
        Log("[ProxyRelay] EnsureProxyConnected: TEA key not available yet (ok, KREL deferred to Tick)\n");
    }

    return true;
}

// ============ Hooked connect() ============
// Redirects game server connections to proxy server (port-based detection, IP auto-captured)
static int WSAAPI HookedConnect(SOCKET s, const struct sockaddr* name, int namelen)
{
    if (name && name->sa_family == AF_INET && namelen >= (int)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in* addr = (const struct sockaddr_in*)name;
        WORD port = ntohs(addr->sin_port);
        DWORD destIP = addr->sin_addr.s_addr;

        // Log ALL connections for debugging (helps identify new game server ports)
        {
            struct in_addr ia;
            ia.s_addr = destIP;
            Log("[ProxyRelay] CONNECT: %s:%d\n", inet_ntoa(ia), port);
        }

        // Detect game connection: known port OR same IP as previously detected game server
        bool isGame = IsKnownGamePort(port);
        if (!isGame && g_detectedGameServerAddr != 0 && destIP == g_detectedGameServerAddr) {
            isGame = true;
            Log("[ProxyRelay] IP-match: port %d matched game server IP\n", port);
        }

        // 每次游戏连接前都重新检测窗口标题, 处理两种情况:
        // 1. s_redirectEnabled=false: 首次connect, INI没配IP, 需即时检测
        // 2. s_redirectEnabled=true (从INI恢复): 可能换服了, 需验证并更新
        if (isGame) {
            DetectServerFromTitle();
        }

        if (isGame && s_redirectEnabled) {
            // Update detected game server IP
            if (destIP != g_detectedGameServerAddr) {
                struct in_addr oldIA, newIA;
                oldIA.s_addr = g_detectedGameServerAddr;
                newIA.s_addr = destIP;
                Log("[ProxyRelay] Game server detected: %s (was %s)\n",
                    inet_ntoa(newIA), g_detectedGameServerAddr ? inet_ntoa(oldIA) : "none");
                g_detectedGameServerAddr = destIP;
            }

            // Ensure KeyRelay TCP connection exists before sending KSRV
            // (fixes race: first game connect may happen before ProxyRelayTick establishes it)
            if (!EnsureProxyConnected()) {
                Log("[ProxyRelay] Proxy unreachable, direct connect (no redirect)\n");
                PFN_connect origCall = (PFN_connect)(void*)s_trampoline;
                return origCall(s, name, namelen);
            }

            // Send KSRV to proxy with real game server address
            if (!SendGameServerInfo(destIP, port)) {
                // KSRV failed — socket likely stale (proxy closed it). Reconnect and retry.
                Log("[ProxyRelay] KSRV failed, closing stale socket and reconnecting...\n");
                closesocket(s_proxySock);
                s_proxySock = INVALID_SOCKET;

                if (!EnsureProxyConnected() || !SendGameServerInfo(destIP, port)) {
                    Log("[ProxyRelay] KSRV retry failed, direct connect (no redirect)\n");
                    PFN_connect origCall = (PFN_connect)(void*)s_trampoline;
                    return origCall(s, name, namelen);
                }
                Log("[ProxyRelay] KSRV retry succeeded\n");
            }

            // Brief pause to let proxy start dynamic listener for this port
            Sleep(100);

            // Redirect: change IP to proxy, keep original port
            struct sockaddr_in newAddr = *addr;
            newAddr.sin_addr.s_addr = g_proxyAddr;
            Log("[ProxyRelay] REDIRECT: port %d -> %s:%d\n", port, s_proxyIP, port);

            // Call original connect via trampoline
            PFN_connect origCall = (PFN_connect)(void*)s_trampoline;
            return origCall(s, (struct sockaddr*)&newAddr, sizeof(newAddr));
        }
    }
    // Non-game connection: pass through to original
    PFN_connect origCall = (PFN_connect)(void*)s_trampoline;
    return origCall(s, name, namelen);
}

// ============ Install Connect Hook (Inline) ============
static bool InstallConnectHook()
{
    // Get real address of ws2_32!connect
    HMODULE ws2 = GetModuleHandleA("ws2_32.dll");
    if (!ws2) ws2 = LoadLibraryA("ws2_32.dll");
    if (!ws2) {
        Log("[ProxyRelay] ws2_32.dll not found\n");
        return false;
    }

    s_connectAddr = (BYTE*)GetProcAddress(ws2, "connect");
    if (!s_connectAddr) {
        Log("[ProxyRelay] GetProcAddress(connect) failed\n");
        return false;
    }

    // Calculate instruction bytes to overwrite (need >= 5 for JMP rel32)
    DWORD totalLen = 0;
    while (totalLen < 5) {
        int len = GetInstrLen(s_connectAddr + totalLen);
        if (len == 0) {
            Log("[ProxyRelay] Unknown instruction at connect+%d: %02X %02X %02X\n",
                totalLen, s_connectAddr[totalLen], s_connectAddr[totalLen+1], s_connectAddr[totalLen+2]);
            return false;
        }
        totalLen += len;
    }
    s_savedLen = totalLen;

    Log("[ProxyRelay] connect @ %p, patching %d bytes\n", s_connectAddr, s_savedLen);

    // Save original bytes
    memcpy(s_savedBytes, s_connectAddr, s_savedLen);

    // Build trampoline: original instructions + JMP back to (connect + savedLen)
    DWORD oldProt;
    VirtualProtect(s_trampoline, sizeof(s_trampoline), PAGE_EXECUTE_READWRITE, &oldProt);
    memcpy(s_trampoline, s_savedBytes, s_savedLen);
    s_trampoline[s_savedLen] = 0xE9; // JMP rel32
    DWORD jmpBack = (DWORD)(s_connectAddr + s_savedLen) - (DWORD)(s_trampoline + s_savedLen + 5);
    memcpy(s_trampoline + s_savedLen + 1, &jmpBack, 4);

    // Write JMP hook at connect entry
    VirtualProtect(s_connectAddr, s_savedLen, PAGE_EXECUTE_READWRITE, &oldProt);
    s_connectAddr[0] = 0xE9; // JMP rel32
    DWORD jmpHook = (DWORD)HookedConnect - (DWORD)(s_connectAddr + 5);
    memcpy(s_connectAddr + 1, &jmpHook, 4);
    // NOP-pad remaining bytes
    for (DWORD i = 5; i < s_savedLen; i++)
        s_connectAddr[i] = 0x90;
    VirtualProtect(s_connectAddr, s_savedLen, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), s_connectAddr, s_savedLen);

    Log("[ProxyRelay] Inline hook installed on ws2_32!connect (%d bytes)\n", s_savedLen);
    s_connectHookInstalled = true;
    return true;
}

// ============ Uninstall Connect Hook ============
static void UninstallConnectHook()
{
    if (!s_connectAddr || !s_savedLen) return;

    // Restore original bytes
    DWORD oldProt;
    VirtualProtect(s_connectAddr, s_savedLen, PAGE_EXECUTE_READWRITE, &oldProt);
    memcpy(s_connectAddr, s_savedBytes, s_savedLen);
    VirtualProtect(s_connectAddr, s_savedLen, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), s_connectAddr, s_savedLen);

    Log("[ProxyRelay] Inline hook removed from ws2_32!connect\n");
    s_connectAddr = NULL;
    s_savedLen = 0;
    s_connectHookInstalled = false;
}

// ============ Connect to Proxy Server ============
// CRITICAL: Uses trampoline to call original connect, NOT the hooked version!
static SOCKET ConnectToProxy()
{
    SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return INVALID_SOCKET;

    DWORD sndTimeout = 3000;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&sndTimeout, sizeof(sndTimeout));

    DWORD rcvTimeout = 100;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&rcvTimeout, sizeof(rcvTimeout));

    // Disable Nagle for low latency
    int nodelay = 1;
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char*)&nodelay, sizeof(nodelay));

    struct sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(s_proxyPort);
    inet_pton(AF_INET, s_proxyIP, &addr.sin_addr);

    // Call original connect via trampoline (avoid our own hook intercepting this!)
    PFN_connect origConnect = (PFN_connect)(void*)s_trampoline;
    if (origConnect(sock, (struct sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return INVALID_SOCKET;
    }
    return sock;
}

// ============ Protocol: Send Message ============
// Format: 4-byte magic + data
static bool SendMsg(SOCKET sock, const char* magic, const void* data, int dataLen)
{
    char buf[128];
    if (4 + dataLen > (int)sizeof(buf)) return false;
    memcpy(buf, magic, 4);
    memcpy(buf + 4, data, dataLen);
    int sent = send(sock, buf, 4 + dataLen, 0);
    return sent == 4 + dataLen;
}

// ============ Protocol: Send Player Name (KNAM) ============
// Format: "KNAM" + 1B len + name bytes (GBK)
static bool SendPlayerName(SOCKET sock, const BYTE* name, BYTE nameLen)
{
    if (nameLen == 0 || nameLen > PLAYER_NAME_MAX) return false;
    char buf[4 + 1 + PLAYER_NAME_MAX]; // max 37 bytes
    memcpy(buf, "KNAM", 4);
    buf[4] = (char)nameLen;
    memcpy(buf + 5, name, nameLen);
    int total = 5 + nameLen;
    int sent = send(sock, buf, total, 0);
    return sent == total;
}

// ============ Protocol: Send Player Info (KINF) ============
// Format: "KINF" + 2B X(LE) + 2B Y(LE) + 4B handle(LE) + 4B pad = 16 bytes
static bool SendPlayerInfo(SOCKET sock, WORD x, WORD y, DWORD handle)
{
    char buf[16];
    memcpy(buf, "KINF", 4);
    memcpy(buf + 4, &x, 2);       // LE
    memcpy(buf + 6, &y, 2);       // LE
    memcpy(buf + 8, &handle, 4);  // LE
    memset(buf + 12, 0, 4);       // pad
    int sent = send(sock, buf, 16, 0);
    return sent == 16;
}

// ============ Server Name Detection (仅日志用) ============
// 从游戏窗口标题解析服务器名称, 仅用于日志记录
// IP 已固定写死, 不再根据服务器名切换
static void DetectServerFromTitle()
{
    if (!GameHwnd) return;
    // 已检测过, 不重复
    if (s_serverName[0] != '\0') return;

    char title[256] = {0};
    GetWindowTextA((HWND)GameHwnd, title, sizeof(title));
    if (title[0] == 0) return;

    static const char* knownServers[] = {
        "桃园结义", "巧借东风", "单刀赴会", "抚琴退敌",
    };

    for (int i = 0; i < _countof(knownServers); i++) {
        if (strstr(title, knownServers[i])) {
            strncpy(s_serverName, knownServers[i], sizeof(s_serverName) - 1);
            Log("[ProxyRelay] Server detected: %s (proxy fixed: %s)\n", knownServers[i], s_proxyIP);
            return;
        }
    }
}

// ============ Public API ============

void ProxyRelayInit()
{
    if (s_initialized) return;

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    LoadProxyConfig();

    if (InstallConnectHook()) {
        Log("[ProxyRelay] Connect hook installed (redirect -> %s:%d)\n", s_proxyIP, s_proxyPort);
    } else {
        Log("[ProxyRelay] WARNING: Connect hook failed, game traffic will NOT be redirected\n");
    }

    s_initialized = true;
    Log("[ProxyRelay] Initialized (pid=%d)\n", GetCurrentProcessId());
}

void ProxyRelayTick()
{
    if (!s_initialized) return;

    // Rate-limit to ~5Hz (every 200ms)
    ULONGLONG now = GetTickCount64();
    if (now - s_lastTickTime < 200) return;
    s_lastTickTime = now;

    // --- 检测服务器名称 (从窗口标题, 一次性) ---
    DetectServerFromTitle();

    // --- Read TEA key ---
    BYTE newKey[KEY_SIZE];
    if (!ReadTEAKey(newKey)) {
        // Network object invalid: disconnect proxy, reset key
        if (s_proxySock != INVALID_SOCKET) {
            Log("[ProxyRelay] Game disconnected, closing proxy link\n");
            closesocket(s_proxySock);
            s_proxySock = INVALID_SOCKET;
            memset(s_currentKey, 0, KEY_SIZE);
        }
        return;
    }

    // --- Key changed: update key in-place, send KREL on existing socket ---
    bool keyChanged = memcmp(newKey, s_currentKey, KEY_SIZE) != 0;
    if (keyChanged) {
        memcpy(s_currentKey, newKey, KEY_SIZE);
        // Reset name tracker to force re-send
        s_lastNameLen = 0;

        char keyStr[KEY_SIZE + 1];
        memcpy(keyStr, newKey, KEY_SIZE);
        keyStr[KEY_SIZE] = '\0';
        Log("[ProxyRelay] New key: %s\n", keyStr);

        // If already connected, send new key on existing socket (keep session alive)
        if (s_proxySock != INVALID_SOCKET) {
            if (!SendMsg(s_proxySock, "KREL", s_currentKey, KEY_SIZE)) {
                Log("[ProxyRelay] Failed to send updated key, reconnecting...\n");
                closesocket(s_proxySock);
                s_proxySock = INVALID_SOCKET;
            } else {
                Log("[ProxyRelay] Key updated on existing session\n");
            }
        }
    }

    // --- Ensure proxy connection exists (仅在服务器已检测后) ---
    if (s_proxySock == INVALID_SOCKET && s_proxyIP[0] != '\0') {
        s_proxySock = ConnectToProxy();
        if (s_proxySock == INVALID_SOCKET) {
            // Connection failed, will retry next tick
            return;
        }
        Log("[ProxyRelay] Connected to proxy %s:%d\n", s_proxyIP, s_proxyPort);

        // Send key immediately on connect
        if (!SendMsg(s_proxySock, "KREL", s_currentKey, KEY_SIZE)) {
            Log("[ProxyRelay] Failed to send key\n");
            closesocket(s_proxySock);
            s_proxySock = INVALID_SOCKET;
            return;
        }
        Log("[ProxyRelay] Key sent\n");
    }

    // --- Send KNAM: player name (on change or first connect) ---
    {
        BYTE nameBuf[PLAYER_NAME_MAX + 1];
        BYTE nameLen = ReadPlayerName(nameBuf);
        if (nameLen > 0) {
            if (nameLen != s_lastNameLen || memcmp(nameBuf, s_lastName, nameLen) != 0) {
                if (SendPlayerName(s_proxySock, nameBuf, nameLen)) {
                    memcpy(s_lastName, nameBuf, nameLen);
                    s_lastName[nameLen] = 0;
                    s_lastNameLen = nameLen;
                    Log("[ProxyRelay] Player name sent: %s (%d bytes)\n", (char*)s_lastName, nameLen);
                } else {
                    Log("[ProxyRelay] KNAM send failed, reconnecting...\n");
                    closesocket(s_proxySock);
                    s_proxySock = INVALID_SOCKET;
                    return;
                }
            }
        }
    }

    // --- Send KINF: player position and handle (every tick) ---
    {
        WORD px, py;
        DWORD handle;
        if (ReadPlayerInfo(&px, &py, &handle)) {
            if (!SendPlayerInfo(s_proxySock, px, py, handle)) {
                Log("[ProxyRelay] KINF send failed, reconnecting...\n");
                closesocket(s_proxySock);
                s_proxySock = INVALID_SOCKET;
                return;
            }
        }
    }

    // --- Send KTIM: game time sync (every tick) ---
    {
        __int64 gameTime = ReadGameTime();
        if (gameTime > 0) {
            if (!SendMsg(s_proxySock, "KTIM", &gameTime, 8)) {
                Log("[ProxyRelay] KTIM send failed, reconnecting...\n");
                closesocket(s_proxySock);
                s_proxySock = INVALID_SOCKET;
                return;
            }
        }
    }
}

void ProxyRelayCleanup()
{
    if (!s_initialized) return;

    if (s_proxySock != INVALID_SOCKET) {
        closesocket(s_proxySock);
        s_proxySock = INVALID_SOCKET;
    }

    UninstallConnectHook();
    WSACleanup();

    s_initialized = false;
    Log("[ProxyRelay] Cleanup complete\n");
}

bool IsProxyConnected()
{
    return s_proxySock != INVALID_SOCKET;
}
