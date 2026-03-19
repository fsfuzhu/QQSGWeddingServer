#pragma once

#include <windows.h>

// ============================================================
// ProxyRelay — TEA Key Relay + Connect Hook (tick-based, non-threaded)
//
// Merged from standalone KeyRelay DLL into QQSGWedding main loop.
// Call ProxyRelayInit() once at startup, ProxyRelayTick() every frame,
// ProxyRelayCleanup() at DLL unload.
//
// Features:
//   1. Read TEA key from game network object, send to proxy (KREL)
//   2. Send player name (KNAM), position/handle (KINF), game time (KTIM)
//   3. Send game server address (KSRV) — auto-detected from connect()
//   4. Inline hook ws2_32!connect to redirect game ports -> proxy
//   5. Receive messages from proxy (WCDW etc.)
// ============================================================

void ProxyRelayInit();       // Call once from MyFunInpawn first tick
void ProxyRelayTick();       // Call every frame from MyFunInpawn (internally rate-limited to ~200ms)
void ProxyRelayCleanup();    // Call from DLL_PROCESS_DETACH
bool IsProxyConnected();     // For UI status display
void SendWeddingConfig(WORD gentleInterval, WORD gentleCount, WORD aggressiveStart, WORD aggressiveInterval, WORD aggressiveCount);
void SendNpcTrigger(WORD count);  // 发送 NTRG 请求代理重放 0x3F7
void SendGentleEnable(bool enable);  // 发送 WGEN 温和发包开关

// === Receive Handler API ===
// 回调签名: void handler(const BYTE* payload, int payloadLen)
typedef void (*ProxyMsgHandler)(const BYTE* payload, int payloadLen);
bool ProxyRelayRegisterHandler(const char* magic4, ProxyMsgHandler handler);
