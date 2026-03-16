#pragma once

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
//
// Proxy IP: 43.139.221.10:19900 (hardcoded)
// ============================================================

void ProxyRelayInit();       // Call once from MyFunInpawn first tick
void ProxyRelayTick();       // Call every frame from MyFunInpawn (internally rate-limited to ~200ms)
void ProxyRelayCleanup();    // Call from DLL_PROCESS_DETACH
bool IsProxyConnected();     // For UI status display
void SendWeddingConfig(WORD burstStartMs, WORD burstPerMs);
