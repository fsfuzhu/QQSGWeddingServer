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
//   5. Auto-detect server name from window title, map to proxy IP
//
// Config: ProxyRelay.ini in game EXE directory (auto-generated on server detection)
//   [Proxy]
//   IP=101.35.81.74      (auto-set by DetectServerFromTitle)
//   Port=19900
//   ServerName=桃园结义   (auto-set by DetectServerFromTitle)
// ============================================================

void ProxyRelayInit();       // Call once from MyFunInpawn first tick
void ProxyRelayTick();       // Call every frame from MyFunInpawn (internally rate-limited to ~200ms)
void ProxyRelayCleanup();    // Call from DLL_PROCESS_DETACH
bool IsProxyConnected();     // For UI status display
