#pragma once

void WeddingInit();             // 注册 WCDW handler (在 ProxyRelayInit 之后调用)
void SendReserveWeddingDate();
void WeddingTick();             // 每帧调用
