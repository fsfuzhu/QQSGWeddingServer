#pragma once

void WeddingInit();             // 注册 WCDW handler (在 ProxyRelayInit 之后调用)
void SendReserveWeddingDate();
void WeddingTick();             // 每帧调用

// NPC 触发: 发送 opcode 0x3F7 自动触发服务器下发婚礼倒计时
void NpcTriggerStart(int count);  // 启动连续触发, count=次数
void NpcTriggerStop();            // 停止
bool IsNpcTriggerActive();        // 是否正在触发中
