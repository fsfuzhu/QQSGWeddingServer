#pragma once

#include "GameTypes.h"

// =====================================================================
// FastSend - 绕过 TVM 的高速发包模块
// =====================================================================
//
// 原理:
//   正常路径: DLL → TVM(0x1740C5B, ~1-10ms) → 序列化 → 加密 → queue_push
//   快速路径: DLL → TEA加密(~10μs) → 构建包头 → queue_push(~0.1μs)
//
//   通过提前缓存加密好的数据包, 在关键时刻直接批量推入发送队列
//   绕过 TVM 字节码解释器 (295KB alloca + 慢速模拟)
//
// 地址清单 (IDA+CE 逆向确认):
//   0xAF4CE0  - queue_push:  __thiscall(Queue* ecx, void* pkt), retn 4
//   0xA93745  - QQ TEA CBC:  __cdecl(char* pt, int len, int key, BYTE* out, DWORD* outLen)
//   0xD6B432  - 游戏分配器: __cdecl(int size) → void* (CRT malloc thunk)
//   0x1363DD0 - 连接对象指针地址
//   connObj+8 - TEA 密钥 (16字节)
//   connObj+0x170 - 发送队列 Queue2 [bufPtr, readIdx, writeIdx, capacity]
//
// 包头格式 (16字节, 8个WORD, 小端序):
//   WORD[0] = 16 (固定, header size)
//   WORD[1] = 加密后数据长度
//   WORD[2] = packetType
//   WORD[3-6] = 0
//   WORD[7] = packetType (对婚礼包, CE 验证 6/6 匹配)
// =====================================================================

namespace FastSend
{
    // 初始化 (DLL 加载后调用一次, 设置函数指针)
    void Init();

    // 预构建 N 个加密好的婚礼包到缓存
    // packetType: 4368 (抢婚礼) 或 4364 (抢婚期)
    // data/dataLen: 原始包体数据
    // count: 预构建数量 (建议 ≤ 30)
    void PreBuildPackets(int packetType, const char* data, int dataLen, int count);

    // 批量推入发送队列 — 在关键时刻调用
    // 返回实际推入的包数量
    int BurstPush();

    // 获取当前缓存数量
    int GetCachedCount();

    // 释放所有缓存
    void Cleanup();

    // 检查连接是否就绪 (state == 4)
    bool IsConnectionReady();
}
