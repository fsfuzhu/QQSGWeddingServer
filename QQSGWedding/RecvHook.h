#pragma once

#include <windows.h>

// =====================================================================
// RecvHook - 收包分发函数 hook, 监控服务器下发的婚礼包
// =====================================================================
//
// Hook 目标: sub_594340 (主收包分发函数)
//   char __cdecl sub_594340(int packetType, int packetData)
//   所有服务器包经此函数分发到各子系统
//
// 婚礼包类型 (服务器→客户端):
//   4370 - 婚礼状态更新 (event 775)
//   4372 - 婚礼开始确认 (events 735, 774, 775)
//   4374 - 倒计时数据   (event 773)
//   4376 - 婚礼仪式信息广播 (event 776)
//   4381 - 婚礼流程更新 (event 777)
//   4383 - 婚礼祝福结果 (event 777)
//   4384, 4392, 4394 - 其他婚礼包
// =====================================================================

namespace RecvHook
{
    // 安装 inline hook (在 DLL 初始化后调用一次)
    void Install();

    // 卸载 hook (恢复原始字节)
    void Uninstall();

    // 消费婚礼触发信号 (读取后自动清除, 供 WeddingTick 调用)
    bool ConsumeWeddingTrigger();

    // 获取最近收到的婚礼包类型 (0=尚未收到)
    int GetLastWeddingPacketType();

    // 设置日志 ListBox 控件句柄
    void SetLogListBox(HWND hListBox);

    // 设置状态 Static 控件句柄
    void SetStatusLabel(HWND hStatic);

    // 从日志缓冲区刷新到 UI (在主线程 WeddingTick 中调用)
    void FlushLogToUI();

    // === 倒计时相关 (基于 4374 包) ===

    // 是否已收到倒计时数据
    bool HasCountdown();

    // 获取剩余毫秒 (实时计算: target_sec*1000 - server_time_ms)
    // 返回负数表示已超时, -1 表示无数据
    __int64 GetRemainingMs();

    // 清除倒计时 (触发burst后调用)
    void ClearCountdown();
}
