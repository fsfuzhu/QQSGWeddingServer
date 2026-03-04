#include "FastSend.h"
#include <cstring>
#include <cstdlib>

// =====================================================================
// 游戏函数指针类型
// =====================================================================

// QQ TEA CBC 加密: sub_A93875
// char __cdecl encrypt(char* plaintext, int ptLen, int keyPtr, BYTE* output, DWORD* outLen)
typedef void(__cdecl* TEAEncryptFunc)(char* plaintext, int ptLen, int key, unsigned char* output, unsigned int* outLen);

// 游戏内存分配器: sub_D6B502
// void* __cdecl alloc(int size)
typedef void* (__cdecl* GameAllocFunc)(int size);

// 游戏内存释放器: sub_D6B4DE
// void __cdecl free(void* ptr)
typedef void(__cdecl* GameFreeFunc)(void* ptr);

// 队列 push: 0xAF4E10
// void __thiscall push(Queue* this, void* packet)  — retn 4
// 用 __fastcall 模拟 __thiscall: ECX=this, EDX=unused, 栈上=packet
typedef void(__fastcall* QueuePushFunc)(void* queue, void* edx_unused, void* packet);

// =====================================================================
// 地址常量
// =====================================================================
static const DWORD ADDR_TEA_ENCRYPT = 0xA93875;
static const DWORD ADDR_GAME_ALLOC  = 0xD6B502;
static const DWORD ADDR_GAME_FREE   = 0xD6B4DE;
static const DWORD ADDR_QUEUE_PUSH  = 0xAF4E10;
static const DWORD ADDR_CONN_PTR    = 0x1363D90;  // *(DWORD*)此处 = connObj

// =====================================================================
// 函数指针
// =====================================================================
static TEAEncryptFunc  fnTEAEncrypt = nullptr;
static GameAllocFunc   fnGameAlloc  = nullptr;
static GameFreeFunc    fnGameFree   = nullptr;
static QueuePushFunc   fnQueuePush  = nullptr;

// =====================================================================
// 缓存
// =====================================================================
static const int MAX_CACHED = 50;
static const int PACKET_BUF_SIZE = 4096;  // 预留足够空间, 防止发送线程回收后重用缓冲区溢出

struct CachedPacket {
    void* buffer;       // 游戏分配器分配的内存
    int   totalSize;    // 16 (header) + encrypted data length
};

static CachedPacket g_cache[MAX_CACHED];
static int g_numCached = 0;
static bool g_initialized = false;

// =====================================================================
// 辅助: 读取连接对象
// =====================================================================
static DWORD GetConnObj()
{
    DWORD ptr = *(DWORD*)ADDR_CONN_PTR;
    if (ptr == 0) return 0;
    return ptr;
}

// =====================================================================
// 辅助: 获取 TEA 密钥指针 (connObj + 8)
// =====================================================================
static BYTE* GetTEAKey()
{
    DWORD connObj = GetConnObj();
    if (connObj == 0) return nullptr;
    return (BYTE*)(connObj + 8);
}

// =====================================================================
// 辅助: 获取发送队列指针 (connObj + 0x170)
// =====================================================================
static void* GetSendQueue()
{
    DWORD connObj = GetConnObj();
    if (connObj == 0) return nullptr;
    return (void*)(connObj + 0x170);
}

// =====================================================================
// 辅助: 获取发送队列剩余空间
// =====================================================================
static int GetQueueFreeSlots()
{
    DWORD connObj = GetConnObj();
    if (connObj == 0) return 0;

    DWORD readIdx  = *(DWORD*)(connObj + 0x174);
    DWORD writeIdx = *(DWORD*)(connObj + 0x178);
    DWORD capacity = *(DWORD*)(connObj + 0x17C);

    if (capacity == 0) return 0;

    // 环形缓冲区: 已用 = (write - read + cap) % cap
    DWORD used = (writeIdx - readIdx + capacity) % capacity;
    // 可用 = capacity - 1 - used (留1个防止满溢覆盖)
    return (int)(capacity - 1 - used);
}

// =====================================================================
// 实现
// =====================================================================

void FastSend::Init()
{
    fnTEAEncrypt = (TEAEncryptFunc)ADDR_TEA_ENCRYPT;
    fnGameAlloc  = (GameAllocFunc)ADDR_GAME_ALLOC;
    fnGameFree   = (GameFreeFunc)ADDR_GAME_FREE;
    fnQueuePush  = (QueuePushFunc)ADDR_QUEUE_PUSH;

    memset(g_cache, 0, sizeof(g_cache));
    g_numCached = 0;
    g_initialized = true;
}

bool FastSend::IsConnectionReady()
{
    DWORD connObj = GetConnObj();
    if (connObj == 0) return false;

    DWORD state = *(DWORD*)(connObj + 0x198);
    return (state == 4);
}

void FastSend::PreBuildPackets(int packetType, const char* data, int dataLen, int count)
{
    if (!g_initialized) Init();

    // 先清理旧缓存
    Cleanup();

    BYTE* teaKey = GetTEAKey();
    if (!teaKey) return;

    if (count > MAX_CACHED) count = MAX_CACHED;

    // 临时加密输出缓冲区
    unsigned char encBuf[256];
    unsigned int  encLen = 0;

    for (int i = 0; i < count; i++)
    {
        // 1. TEA CBC 加密 (每次调用产生不同密文, 因为内部有随机填充)
        encLen = 0;
        fnTEAEncrypt((char*)data, dataLen, (int)teaKey, encBuf, &encLen);

        if (encLen == 0 || encLen > 200) continue;  // 安全检查

        int totalSize = 16 + (int)encLen;

        // 2. 分配包缓冲 (使用游戏分配器, 确保 vtable[7] 回收时不崩溃)
        void* buf = fnGameAlloc(PACKET_BUF_SIZE);
        if (!buf) continue;

        memset(buf, 0, PACKET_BUF_SIZE);

        // 3. 构建 16 字节包头 (小端序, 发送线程会 htons 转换)
        WORD* header = (WORD*)buf;
        header[0] = 16;                    // WORD[0]: header size = 16
        header[1] = (WORD)encLen;          // WORD[1]: 加密数据长度
        header[2] = (WORD)packetType;      // WORD[2]: 包类型
        header[3] = 0;                     // WORD[3]: 保留
        header[4] = 0;                     // WORD[4]: 保留
        header[5] = 0;                     // WORD[5]: 保留
        header[6] = 0;                     // WORD[6]: 保留
        header[7] = (WORD)packetType;      // WORD[7]: = packetType (CE验证)

        // 4. 拷贝加密后的数据到包体 (偏移16)
        memcpy((BYTE*)buf + 16, encBuf, encLen);

        // 5. 存入缓存
        g_cache[g_numCached].buffer = buf;
        g_cache[g_numCached].totalSize = totalSize;
        g_numCached++;
    }
}

int FastSend::BurstPush()
{
    if (!g_initialized || g_numCached == 0) return 0;

    void* queue = GetSendQueue();
    if (!queue) return 0;

    // 检查连接状态
    if (!IsConnectionReady()) return 0;

    // 检查队列剩余空间, 避免溢出
    int freeSlots = GetQueueFreeSlots();
    int pushCount = (g_numCached < freeSlots) ? g_numCached : freeSlots;

    // 批量推入 — 这是速度关键: 每次 push 只有 ~10 条指令
    for (int i = 0; i < pushCount; i++)
    {
        if (g_cache[i].buffer)
        {
            fnQueuePush(queue, nullptr, g_cache[i].buffer);
        }
    }

    // 已推入的包不再由我们管理 (发送线程会处理并回收)
    // 清除已推入的缓存条目
    for (int i = 0; i < pushCount; i++)
    {
        g_cache[i].buffer = nullptr;
        g_cache[i].totalSize = 0;
    }

    // 如果还有未推入的, 移到数组前面
    if (pushCount < g_numCached)
    {
        int remaining = g_numCached - pushCount;
        memmove(g_cache, g_cache + pushCount, remaining * sizeof(CachedPacket));
        memset(g_cache + remaining, 0, pushCount * sizeof(CachedPacket));
        g_numCached = remaining;
    }
    else
    {
        g_numCached = 0;
    }

    return pushCount;
}

int FastSend::GetCachedCount()
{
    return g_numCached;
}

void FastSend::Cleanup()
{
    // 释放未推入队列的缓存 (已推入的由发送线程管理)
    for (int i = 0; i < g_numCached; i++)
    {
        if (g_cache[i].buffer && fnGameFree)
        {
            fnGameFree(g_cache[i].buffer);
        }
        g_cache[i].buffer = nullptr;
        g_cache[i].totalSize = 0;
    }
    g_numCached = 0;
}
