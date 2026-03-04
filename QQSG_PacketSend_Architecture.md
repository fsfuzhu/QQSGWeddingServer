# QQSG 发包架构逆向分析报告

> 分析目标: QQSG.exe (QQ三国) 网络发包系统
> 分析工具: IDA Pro 9.2 + Cheat Engine Lua 动态调试
> 分析日期: 2026-02-22
> 目的: 理解发包全流程，找到绕过 TVM 保护的优化路径

---

## 一、总体架构概览

QQSG 的网络发包采用 **双线程异步架构**:

```
┌─────────────────────────────────────────────────────┐
│                     游戏主线程                        │
│                                                       │
│  DLL调用 SendPacket(connObj, pktType, data, len)     │
│       │                                               │
│       ▼                                               │
│  TVM 字节码解释器 (0x173D98E)    ← 性能瓶颈!         │
│  ┌─ alloca(295KB)                                    │
│  ├─ 检查 connObj+0x198 == 4                          │
│  ├─ 调用 sub_AF6B40() 序列化+加密                    │
│  │   ├─ sub_AF8250() 序列化                          │
│  │   └─ sub_A93875() QQ TEA CBC 加密                 │
│  ├─ 构建 16字节包头                                   │
│  └─ 调用 queue_push(connObj+0x170, pkt_ptr)          │
│       │                    地址: 0xAF4E10             │
│       ▼                                               │
│  ┌─────────────────────┐                              │
│  │  指针环形队列         │ connObj+0x170               │
│  │  [bufPtr][rdIdx]     │                              │
│  │  [wrIdx][capacity]   │                              │
│  └──────────┬──────────┘                              │
└─────────────┼─────────────────────────────────────────┘
              │ (跨线程共享)
┌─────────────┼─────────────────────────────────────────┐
│             ▼           发送线程                       │
│  sub_AF67D0: queue_pop()                              │
│       │                                               │
│       ├─ htons() 转换包头字段为网络字节序              │
│       ├─ memcpy 到发送缓冲区 connObj+0x180            │
│       ├─ 更新待发长度 connObj+0x188                    │
│       └─ 调用 vtable[7] (TVM后处理)                   │
│                                                       │
│  sub_AF6480: ws2_32.send()                            │
│       │                                               │
│       ▼                                               │
│  TCP Socket (connObj+0x120)  ──→  游戏服务器           │
└───────────────────────────────────────────────────────┘
```

---

## 二、关键数据结构

### 2.1 连接对象 (Connection Object)

- **全局指针地址**: `0x1363D90` (存放 connObj 的指针)
- **获取方式**: `connObj = *(DWORD*)0x1363D90`
- **VTable 地址**: `0xDE69EC` (网络连接类)

```
connObj + 0x000: VTable 指针 → 0xDE69EC
connObj + 0x008: TEA 加密密钥 (16字节, 4个DWORD)
connObj + 0x018: 主机名字符串 (最大260字节)
connObj + 0x11C: 端口号 (WORD)
connObj + 0x120: Socket 句柄 (int, 由 ws2_32 分配)
connObj + 0x160: 队列1 (QueueStruct, 16字节, 用途未确认)
connObj + 0x170: 队列2 (QueueStruct, 16字节, 发送队列, 核心!)
connObj + 0x180: 发送缓冲区指针 (char*)
connObj + 0x184: 发送缓冲区总容量 (初始值=16400)
connObj + 0x188: 待发送数据长度 (int)
connObj + 0x198: 连接状态 (int, 必须==4才能发包)
connObj + 0x1A8: 时间戳 (timeGetTime)
connObj + 0x1B4: 错误状态码
connObj + 0x1E0: 统计: 总发送字节数 (double)
connObj + 0x1EC: 加密对象指针
```

### 2.2 发送队列 (QueueStruct) — connObj+0x170

这是一个**指针环形缓冲区**(Ring Buffer of Pointers):

```
偏移  字段        说明
+0x0  bufPtr      指针数组基址 (DWORD* 类型, 每个元素是一个 packet 指针)
+0x4  readIndex   消费者(发送线程)的读取位置
+0x8  writeIndex  生产者(游戏线程)的写入位置
+0xC  capacity    环形缓冲区容量 (实测值=65)
```

**空判断**: `readIndex == writeIndex`
**已用数量**: `(writeIndex - readIndex + capacity) % capacity`

### 2.3 数据包格式 (Queue Packet)

每个入队的数据包是一个**连续内存块**, 由包头(16字节) + 加密载荷组成:

```
字节偏移  类型    字段           说明
0x00      WORD    headerSize    固定值=16 (包头长度)
0x02      WORD    dataLen       加密后载荷长度
0x04      WORD    packetType    消息类型编号 (如 4368=抢婚礼)
0x06      WORD    reserved1     0
0x08      DWORD   reserved2     0
0x0C      WORD    reserved3     0
0x0E      WORD    checksum      由 sub_AF70B0() 生成 (TVM保护)
0x10+     BYTE[]  payload       QQ TEA CBC 加密后的数据
```

**注意**: 包头中所有 WORD 字段以**主机字节序(小端)**存储在队列中。
发送线程在发出前会用 `htons()` 转换为网络字节序。

### 2.4 VTable 布局 (0xDE69EC)

网络连接类的虚函数表:

```
索引  偏移    地址         说明
[0]   +0x00   0x173D98E   SendPacket (TVM保护!) — 发包入口
[1]   +0x04   0xAF5DD3    (反编译失败, 可能mid-function)
[2]   +0x08   0xAF58C0    (反编译失败)
[3]   +0x0C   0xAF5B50    析构函数
[4]   +0x10   0x16C6FF0   TVM保护函数
[5]   +0x14   0x16C1C69   TVM保护函数
[6]   +0x18   0x1734A89   TVM保护函数
[7]   +0x1C   0x1743810   TVM保护函数 (发送线程后处理回调)
[8]   +0x20   0x172F3C6   TVM保护函数
```

---

## 三、核心函数详解

### 3.1 queue_push — 队列入队 (0xAF4E10)

IDA 未自动识别此函数(位于 sub_AF4E00 和 sub_AF4E30 之间的间隙)。通过 CE 硬件写断点动态发现。

**调用约定**: `__thiscall`, 使用 `retn 4` 清理1个栈参数

**签名**:
```c
void __thiscall queue_push(QueueStruct* this_ecx, void* packet_ptr);
// ECX = 队列指针 (connObj + 0x170)
// [ESP+4] = 数据包指针 (16字节包头 + 加密载荷)
```

**反汇编**:
```asm
AF4E10: mov  eax, [ecx+8]       ; eax = writeIndex
AF4E13: mov  edx, [ecx]         ; edx = bufPtr (指针数组基址)
AF4E15: push esi
AF4E16: mov  esi, [esp+8]       ; esi = packet_ptr (栈上参数, push esi后偏移+4)
AF4E1A: mov  [edx+eax*4], esi   ; bufPtr[writeIndex] = packet_ptr  ★存入指针
AF4E1D: mov  eax, [ecx+8]       ; 重读 writeIndex
AF4E20: inc  eax                ; writeIndex + 1
AF4E21: pop  esi
AF4E22: cdq                     ; 符号扩展 EAX → EDX:EAX
AF4E23: idiv dword ptr [ecx+0Ch]; EDX:EAX / capacity → EAX=商, EDX=余数
AF4E26: mov  [ecx+8], edx       ; writeIndex = (writeIndex+1) % capacity  ★更新索引
AF4E29: retn 4                  ; 返回, 弹出4字节参数
```

**CE 动态验证结果**:
```
写断点触发: EIP = 0x00AF4E29 (retn 4, 即 mov [ecx+8],edx 的下一条)
ECX = connObj+0x170 (队列基址)
EBP = connObj (连接对象)
ESP 栈扫描发现 TVM 返回地址 0x1748A2C, 确认由 TVM 内部调用
```

### 3.2 queue_pop — 队列出队 (0xAF4E00)

**签名**: `int __thiscall queue_pop(QueueStruct* this_ecx)`

```asm
AF4E00: mov  eax, [ecx+4]       ; eax = readIndex
AF4E03: inc  eax                ; readIndex + 1
AF4E04: cdq
AF4E05: idiv dword ptr [ecx+0Ch]; / capacity
AF4E08: mov  [ecx+4], edx       ; readIndex = (readIndex+1) % capacity
AF4E0B: retn
```

### 3.3 queue_isEmpty — 队列空判断 (0xAF4DB0)

**签名**: `bool __thiscall queue_isEmpty(QueueStruct* this_ecx)`

```c
bool isEmpty(QueueStruct* this) {
    return this->readIndex == this->writeIndex;
}
```

### 3.4 queue_front — 取队首元素 (0xAF4DF0)

**签名**: `void* __thiscall queue_front(QueueStruct* this_ecx)`

```c
void* front(QueueStruct* this) {
    return (void*)this->bufPtr[this->readIndex];
    // 即: *(DWORD*)(this[0] + 4 * this[1])
}
```

### 3.5 sub_AF6B40 — 序列化+加密 (0xAF6B40)

**调用约定**: `__thiscall`

**签名**:
```c
char __thiscall PacketSerializeAndEncrypt(
    ConnObj*     this,        // ECX = 连接对象
    int          msgID,       // 消息类型编号
    int          dataPtr,     // 原始数据指针
    int          subType,     // 子类型/格式代码
    char*        outBuffer,   // 输出缓冲区 (序列化+加密后的数据)
    int*         outLen,      // [in/out] 缓冲区大小 / 实际输出长度
    int          magic,       // 固定值=196 (从已知调用者看到)
    char         doEncrypt    // 1=加密, 0=不加密
);
```

**内部流程**:
```
1. 调用 sub_AF8250(msgID, dataPtr, subType, outBuffer, outLen, magic)
   → 将消息序列化为二进制格式
2. 如果 doEncrypt == 1:
   a. 调用 sub_AF7040(this, msgID) 检查此消息是否需要加密
      → 这是 TVM thunk (跳转到 0x172BEDA)
   b. 如果需要加密:
      调用 sub_A93875(outBuffer, *outLen, this+2, tempBuf, &tempLen)
      → QQ TEA CBC 加密, 密钥取自 connObj+8
      memcpy(outBuffer, tempBuf, tempLen)
      → 加密结果覆写回输出缓冲区
3. 返回 1=成功, 0=失败
```

### 3.6 sub_A93875 — QQ TEA CBC 加密 (0xA93875)

**调用约定**: `__cdecl`

**签名**:
```c
char __cdecl QQ_TEA_Encrypt(
    char*   plaintext,    // 明文数据
    int     plaintextLen, // 明文长度
    int     keyPtr,       // 密钥指针 (16字节 = 4个DWORD)
    BYTE*   output,       // 密文输出缓冲区
    DWORD*  outputLen     // [out] 密文长度
);
```

**算法细节**:
- 底层密码: **TEA (Tiny Encryption Algorithm)**, 16轮 Feistel 网络
- TEA 常数: `delta = 0x9E3779B9` (黄金比例), 代码中以 `-1640531527 (0x61C88647)` 形式出现
- 模式: **CBC (Cipher Block Chaining)** + QQ 特有的双向 XOR 反馈
- 块大小: 8字节
- 填充规则:
  - `padLen = (plaintextLen + 10) % 8`
  - `if (padLen != 0) padLen = 8 - padLen`
  - 总长度 = 1(填充标记) + padLen(随机填充) + 2(随机字节) + plaintextLen + 7(尾部零)
  - 对齐到 8 字节的倍数
- 对于婚礼包 (plaintext=1字节): 加密后输出 **16字节**

**TEA 核心函数**: `sub_A9343A` (0xA9343A)
```c
// 单块 TEA 加密 (8字节输入 → 8字节输出)
void __cdecl TEA_EncryptBlock(DWORD* input, int keyPtr, DWORD* output);
// input[0..1] = 8字节明文, keyPtr → key[0..3] = 16字节密钥, output[0..1] = 8字节密文
```

### 3.7 sub_AF70B0 — 包头校验值生成

**地址**: 0xAF70B0 (thunk → 0x173AEAA, TVM保护)
**签名**: `int sub_AF70B0(void)` — 无参数
**返回值**: 写入包头 WORD[7] 的校验/序列值
**状态**: TVM 保护, 未完全破解。从单次 CE 抓包观察, 返回值与 packetType 相同 (待更多样本验证)

### 3.8 sub_AF67D0 — 发送线程: 出队+处理 (0xAF67D0)

**调用约定**: `__thiscall`, ECX = connObj

**伪代码**:
```c
char ProcessSendQueue(ConnObj* this) {
    QueueStruct* queue = &this->queue2;  // connObj+0x170

    if (queue_isEmpty(queue))
        return 1;  // 无数据

    while (true) {
        WORD* pkt = (WORD*)queue_front(queue);

        // 验证包头
        if (pkt[0] != 16)           // headerSize 必须=16
            { error("bad header"); return 0; }
        if (pkt[1] > 0x4000)        // dataLen 不超过 16KB
            { error("bad body"); return 0; }

        int totalLen = pkt[1] + 16;  // 总包长 = dataLen + headerSize

        // 检查发送缓冲区是否有足够空间
        // this+0x184 = 缓冲区容量, this+0x188 = 已用长度
        if (this->bufCapacity - this->pendingLen < totalLen)
            return 1;  // 空间不足, 等下次

        // 转换包头为网络字节序 (大端) — 直接修改队列中的包!
        pkt[0] = htons(pkt[0]);     // headerSize
        pkt[1] = htons(pkt[1]);     // dataLen
        pkt[2] = htons(pkt[2]);     // packetType
        pkt[7] = htons(pkt[7]);     // checksum

        // 拷贝到发送缓冲区
        memcpy(this->sendBuf + this->pendingLen, pkt, totalLen);
        this->pendingLen += totalLen;

        // 出队
        queue_pop(queue);

        // 调用 vtable[7] 后处理回调 (TVM at 0x1743810)
        this->vtable[7](this, pkt);

        // 计数器+1
        this->sendCount++;

        if (queue_isEmpty(queue))
            break;
    }
    return 1;
}
```

### 3.9 sub_AF6480 — 发送线程: TCP 发送 (0xAF6480)

**调用约定**: `__thiscall`, ECX = connObj (但声明为 `int this`, 用字节偏移)

**伪代码**:
```c
int TcpSend(ConnObj* this) {
    int pendingLen = this->pendingLen;   // +0x188
    if (pendingLen <= 0) return 0;

    // 调用 ws2_32.send()
    int sent = send(
        this->socket,     // +0x120
        this->sendBuf,    // +0x180 (缓冲区指针)
        pendingLen,        // +0x188 (待发长度)
        0                  // flags
    );
    // 调用地址: 0xAF64AD (send() 的返回地址, CE hook 验证)

    if (sent == SOCKET_ERROR) {
        this->errorState = 9;  // +0x1B4
        return -1;
    }

    // 处理部分发送
    this->pendingLen -= sent;                    // 减去已发字节
    this->totalBytesSent += (double)sent;        // +0x1E0 统计
    memmove(this->sendBuf, this->sendBuf + sent, this->pendingLen);
    return sent;
}
```

### 3.10 sub_AF6D60 — 发送线程入口 (0xAF6D60)

```c
int __stdcall SendThreadEntry(ConnObj* connObj) {
    connObj->timestamp = timeGetTime();
    ProcessStateMachine(connObj);  // sub_AF6DB0

    while (GetState(connObj) != 6) {  // 6 = 断开连接
        connObj->timestamp = timeGetTime();
        ProcessStateMachine(connObj);
    }
    return 0;
}
```

**状态机** (sub_AF6DB0): 0→2→3→4(运行)→6(断开)
在状态4中循环: `select(write) → ProcessSendQueue → TcpSend → select(read) → recv`

---

## 四、DLL 当前实现分析

### 4.1 注入方式

- **方法**: dbgcore.dll 代理注入 (DLL Hijacking)
- **入口**: DllMain → 修改 VTable 地址 0xDC630C 为 MyFunInpawn
- 隐藏模块: HideModule(hModule)

### 4.2 游戏循环 Hook

```
VTable[0xDC630C] → MyFunInpawn()
  ├─ 首次: LoadWindow() + PatchFrameLimit(1ms)
  ├─ WeddingTick()
  │   ├─ 检查UI勾选状态 (每帧 GetWindowTextA + atoi 读延迟)
  │   ├─ GetTickCount() 时间判断
  │   └─ SendWeddingStart() 或 SendReserveWeddingDate()
  └─ originalFunction() (调用原始VTable函数)
```

### 4.3 帧率补丁

- 0x801BFF: `mov edi, 1; nop` (帧时间=1ms)
- 0x801C35: 7x NOP (移除 Sleep 调用)

### 4.4 发包函数

```cpp
// 直接调用 TVM 保护的 SendPacket
void SendWeddingStart() {
    char code[1] = { 0 };
    // 函数指针: 0x173D98E (TVM入口)
    // ECX: *(DWORD*)0x1363D90 (connObj)
    Funcs::SendPacket(*(DWORD*)0x1363D90, 4368, (int)code, 1);
}

void SendReserveWeddingDate() {
    int timestamp = ...; // 从UI读取日期, 转换为Unix时间戳
    Funcs::SendPacket(*(DWORD*)0x1363D90, 4364, (int)&timestamp, 4);
}
```

### 4.5 当前性能瓶颈

每次调用 `SendPacket(0x173D98E)` 都要经过 TVM 字节码解释器:
1. `alloca(295KB)` — 巨大的栈分配
2. TVM 状态检查 + NOR-chain 计算 (模拟执行, 极慢)
3. 内部调用 native 函数完成实际工作

**估计每次 TVM 调用耗时: 1~10ms**
帧率补丁让游戏跑到 ~1000fps, 但每帧只能发一个包, 被 TVM 限速。

---

## 五、关键地址速查表

### 5.1 全局地址

| 地址 | 类型 | 说明 |
|------|------|------|
| `0x1363D90` | DWORD ptr | 连接对象指针 (connObj = *0x1363D90) |
| `0x1351620` | DWORD ptr | 游戏基址 (Base) |
| `0xDE69EC` | VTable | 网络连接类虚函数表 |
| `0xDE69B0` | VTable | IPC共享内存连接类虚函数表 |
| `0xDC630C` | VTable entry | DLL Hook 的游戏循环入口 |

### 5.2 函数地址

| 地址 | 名称 | 调用约定 | 说明 |
|------|------|----------|------|
| `0x173D98E` | SendPacket | __thiscall(connObj, pktType, data, len) | TVM保护! 发包总入口 |
| `0xAF4E10` | queue_push | __thiscall(queue_ecx, pkt_ptr) retn 4 | 队列入队 ★核心 |
| `0xAF4E00` | queue_pop | __thiscall(queue_ecx) | 队列出队 |
| `0xAF4DB0` | queue_isEmpty | __thiscall(queue_ecx) → bool | 队列空判断 |
| `0xAF4DF0` | queue_front | __thiscall(queue_ecx) → void* | 取队首 |
| `0xAF6B40` | SerializeEncrypt | __thiscall(connObj, 8 params) | 序列化+加密 |
| `0xA93875` | QQ_TEA_Encrypt | __cdecl(pt, ptLen, key, out, &outLen) | QQ TEA CBC |
| `0xA9343A` | TEA_Block | __cdecl(in, key, out) | 单块TEA加密 |
| `0xAF8250` | Serialize | __cdecl(msgID, data, subtype, buf, &len, magic) | 序列化 |
| `0xAF7040` | ShouldEncrypt | __thiscall(connObj, msgID) → TVM | 加密判断 |
| `0xAF70B0` | GetChecksum | void → int → TVM | 包头WORD[7] |
| `0xAF67D0` | ProcessSendQueue | __thiscall(connObj) | 发送线程出队处理 |
| `0xAF6480` | TcpSend | __thiscall(connObj) | ws2_32.send() |
| `0xAF6D60` | SendThreadEntry | __stdcall(connObj) | 发送线程入口 |
| `0xAF5960` | ConnObj_Ctor | __thiscall(connObj, host, port, data) | 连接对象构造 |
| `0x609F60` | SendWeddingStart_Wrapper | __cdecl(data) | Lua绑定: 抢婚礼 |
| `0x609F20` | ReserveWeddingDate_Wrapper | __cdecl(data) | Lua绑定: 抢婚期 |
| `0x689170` | LuaBind_SendWeddingStart | __thiscall(luaState) | Lua注册函数 |
| `0x689030` | LuaBind_ReserveWeddingDate | __thiscall(luaState) | Lua注册函数 |

### 5.3 连接对象偏移

| 偏移 | 类型 | 说明 |
|------|------|------|
| +0x000 | DWORD | VTable 指针 |
| +0x008 | BYTE[16] | TEA 加密密钥 (4个DWORD) |
| +0x018 | char[260] | 服务器主机名 |
| +0x11C | WORD | 服务器端口 |
| +0x120 | int | Socket 句柄 |
| +0x160 | QueueStruct(16B) | 队列1 (用途待确认) |
| +0x170 | QueueStruct(16B) | **队列2 (发送队列)** |
| +0x180 | char* | 发送缓冲区指针 |
| +0x184 | int | 发送缓冲区容量 (=16400) |
| +0x188 | int | 待发送数据长度 |
| +0x190 | int | 接收缓冲区容量 (=262160) |
| +0x198 | int | 连接状态 (4=已连接可用) |
| +0x1A8 | DWORD | timeGetTime 时间戳 |
| +0x1B4 | int | 错误状态码 |
| +0x1E0 | double | 总发送字节数统计 |
| +0x1E8 | int | 已发送包计数 |
| +0x1EC | void* | 加密/安全对象指针 |

---

## 六、加密体系

### 6.1 密钥位置

TEA 加密密钥存储在 **connObj + 0x008**, 共 16 字节 (4个 DWORD)。
密钥在连接建立时由服务器下发或协商, 整个会话期间不变。

### 6.2 加密流程

```
原始数据 (如 wedding: {0x00}, 1字节)
    │
    ▼
QQ TEA CBC 加密 (sub_A93875)
    │  密钥: connObj+0x008
    │  填充: 随机字节, 对齐到 8 字节块
    │  模式: CBC + QQ特有双向XOR反馈
    │
    ▼
加密后数据 (wedding: 16字节)
```

**加密后数据长度计算**:
```
padLen = (plaintextLen + 10) % 8
if (padLen != 0) padLen = 8 - padLen
encryptedLen = 1 + padLen + 2 + plaintextLen + 7
encryptedLen 向上对齐到 8 的倍数
```

| 明文长度 | 加密后长度 |
|----------|------------|
| 1字节 | 16字节 |
| 4字节 | 16字节 |
| 8字节 | 24字节 |
| 16字节 | 24字节 |

### 6.3 QQ TEA 算法参考

这是 QQ 协议中广泛使用的标准加密算法。
开源实现参考: 搜索 "QQ TEA encrypt decrypt" 可找到完整的 C/Python 实现。

核心 TEA 轮函数:
```c
// 16轮 Feistel
uint32_t sum = 0;
for (int i = 0; i < 16; i++) {
    sum -= 0x61C88647;  // 即 sum += 0x9E3779B9
    v0 += ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
    v1 += ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
}
```

---

## 七、优化方案

### 7.1 当前瓶颈分析

```
每个婚礼包的时间分解:
  TVM 解释执行:     ~1-10ms  (alloca 295KB + 字节码模拟)  ← 99%+ 时间
  sub_AF6B40 序列化:   ~5μs
  TEA 加密:            ~2μs
  queue_push:          ~0.1μs
  发送线程处理+send:   ~0.5ms  (受TCP/网络限制)
```

### 7.2 方案B: 预加密缓存+批量推送 (推荐, 最快)

**原理**: 在婚礼开始前, 预先调用 TVM 生成 N 个加密好的数据包并缓存。
关键时刻只需调用 queue_push, 完全避免 TVM 开销。

**实现步骤**:
1. 预先调用 TVM SendPacket N 次 (如100次, 总耗时~100ms-1s, 无所谓)
2. Hook queue_push 截获每次入队的 packet_ptr, 深拷贝保存
3. 等婚礼窗口打开时, 用 queue_push(0xAF4E10) 将缓存的包批量推入队列
4. 发送线程自动处理并发出

**关键时刻性能**: 100个包 × 0.1μs = **~10微秒** (比当前快 10000 倍)

**待验证风险**:
- 包头 WORD[7] (sub_AF70B0 返回值) 是否会过期/被服务器拒绝
- 服务器是否检查加密数据中的随机填充以防重放
- 缓存的包指针是否会被 vtable[7] 后处理回调释放

### 7.3 方案A: 直接调用 sub_AF6B40 + queue_push

**原理**: 绕过 TVM, 直接调用原生函数完成序列化加密, 再推入队列。

**实现难点**:
- sub_AF6B40 的第3/4参数 (dataPtr/subType) 对于婚礼包的正确值未知
- sub_AF70B0 (checksum) 是 TVM 保护的, 需要找到替代方式
- sub_AF7040 (加密判断) 也是 TVM 保护的

---

## 八、IPC 共享内存连接类 (补充)

除了网络连接类, 还发现一个 **IPC 共享内存连接类** (VTable 0xDE69B0):

```
构造函数: sub_AF46E0
  → 调用基类构造 sub_AF5960(this, "127.0.0.1", 12345, 0)
  → 设置 VTable 为 0xDE69B0
  → 使用 CreateFileMapping/MapViewOfFile 创建共享内存
```

它的 vtable[0] = `sub_AF49D0` 替代了 TVM 的 SendPacket, 通过共享内存环形缓冲区传递数据包:

```c
// sub_AF49D0: 共享内存发包 (非TVM)
char SendViaSharedMem(ConnObj* this, short pktType, void* data, unsigned int dataLen) {
    // 从空闲池取一个 buffer
    WORD* buf = PopFreeBuffer(pool);
    // 填充包头
    buf[0] = 16;         // headerSize
    buf[1] = dataLen;    // dataLen
    buf[2] = pktType;    // packetType
    buf[7] = sub_AF70B0(); // checksum
    // 拷贝数据
    memcpy(buf + 8, data, dataLen);
    // 推入已填充队列
    PushFilledBuffer(queue, buf);
    return 1;
}
```

此类用于进程间通信, 不走 TCP 网络。了解它有助于理解包头格式, 但优化目标仍是网络连接类。

---

## 九、CE 动态验证脚本清单

以下脚本位于 `CE_Scripts/` 目录:

| 文件 | 用途 | 状态 |
|------|------|------|
| `hook_send_no_pause.lua` | inline hook ws2_32.send(), 不暂停线程抓包 | 已验证 |
| `find_enqueue_func.lua` | 硬件写断点 connObj+0x188, 找发送缓冲区写入者 | 已验证 |
| `find_queue_push.lua` | 硬件写断点 connObj+0x178, 找 queue_push | 已验证 |

### 关键 CE 验证结果

**hook_send_no_pause.lua 输出**:
- send() 调用者: `0x00AF64AD` (sub_AF6480 内部)
- Socket: 3484, 每包 32 字节 (16 header + 16 encrypted)
- tersafe32.dll (反作弊) 使用独立 Socket 1508

**find_queue_push.lua 输出**:
- queue_push 写入者: `EIP = 0x00AF4E29` (queue_push 的 retn 4 指令)
- 队列 capacity = 65, buffer = heap 地址
- 调用栈中包含 TVM 地址 0x1748A2C (确认 push 由 TVM 内部调用)
- 抓到的包头: `00 10 00 10 11 0C 00 00 00 00 00 00 00 00 11 0C`
- 对应 packetType = 4364 (ReserveWeddingDate)

---

## 十、术语表

| 术语 | 说明 |
|------|------|
| **TVM** | Themida Virtual Machine, 代码保护虚拟机, 将原生代码转为字节码解释执行 |
| **connObj** | 连接对象 (Connection Object), QQSG 的核心网络对象 |
| **QQ TEA** | QQ 协议使用的 TEA 加密算法 (CBC 模式, 16轮) |
| **htons** | Host TO Network Short, 将 16位值从主机字节序转为网络字节序 (大端) |
| **Ring Buffer** | 环形缓冲区, 用固定大小数组 + 读/写索引实现的 FIFO 队列 |
| **VTable** | 虚函数表, C++ 多态机制, 存放函数指针数组 |
| **dbgcore.dll** | Windows 系统 DLL, 被代理用于 DLL 注入 |
| **tersafe32.dll** | 腾讯反作弊模块 |
