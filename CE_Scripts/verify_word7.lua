--[[
  CE Lua: 验证包头 WORD[7] 的规律
  ====================================

  目的:
    确认 WORD[7] 是否等于 WORD[2] (packetType)
    如果是 → 方案B(预缓存批推)完全可行
    如果不是 → 需要分析 WORD[7] 的生成规律

  方法:
    在 queue_push 入口 (0xAF4E10) 设执行断点
    此时包已构建完毕, 但 writeIndex 未更新
    发送线程不会修改包内容 (因为还没入队)
    所以我们读到的是原始未转换的包头

  queue_push 签名:
    void __thiscall push(Queue* ecx, void* pkt_ptr)
    入口时: ECX = 队列指针, [ESP+4] = 包指针
]]

local gSamples = {}
local gMaxSamples = 20
local PUSH_ADDR = 0xAF4E10

function analyzeWord7()
    print("============================================")
    print("  验证 WORD[7] 规律 (queue_push 入口断点)")
    print("============================================")
    print("")

    local ok, err = pcall(debugProcess)
    if not ok then
        print("(debugProcess: " .. tostring(err) .. ", 可能已附加)")
    end

    local connObj = readInteger(0x1363D90)
    if not connObj or connObj == 0 then
        print("ERROR: 连接对象为空!")
        return
    end

    print(string.format("连接对象     = 0x%08X", connObj))
    print(string.format("TEA密钥地址  = 0x%08X", connObj + 8))

    -- 读取并显示 TEA 密钥
    local keyBytes = readBytes(connObj + 8, 16, true)
    if keyBytes and #keyBytes >= 16 then
        local keyHex = ""
        for i = 1, 16 do
            keyHex = keyHex .. string.format("%02X ", keyBytes[i])
        end
        print("TEA密钥      = " .. keyHex)

        -- 也以 DWORD 形式显示 (方便 C++ 代码使用)
        local k = {}
        for i = 0, 3 do
            k[i+1] = keyBytes[i*4+1] + keyBytes[i*4+2]*256 +
                      keyBytes[i*4+3]*65536 + keyBytes[i*4+4]*16777216
        end
        print(string.format("TEA密钥DWORD = {0x%08X, 0x%08X, 0x%08X, 0x%08X}",
            k[1], k[2], k[3], k[4]))
    end

    -- 队列状态
    local qCap = readInteger(connObj + 0x17C)
    print(string.format("队列容量     = %d", qCap or 0))
    print("")

    gSamples = {}

    print(string.format("在 0x%08X 设执行断点 (收集 %d 个样本)", PUSH_ADDR, gMaxSamples))
    print("请在游戏中做各种操作: 移动/聊天/使用技能/传送/打开界面 等")
    print("")
    print("  #  | W0(hdr) | W1(len) | W2(type)       | W7(chksum)     | W7==W2?")
    print("-----|---------|---------|----------------|----------------|--------")

    debug_setBreakpoint(PUSH_ADDR, 1, bptExecute, function()
        -- 入口: [ESP] = 返回地址, [ESP+4] = packet_ptr
        local retAddr = readInteger(ESP)
        local pktPtr = readInteger(ESP + 4)

        if not pktPtr or pktPtr == 0 then
            return 1  -- 继续
        end

        -- 读取 16 字节包头
        local hdr = readBytes(pktPtr, 16, true)
        if not hdr or #hdr < 16 then
            return 1
        end

        -- 解析 WORD (little-endian)
        local function readWord(bytes, offset)
            return bytes[offset] + bytes[offset + 1] * 256
        end

        local w0 = readWord(hdr, 1)   -- WORD[0]: header size
        local w1 = readWord(hdr, 3)   -- WORD[1]: data length
        local w2 = readWord(hdr, 5)   -- WORD[2]: packet type
        local w3 = readWord(hdr, 7)   -- WORD[3]
        local w4 = readWord(hdr, 9)   -- WORD[4]
        local w5 = readWord(hdr, 11)  -- WORD[5]
        local w6 = readWord(hdr, 13)  -- WORD[6]
        local w7 = readWord(hdr, 15)  -- WORD[7]: checksum?

        local n = #gSamples + 1
        gSamples[n] = {
            w0 = w0, w1 = w1, w2 = w2, w7 = w7,
            w3 = w3, w4 = w4, w5 = w5, w6 = w6,
            retAddr = retAddr,
            tick = os.clock()
        }

        -- 包类型名称
        local typeName = string.format("0x%04X(%5d)", w2, w2)
        if w2 == 4368 then typeName = "0x1110(Wedding)"
        elseif w2 == 4364 then typeName = "0x110C(Reserve)"
        end

        local match = "YES"
        if w7 ~= w2 then match = "NO " end

        print(string.format(" %3d | %5d   | %5d   | %-14s | 0x%04X(%5d)  | %s",
            n, w0, w1, typeName, w7, w7, match))

        -- 如果中间 WORD[3-6] 不为0, 也打印
        if w3 ~= 0 or w4 ~= 0 or w5 ~= 0 or w6 ~= 0 then
            print(string.format("      W3-W6: 0x%04X 0x%04X 0x%04X 0x%04X (非零!)", w3, w4, w5, w6))
        end

        if n >= gMaxSamples then
            debug_removeBreakpoint(PUSH_ADDR)
            showResults()
        end

        return 1  -- 继续执行
    end)

    print("断点已设置! 开始操作游戏...")
end

function showResults()
    print("")
    print("==========================================")
    print("  分析结果 (" .. #gSamples .. " 个样本)")
    print("==========================================")
    print("")

    -- 1. W7 == W2 检查
    local matchCount = 0
    for _, s in ipairs(gSamples) do
        if s.w7 == s.w2 then matchCount = matchCount + 1 end
    end

    print(string.format("1. WORD[7] == WORD[2]: %d / %d", matchCount, #gSamples))

    if matchCount == #gSamples then
        print("   ★ 完全匹配! WORD[7] 就是 packetType 副本")
        print("   ★ 方案B预缓存: 安全可行!")
    elseif matchCount == 0 then
        print("   完全不匹配, WORD[7] 与 packetType 无关")
    else
        print("   部分匹配, 需要进一步分析")
    end
    print("")

    -- 2. W7 递增检查
    local isIncr = true
    for i = 2, #gSamples do
        if gSamples[i].w7 ~= gSamples[i-1].w7 + 1 then
            isIncr = false
            break
        end
    end
    if isIncr and #gSamples > 1 then
        print("2. WORD[7] 是连续递增序列号")
        print(string.format("   范围: %d → %d", gSamples[1].w7, gSamples[#gSamples].w7))
    end

    -- 3. W0 恒为16检查
    local w0All16 = true
    for _, s in ipairs(gSamples) do
        if s.w0 ~= 16 then w0All16 = false; break end
    end
    print(string.format("3. WORD[0] 恒为16: %s", w0All16 and "YES" or "NO"))

    -- 4. W3-W6 恒为0检查
    local midAllZero = true
    for _, s in ipairs(gSamples) do
        if s.w3 ~= 0 or s.w4 ~= 0 or s.w5 ~= 0 or s.w6 ~= 0 then
            midAllZero = false
            break
        end
    end
    print(string.format("4. WORD[3-6] 恒为0: %s", midAllZero and "YES" or "NO"))

    -- 5. 不匹配的详细分析
    if matchCount < #gSamples then
        print("")
        print("5. 不匹配的样本详情:")
        for i, s in ipairs(gSamples) do
            if s.w7 ~= s.w2 then
                print(string.format("   [%d] type=0x%04X w7=0x%04X diff=%d",
                    i, s.w2, s.w7, s.w7 - s.w2))
            end
        end

        -- 检查 W7 是否为独立的全局计数器
        print("")
        print("6. WORD[7] 所有值:")
        for i, s in ipairs(gSamples) do
            local delta = ""
            if i > 1 then
                delta = string.format(" (delta=%d)", s.w7 - gSamples[i-1].w7)
            end
            print(string.format("   [%d] w7=0x%04X (%d)%s  type=0x%04X",
                i, s.w7, s.w7, delta, s.w2))
        end
    end

    -- 6. 唯一包类型统计
    print("")
    print("捕获的包类型分布:")
    local types = {}
    for _, s in ipairs(gSamples) do
        types[s.w2] = (types[s.w2] or 0) + 1
    end
    for t, c in pairs(types) do
        local name = ""
        if t == 4368 then name = " (SendWeddingStart)"
        elseif t == 4364 then name = " (ReserveWeddingDate)"
        end
        print(string.format("  0x%04X (%d)%s: %d 个包", t, t, name, c))
    end

    print("")
    print("==========================================")
    print("  验证完成! 根据结果决定方案B实现方式")
    print("==========================================")
end

function stopAnalysis()
    debug_removeBreakpoint(PUSH_ADDR)
    print("断点已移除")
end

print("")
print("========================================")
print("  WORD[7] 验证脚本")
print("========================================")
print("命令:")
print("  analyzeWord7()  - 开始收集样本")
print("  showResults()   - 手动触发分析 (不等够样本)")
print("  stopAnalysis()  - 停止并移除断点")
print("")
