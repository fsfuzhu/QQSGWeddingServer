--[[
  CE Lua: 用硬件写断点找到队列PUSH函数(游戏线程入队)
  ==========================================================

  原理:
    connObj+0x170 是一个指针环形队列:
      +0x170: buffer pointer (指针数组)
      +0x174: readIndex  (发送线程 pop 修改)
      +0x178: writeIndex (游戏线程 push 修改) <-- 监控这个!
      +0x17C: capacity

    发送线程的 pop(sub_AF4E00) 只修改 readIndex(+0x174)
    所以 writeIndex(+0x178) 只被游戏线程的 push 操作写入
    不会有发送线程的误触发

  目的:
    找到 TVM 内部调用的 native 函数 (真正执行 push 的那个)
    有了这个函数, 就可以绕过 TVM 直接调用, 大幅提速

  风险:
    硬件写断点会暂停游戏线程
    一次捕获后立即移除, 影响最小
]]

function findQueuePush()
    print("============================================")
    print("  寻找队列PUSH函数 (writeIndex监控)")
    print("============================================")

    -- 附加调试器
    local ok, err = pcall(debugProcess)
    if not ok then
        print("WARNING: debugProcess failed: " .. tostring(err))
        print("可能已经附加了, 继续...")
    end

    -- 读取连接对象
    local connPtrAddr = 0x1363D90
    local connObj = readInteger(connPtrAddr)
    if not connObj or connObj == 0 then
        print("ERROR: 连接对象为空! 请确保已登录游戏")
        return
    end

    -- 读取队列状态
    local qBufPtr    = readInteger(connObj + 0x170)
    local qReadIdx   = readInteger(connObj + 0x174)
    local qWriteIdx  = readInteger(connObj + 0x178)
    local qCapacity  = readInteger(connObj + 0x17C)

    print(string.format("连接对象     = 0x%08X", connObj))
    print(string.format("队列 buffer  = 0x%08X (connObj+0x170)", qBufPtr or 0))
    print(string.format("队列 readIdx = %d (connObj+0x174)", qReadIdx or 0))
    print(string.format("队列 writeIdx= %d (connObj+0x178)", qWriteIdx or 0))
    print(string.format("队列 capacity= %d (connObj+0x17C)", qCapacity or 0))
    print("")

    -- 验证队列看起来合理
    if not qBufPtr or qBufPtr == 0 then
        print("WARNING: 队列 buffer 为空! 可能还没初始化")
        print("请先在游戏内做一次操作(发一个包)再运行此脚本")
        return
    end

    if not qCapacity or qCapacity == 0 then
        print("WARNING: 队列 capacity 为 0! 队列结构可能不对")
        print("请检查偏移是否正确")
        return
    end

    -- 也读取发送缓冲区状态作参考
    local sendBufPtr = readInteger(connObj + 0x180)
    local pendLen    = readInteger(connObj + 0x188)
    local state      = readInteger(connObj + 0x198)
    print(string.format("发送缓冲区   = 0x%08X (connObj+0x180)", sendBufPtr or 0))
    print(string.format("待发长度     = %d (connObj+0x188)", pendLen or 0))
    print(string.format("连接状态     = %d (connObj+0x198, 需==4)", state or 0))
    print("")

    -- 监控目标: writeIndex 地址
    local targetAddr = connObj + 0x178
    print(string.format(">>> 设置硬件写断点: 0x%08X (writeIndex)", targetAddr))
    print(">>> 请在游戏中触发一次发包操作...")
    print("")

    local hitCount = 0
    local maxHits = 3  -- 收集3次样本

    debug_setBreakpoint(targetAddr, 4, bptWrite, function()
        hitCount = hitCount + 1
        local newWriteIdx = readInteger(targetAddr)

        print(string.format("=== 写断点触发 #%d ===", hitCount))
        print(string.format("  EIP = 0x%08X", EIP))
        print(string.format("  新 writeIndex = %d", newWriteIdx or 0))
        print("")

        -- 寄存器状态
        print(string.format("  EAX = 0x%08X", EAX))
        print(string.format("  EBX = 0x%08X", EBX))
        print(string.format("  ECX = 0x%08X (this?)", ECX))
        print(string.format("  EDX = 0x%08X", EDX))
        print(string.format("  ESI = 0x%08X", ESI))
        print(string.format("  EDI = 0x%08X", EDI))
        print(string.format("  EBP = 0x%08X", EBP))
        print(string.format("  ESP = 0x%08X", ESP))
        print("")

        -- 模块定位
        local mods = enumModules()
        local eipMod = "unknown"
        if mods then
            for _, m in ipairs(mods) do
                local mSize = getModuleSize(m.Name) or 0x2000000
                if EIP >= m.Address and EIP < m.Address + mSize then
                    eipMod = string.format("%s+0x%X", m.Name, EIP - m.Address)
                    break
                end
            end
        end
        print(string.format("  EIP 位置: %s", eipMod))

        -- 检查: EIP 是否在 TVM 区域 (0x1600000-0x1800000)?
        if EIP >= 0x1600000 and EIP <= 0x1800000 then
            print("  >>> 注意: EIP 在 TVM 保护区域内!")
            print("  >>> 这说明 TVM 直接操作队列, 没有调用独立的 push 函数")
        elseif EIP >= 0x400000 and EIP < 0x1200000 then
            print("  >>> EIP 在普通代码区!")
            print("  >>> 这是我们要找的 native push 函数!")
        end
        print("")

        -- EBP chain 调用栈
        print("  调用栈 (EBP chain):")
        local ebpVal = EBP
        for i = 1, 20 do
            if not ebpVal or ebpVal == 0 or ebpVal > 0x7FFFFFFF then break end
            local ret = readInteger(ebpVal + 4)
            if not ret or ret == 0 then break end

            local retMod = string.format("0x%08X", ret)
            if mods then
                for _, m in ipairs(mods) do
                    local mSize = getModuleSize(m.Name) or 0x2000000
                    if ret >= m.Address and ret < m.Address + mSize then
                        retMod = string.format("%s+0x%X (0x%08X)", m.Name, ret - m.Address, ret)
                        break
                    end
                end
            end

            -- 标记 TVM 区域
            local marker = ""
            if ret >= 0x1600000 and ret <= 0x1800000 then
                marker = " [TVM区域]"
            end
            print(string.format("    [%2d] %s%s", i, retMod, marker))

            local next = readInteger(ebpVal)
            if not next or next <= ebpVal then break end
            ebpVal = next
        end
        print("")

        -- ESP 栈扫描: 找可能的返回地址
        print("  ESP 栈扫描 (可能的返回地址):")
        local scanCount = 0
        for i = 0, 60 do
            local val = readInteger(ESP + i * 4)
            if val and val > 0x400000 and val < 0x1800000 then
                -- 检查是否可能是返回地址 (前面是 call 指令)
                local prevByte5 = readBytes(val - 5, 1)
                local prevByte2 = readBytes(val - 2, 1)
                local prevByte6 = readBytes(val - 6, 1)
                if prevByte5 == 0xE8 or prevByte2 == 0xFF or prevByte6 == 0xFF then
                    local valMod = string.format("0x%08X", val)
                    if mods then
                        for _, m in ipairs(mods) do
                            local mSize = getModuleSize(m.Name) or 0x2000000
                            if val >= m.Address and val < m.Address + mSize then
                                valMod = string.format("%s+0x%X", m.Name, val - m.Address)
                                break
                            end
                        end
                    end

                    local marker = ""
                    if val >= 0x1600000 and val <= 0x1800000 then
                        marker = " [TVM]"
                    end
                    print(string.format("    [ESP+0x%03X] %s%s", i*4, valMod, marker))
                    scanCount = scanCount + 1
                end
            end
        end
        if scanCount == 0 then
            print("    (无可疑返回地址)")
        end
        print("")

        -- 尝试读取刚入队的数据包
        local curBufPtr = readInteger(connObj + 0x170)
        local curWriteIdx = readInteger(connObj + 0x178)
        if curBufPtr and curBufPtr ~= 0 and curWriteIdx then
            -- 上一个 writeIndex 处的指针就是刚入队的包
            local prevIdx = curWriteIdx  -- 断点是写入后触发的, curWriteIdx 已更新
            -- 刚入队的包在 prevIdx-1 的位置
            local cap = readInteger(connObj + 0x17C) or 1
            local packetIdx = (curWriteIdx - 1 + cap) % cap
            local packetPtr = readInteger(curBufPtr + packetIdx * 4)
            if packetPtr and packetPtr ~= 0 then
                print(string.format("  刚入队的数据包指针: 0x%08X (index=%d)", packetPtr, packetIdx))
                -- dump 前 64 字节
                local bytes = readBytes(packetPtr, 64, true)
                if bytes then
                    local hex = ""
                    for j = 1, #bytes do
                        hex = hex .. string.format("%02X ", bytes[j])
                        if j % 16 == 0 then hex = hex .. "\n                  " end
                    end
                    print(string.format("  包头数据: %s", hex))

                    -- 解析包头 (16字节, 小端序, 发送线程会 htons 转换)
                    local headerSize = bytes[1] + bytes[2] * 256
                    local dataLen    = bytes[3] + bytes[4] * 256
                    local pktType    = bytes[5] + bytes[6] * 256
                    print(string.format("  解析: headerSize=%d, dataLen=%d, pktType=%d (0x%04X)",
                        headerSize, dataLen, pktType, pktType))
                    if pktType == 4368 then
                        print("  >>> 这是 SendWeddingStart 包!")
                    elseif pktType == 4364 then
                        print("  >>> 这是 ReserveWeddingDate 包!")
                    end
                end
            end
        end

        if hitCount >= maxHits then
            print(string.format(">>> 已收集 %d 次样本, 移除断点", maxHits))
            debug_removeBreakpoint(targetAddr)
        end

        return 1  -- 继续执行
    end)

    print("硬件写断点已设置!")
    print("现在请在游戏中操作 (移动/使用技能/抢婚礼 均可)")
    print(string.format("将收集 %d 次样本后自动停止", maxHits))
end

-- 手动检查队列状态
function checkQueue()
    local connObj = readInteger(0x1363D90)
    if not connObj or connObj == 0 then
        print("连接对象为空")
        return
    end

    local qBufPtr   = readInteger(connObj + 0x170)
    local qReadIdx  = readInteger(connObj + 0x174)
    local qWriteIdx = readInteger(connObj + 0x178)
    local qCapacity = readInteger(connObj + 0x17C)

    print(string.format("连接对象     = 0x%08X", connObj))
    print(string.format("队列 buffer  = 0x%08X", qBufPtr or 0))
    print(string.format("队列 readIdx = %d", qReadIdx or 0))
    print(string.format("队列 writeIdx= %d", qWriteIdx or 0))
    print(string.format("队列 capacity= %d", qCapacity or 0))

    -- 队列中有多少包
    if qCapacity and qCapacity > 0 then
        local count = (qWriteIdx - qReadIdx + qCapacity) % qCapacity
        print(string.format("队列中待发包 = %d", count))
    end

    -- 如果有包, dump 几个
    if qBufPtr and qBufPtr ~= 0 and qReadIdx and qWriteIdx and qCapacity then
        local count = (qWriteIdx - qReadIdx + qCapacity) % qCapacity
        local n = math.min(count, 5)
        for i = 0, n - 1 do
            local idx = (qReadIdx + i) % qCapacity
            local pktPtr = readInteger(qBufPtr + idx * 4)
            if pktPtr and pktPtr ~= 0 then
                local bytes = readBytes(pktPtr, 16, true)
                if bytes then
                    local hex = ""
                    for j = 1, #bytes do
                        hex = hex .. string.format("%02X ", bytes[j])
                    end
                    local pktType = bytes[5] + bytes[6] * 256
                    print(string.format("  [%d] ptr=0x%08X type=%d: %s", idx, pktPtr, pktType, hex))
                end
            end
        end
    end
end

-- 手动移除断点
function stopWatch()
    local connObj = readInteger(0x1363D90)
    if connObj and connObj ~= 0 then
        debug_removeBreakpoint(connObj + 0x178)
        print("断点已移除")
    end
end

print("")
print("命令:")
print("  findQueuePush() - 设置硬件写断点找push函数")
print("  checkQueue()    - 检查队列当前状态")
print("  stopWatch()     - 手动移除断点")
print("")
