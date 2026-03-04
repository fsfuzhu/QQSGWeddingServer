--[[
  CE Lua: 用硬件写断点找到入队函数
  =====================================

  原理:
    发送线程读 connObj+0x188 来判断有没有待发数据
    游戏主线程通过 TVM → 某个native函数 写入 connObj+0x188
    我们在 connObj+0x188 设硬件写断点
    断下时就在入队函数里, 看 callstack 就知道是哪个函数

  注意:
    这会暂停游戏主线程 (不是发送线程)
    暂停一次就够了, 记录完 callstack 立刻移除断点继续
]]

function findEnqueue()
    print("============================================")
    print("  寻找入队函数 (硬件写断点)")
    print("============================================")

    -- 附加调试器
    pcall(debugProcess)

    -- 读取连接对象
    local connObj = readInteger(0x1363D90)
    if not connObj or connObj == 0 then
        print("ERROR: 连接对象为空! 请确保已登录游戏")
        return
    end

    local targetAddr = connObj + 0x188
    print(string.format("连接对象 = 0x%08X", connObj))
    print(string.format("监控地址 = 0x%08X (connObj+0x188 = 发送缓冲区长度)", targetAddr))

    -- 当前值
    local curLen = readInteger(targetAddr)
    print(string.format("当前待发长度 = %d", curLen or 0))
    print("")
    print("设置硬件写断点...")
    print("触发发包后会断下, 自动记录callstack然后继续")
    print("")

    -- 硬件写断点 (bptWrite = 2, size = 4 for dword)
    debug_setBreakpoint(targetAddr, 4, bptWrite, function()
        local newLen = readInteger(targetAddr)
        print("=== 硬件写断点触发! ===")
        print(string.format("  EIP = 0x%08X", EIP))
        print(string.format("  新的待发长度 = %d", newLen or 0))
        print(string.format("  EAX = 0x%08X", EAX))
        print(string.format("  ECX = 0x%08X", ECX))
        print(string.format("  EDX = 0x%08X", EDX))
        print(string.format("  ESI = 0x%08X", ESI))
        print(string.format("  EDI = 0x%08X", EDI))

        -- 获取 EIP 所在函数
        local mods = enumModules()
        local eipMod = "unknown"
        if mods then
            for _, m in ipairs(mods) do
                local mSize = getModuleSize(m.Name) or 0x1000000
                if EIP >= m.Address and EIP < m.Address + mSize then
                    eipMod = string.format("%s+0x%X", m.Name, EIP - m.Address)
                    break
                end
            end
        end
        print(string.format("  EIP 位置: %s", eipMod))

        -- EBP chain 调用栈
        print("  调用栈:")
        local ebpVal = EBP
        for i = 1, 15 do
            if not ebpVal or ebpVal == 0 or ebpVal > 0x7FFFFFFF then break end
            local ret = readInteger(ebpVal + 4)
            if not ret or ret == 0 then break end

            local retMod = string.format("0x%08X", ret)
            if mods then
                for _, m in ipairs(mods) do
                    local mSize = getModuleSize(m.Name) or 0x1000000
                    if ret >= m.Address and ret < m.Address + mSize then
                        retMod = string.format("%s+0x%X (0x%08X)", m.Name, ret - m.Address, ret)
                        break
                    end
                end
            end
            print(string.format("    [%2d] %s", i, retMod))

            local next = readInteger(ebpVal)
            if not next or next <= ebpVal then break end
            ebpVal = next
        end

        -- ESP-based stack scan (备用: 如果EBP chain不完整)
        print("  ESP栈扫描 (可能的返回地址):")
        for i = 0, 30 do
            local val = readInteger(ESP + i * 4)
            if val and val > 0x400000 and val < 0x1800000 then
                -- 检查前面是否是 call 指令
                local prevByte = readBytes(val - 5, 1)
                local prevByte2 = readBytes(val - 2, 1)
                if prevByte == 0xE8 or prevByte2 == 0xFF then
                    local valMod = string.format("0x%08X", val)
                    if mods then
                        for _, m in ipairs(mods) do
                            local mSize = getModuleSize(m.Name) or 0x1000000
                            if val >= m.Address and val < m.Address + mSize then
                                valMod = string.format("%s+0x%X", m.Name, val - m.Address)
                                break
                            end
                        end
                    end
                    print(string.format("    [ESP+0x%02X] %s", i*4, valMod))
                end
            end
        end

        print("")
        print(">>> 记录完成! 移除断点, 游戏继续运行")
        print(">>> EIP 就是写入 connObj+0x188 的指令")
        print(">>> 调用栈里 QQSG.exe 的地址就是入队函数链")

        -- 移除断点
        debug_removeBreakpoint(targetAddr)

        return 1  -- 继续执行
    end)

    print("硬件写断点已设置!")
    print("现在请触发一次发包 (开DLL抢婚礼 或 在游戏里做任何操作)")
end

-- 也提供手动检查当前缓冲区状态的函数
function checkBuffer()
    local connObj = readInteger(0x1363D90)
    if not connObj or connObj == 0 then
        print("连接对象为空")
        return
    end

    local socket    = readInteger(connObj + 0x120)
    local bufPtr    = readInteger(connObj + 0x180)
    local pendLen   = readInteger(connObj + 0x188)
    local state     = readInteger(connObj + 0x198)

    print(string.format("连接对象 = 0x%08X", connObj))
    print(string.format("  socket(+0x120)      = %d", socket or 0))
    print(string.format("  bufPtr(+0x180)      = 0x%08X", bufPtr or 0))
    print(string.format("  pendingLen(+0x188)  = %d", pendLen or 0))
    print(string.format("  state(+0x198)       = %d (需==4)", state or 0))

    -- 如果有待发数据, dump前64字节
    if bufPtr and bufPtr ~= 0 and pendLen and pendLen > 0 then
        local n = math.min(pendLen, 64)
        local bytes = readBytes(bufPtr, n, true)
        if bytes then
            local hex = ""
            for j = 1, #bytes do
                hex = hex .. string.format("%02X ", bytes[j])
                if j % 16 == 0 then hex = hex .. "\n                         " end
            end
            print(string.format("  缓冲区数据[%d]: %s", pendLen, hex))
        end
    end
end

print("")
print("命令:")
print("  findEnqueue()  - 设置硬件写断点找入队函数")
print("  checkBuffer()  - 检查当前发送缓冲区状态")
print("")
