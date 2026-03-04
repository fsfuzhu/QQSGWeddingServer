--[[
  CE Lua 脚本: 寻找绕过 TVM 的快速发包路径
  =============================================

  目标: 找到 TVM 内部最终调用的 native 发送函数，
        或者直接找到 socket + 封包格式，实现直连发包

  执行顺序:
    Step 1: hookSendAndWinsock()  - 同时 hook wrapper 和 Winsock
    Step 2: 在游戏里触发一次婚礼发包
    Step 3: 查看输出，获取完整调用链和封包数据
    Step 4: 分析结果，决定最佳绕过方案
]]

local LOG_FILE = "C:\\Users\\Administrator\\Desktop\\fast_send_trace.log"
local logFile = nil
local breakpoints = {}

local function log(msg)
    if not logFile then logFile = io.open(LOG_FILE, "w") end
    local line = string.format("[%s] %s", os.date("%H:%M:%S"), msg)
    print(line)
    if logFile then logFile:write(line .. "\n"); logFile:flush() end
end

local function getModName(addr)
    local mods = enumModules()
    if mods then
        for _, m in ipairs(mods) do
            if addr >= m.Address and addr < m.Address + m.Size then
                return string.format("%s+0x%X", m.Name, addr - m.Address)
            end
        end
    end
    return string.format("0x%08X", addr)
end

-- 记录 EBP-chain 调用栈
local function walkStack(maxFrames)
    local frames = {}
    local ebpVal = EBP
    local espVal = ESP

    -- 先从 ESP 读返回地址
    local retFromEsp = readInteger(espVal)
    if retFromEsp and retFromEsp > 0x10000 then
        table.insert(frames, {ret = retFromEsp, ebp = espVal, src = "ESP"})
    end

    -- EBP chain walk
    for i = 1, maxFrames do
        if not ebpVal or ebpVal == 0 or ebpVal == 0xFFFFFFFF then break end
        local retAddr = readInteger(ebpVal + 4)
        if not retAddr or retAddr == 0 then break end
        table.insert(frames, {ret = retAddr, ebp = ebpVal, src = "EBP"})
        local nextEbp = readInteger(ebpVal)
        if not nextEbp or nextEbp <= ebpVal then break end
        ebpVal = nextEbp
    end
    return frames
end

-- ============================================================
-- 核心函数: 同时 Hook SendPacket wrapper + Winsock send
-- ============================================================
function hookSendAndWinsock()
    log("========================================")
    log("  Step 1: Hook 发包 wrapper + Winsock")
    log("========================================")

    local wrapperAddr  = 0x609F60  -- SendWeddingStart thin wrapper
    local wrapperAddr2 = 0x609F20  -- ReserveWeddingDate thin wrapper

    -- === Hook ws2_32.send ===
    local sendAddr = getAddress("ws2_32.send")
    local wsaSendAddr = getAddress("ws2_32.WSASend")

    log(string.format("ws2_32.send    = 0x%08X", sendAddr or 0))
    log(string.format("ws2_32.WSASend = 0x%08X", wsaSendAddr or 0))

    -- 标记: 是否来自婚礼发包
    local inWeddingPacket = false
    local packetStartTick = 0

    -- Hook wrapper 0x609F60 (入口)
    log(string.format("Hook wrapper 0x609F60..."))
    debug_setBreakpoint(wrapperAddr)
    debug_setBreakpoint(wrapperAddr, 1, bptExecute,
        function()
            inWeddingPacket = true
            packetStartTick = getTickCount()
            log(">>> [婚礼包4368] wrapper 进入")
            log(string.format("    dword_1363D90 = 0x%08X", readInteger(0x1363D90) or 0))
            return 1
        end
    )
    table.insert(breakpoints, wrapperAddr)

    -- Hook wrapper 0x609F60 返回点 (0x609F7B 后面)
    -- call [vtable] 在 0x609F7B, 返回后的下一条指令
    local wrapperRet = 0x609F80  -- call 之后
    debug_setBreakpoint(wrapperRet)
    debug_setBreakpoint(wrapperRet, 1, bptExecute,
        function()
            if inWeddingPacket then
                local elapsed = getTickCount() - packetStartTick
                log(string.format(">>> [婚礼包4368] wrapper 返回, 耗时 %d ms", elapsed))
                inWeddingPacket = false
            end
            return 1
        end
    )
    table.insert(breakpoints, wrapperRet)

    -- Hook ws2_32.send (最底层)
    if sendAddr and sendAddr ~= 0 then
        log("Hook ws2_32.send()...")
        debug_setBreakpoint(sendAddr)
        debug_setBreakpoint(sendAddr, 1, bptExecute,
            function()
                local socket = readInteger(ESP + 4)
                local bufPtr = readInteger(ESP + 8)
                local bufLen = readInteger(ESP + 12)
                local retAddr = readInteger(ESP)

                log("=== ws2_32.send() ===")
                log(string.format("    socket = %d (0x%X)", socket, socket))
                log(string.format("    len    = %d", bufLen))
                log(string.format("    caller = %s", getModName(retAddr)))

                if inWeddingPacket then
                    log("    >>> 这是婚礼包的 send 调用!")
                end

                -- dump 发送数据
                if bufPtr and bufPtr ~= 0 and bufLen > 0 then
                    local dumpLen = math.min(bufLen, 128)
                    local bytes = readBytes(bufPtr, dumpLen, true)
                    if bytes then
                        local hex = "    data: "
                        for j = 1, #bytes do
                            hex = hex .. string.format("%02X ", bytes[j])
                            if j % 32 == 0 and j < #bytes then
                                hex = hex .. "\n          "
                            end
                        end
                        log(hex)
                    end
                end

                -- 完整调用栈 - 这是最关键的信息
                log("    调用栈 (从底层到顶层):")
                local frames = walkStack(15)
                for i, f in ipairs(frames) do
                    log(string.format("      [%2d] %s  (from %s)", i, getModName(f.ret), f.src))
                end

                return 1
            end
        )
        table.insert(breakpoints, sendAddr)
    end

    -- Hook ws2_32.WSASend
    if wsaSendAddr and wsaSendAddr ~= 0 then
        log("Hook ws2_32.WSASend()...")
        debug_setBreakpoint(wsaSendAddr)
        debug_setBreakpoint(wsaSendAddr, 1, bptExecute,
            function()
                local socket = readInteger(ESP + 4)
                local bufArrayPtr = readInteger(ESP + 8)
                local bufCount = readInteger(ESP + 12)
                local retAddr = readInteger(ESP)

                log("=== ws2_32.WSASend() ===")
                log(string.format("    socket    = %d (0x%X)", socket, socket))
                log(string.format("    bufCount  = %d", bufCount))
                log(string.format("    caller    = %s", getModName(retAddr)))

                if inWeddingPacket then
                    log("    >>> 这是婚礼包的 WSASend 调用!")
                end

                -- WSABUF 结构: {ULONG len; char* buf}
                if bufArrayPtr and bufArrayPtr ~= 0 then
                    for i = 0, bufCount - 1 do
                        local bLen = readInteger(bufArrayPtr + i * 8)
                        local bPtr = readInteger(bufArrayPtr + i * 8 + 4)
                        if bPtr and bLen and bLen > 0 then
                            local dumpLen = math.min(bLen, 128)
                            local bytes = readBytes(bPtr, dumpLen, true)
                            if bytes then
                                local hex = string.format("    buf[%d] len=%d: ", i, bLen)
                                for j = 1, #bytes do
                                    hex = hex .. string.format("%02X ", bytes[j])
                                end
                                log(hex)
                            end
                        end
                    end
                end

                -- 调用栈
                log("    调用栈:")
                local frames = walkStack(15)
                for i, f in ipairs(frames) do
                    log(string.format("      [%2d] %s", i, getModName(f.ret)))
                end

                return 1
            end
        )
        table.insert(breakpoints, wsaSendAddr)
    end

    log("")
    log("所有 Hook 已就绪!")
    log("请在游戏中触发一次婚礼发包，然后查看输出")
    log("关键信息: send() 的调用栈会揭示 TVM 之后的所有中间函数")
    log("")
end


-- ============================================================
-- Step 2: 分析 send() 调用栈，找到 TVM 之后的第一个 native 函数
-- 用户运行 hookSendAndWinsock() 并触发发包后,
-- 调用此函数分析结果
-- ============================================================
function analyzeTraceResults()
    log("========================================")
    log("  Step 2: 分析追踪结果")
    log("========================================")
    log("")
    log("请检查上面 send()/WSASend() 的调用栈输出。")
    log("调用栈应该类似于:")
    log("")
    log("  [1] ws2_32.send             ← Winsock 发送")
    log("  [2] game.exe+0x??????       ← 封包加密/序列化")
    log("  [3] game.exe+0x??????       ← 发送缓冲区管理")
    log("  [4] game.exe+0x??????       ← TVM native 出口 ← 这就是我们要的!")
    log("  [5] TVM 区域 (0x16x/0x17x)  ← TVM 虚拟机内部")
    log("  [6] game.exe+0x609F7B       ← wrapper 的 call [vtable]")
    log("")
    log("目标: 找到 [4] 的地址 — 这是 TVM 退出后调用的第一个 native 函数")
    log("如果直接调用 [4]，就能跳过整个 TVM 开销!")
    log("")
    log("另外注意 [2] — 如果封包没有加密，我们甚至可以直接用 send()")
end


-- ============================================================
-- Step 3: 测试绕过方案
-- 一旦找到了 native 发送函数, 测试直接调用它
-- ============================================================
function testDirectCall(nativeFuncAddr)
    if not nativeFuncAddr then
        log("ERROR: 请提供 native 函数地址")
        log("用法: testDirectCall(0xXXXXXXXX)")
        return
    end

    log("========================================")
    log(string.format("  Step 3: 测试直接调用 0x%08X", nativeFuncAddr))
    log("========================================")

    -- 读取连接对象
    local connObj = readInteger(0x1363D90)
    if not connObj or connObj == 0 then
        log("ERROR: 连接对象为空!")
        return
    end

    log(string.format("连接对象 = 0x%08X", connObj))

    -- 获取 state (TVM 要求 state==4)
    local state = readInteger(connObj + 0x198)
    log(string.format("当前 state = %d (需要==4)", state or -1))

    -- 构造婚礼包4368的数据 (1字节 0x00)
    local dataAddr = allocateMemory(16)
    writeBytes(dataAddr, 0x00)

    log(string.format("数据地址 = 0x%08X", dataAddr))
    log("")
    log("准备调用... (需要知道参数格式)")
    log("可能的调用格式:")
    log(string.format("  __thiscall: func(0x%08X, 4368, 0x%08X, 1)", connObj, dataAddr))
    log("")
    log("请先用 hookSendAndWinsock() 确认参数格式后再测试!")

    -- 释放临时内存
    -- deAlloc(dataAddr)  -- 暂时保留用于测试
end


-- ============================================================
-- 辅助: 扫描游戏进程中所有已加载模块，找 send/WSASend 的 IAT
-- ============================================================
function scanImports()
    log("========================================")
    log("  扫描所有模块的 Winsock 导入")
    log("========================================")

    local mods = enumModules()
    if not mods then
        log("ERROR: 无法枚举模块")
        return
    end

    for _, mod in ipairs(mods) do
        log(string.format("模块: %s (0x%08X, %dKB)", mod.Name, mod.Address, mod.Size/1024))
    end

    -- 搜索所有模块中对 ws2_32.send 的引用
    local sendAddr = getAddress("ws2_32.send")
    if sendAddr and sendAddr ~= 0 then
        log(string.format("\n搜索对 send() (0x%08X) 的 IAT 引用...", sendAddr))

        -- 扫描所有可能的 IAT 区域 (通常在 .idata/.rdata 段)
        local results = AOBScan(string.format("%02X %02X %02X %02X",
            sendAddr % 256,
            math.floor(sendAddr / 256) % 256,
            math.floor(sendAddr / 65536) % 256,
            math.floor(sendAddr / 16777216) % 256))

        if results then
            local count = stringlist_getCount(results)
            log(string.format("找到 %d 处引用:", count))
            for i = 0, math.min(count - 1, 20) do
                local addr = getAddressFromStringlist(results, i)
                log(string.format("  0x%08X (%s)", addr, getModName(addr)))
            end
            object_destroy(results)
        else
            log("未找到直接引用 (可能是 GetProcAddress 动态获取)")
        end
    end
end


-- ============================================================
-- 辅助: 测量直接调用 SendPacket 与 Winsock send 的时间差
-- ============================================================
function benchmarkPaths()
    log("========================================")
    log("  性能基准测试")
    log("========================================")

    -- 在 wrapper 入口和 send() 分别计时
    local wrapperEnterTime = 0
    local sendEnterTime = 0
    local measurements = {}

    -- hook wrapper
    debug_setBreakpoint(0x609F60)
    debug_setBreakpoint(0x609F60, 1, bptExecute,
        function()
            wrapperEnterTime = getTickCount()
            return 1
        end
    )
    table.insert(breakpoints, 0x609F60)

    -- hook send
    local sendAddr = getAddress("ws2_32.send")
    if sendAddr and sendAddr ~= 0 then
        debug_setBreakpoint(sendAddr)
        debug_setBreakpoint(sendAddr, 1, bptExecute,
            function()
                sendEnterTime = getTickCount()
                if wrapperEnterTime > 0 then
                    local tvmTime = sendEnterTime - wrapperEnterTime
                    table.insert(measurements, tvmTime)
                    log(string.format("  TVM开销: %d ms (#%d)", tvmTime, #measurements))

                    if #measurements >= 10 then
                        local sum = 0
                        for _, v in ipairs(measurements) do sum = sum + v end
                        log(string.format("  === 平均TVM开销: %.1f ms (共%d次) ===",
                            sum / #measurements, #measurements))
                    end
                end
                wrapperEnterTime = 0
                return 1
            end
        )
        table.insert(breakpoints, sendAddr)
    end

    log("基准测试已就绪，请连续触发10+次发包")
end


-- ============================================================
-- 清理
-- ============================================================
function cleanup()
    for _, addr in ipairs(breakpoints) do
        pcall(debug_removeBreakpoint, addr)
    end
    breakpoints = {}
    if logFile then logFile:close(); logFile = nil end
    log("清理完成")
end


-- ============================================================
-- 菜单
-- ============================================================
print("==============================================")
print("  QQSG 快速发包路径分析工具")
print("==============================================")
print("  推荐执行顺序:")
print("  1. hookSendAndWinsock()    -- Hook所有层")
print("  2. 游戏里触发发包")
print("  3. analyzeTraceResults()   -- 分析调用栈")
print("  4. benchmarkPaths()        -- 测量TVM开销")
print("  5. scanImports()           -- 扫描Winsock导入")
print("  ---")
print("  cleanup()                  -- 清理断点")
print("==============================================")
print("  日志: " .. LOG_FILE)
print("==============================================")
