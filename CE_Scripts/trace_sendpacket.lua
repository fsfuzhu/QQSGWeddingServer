--[[
  CE Lua 脚本: 追踪 SendPacket TVM 内部的真正发包函数
  =======================================================

  目标:
    1. 找到 TVM (0x173D98E) 内部最终调用的 native 发包函数
    2. 找到实际的 socket send 调用
    3. 记录完整的调用链

  使用方法:
    1. 用 CE 附加到 QQSG 游戏进程
    2. 在 CE Lua 引擎中执行此脚本
    3. 在游戏中触发一次发包（比如手动点婚礼按钮）
    4. 查看输出的调用链

  原理:
    TVM 的 v_exit 指令会退出虚拟机并 call 真正的 native 函数
    我们在 v_exit 的目标位置设断点，记录调用栈
]]

-- ============================================================
-- 配置区
-- ============================================================
local SEND_PACKET_TVM   = 0x173D98E   -- TVM保护的SendPacket入口
local CONN_OBJ_ADDR     = 0x1363D90   -- 连接对象指针地址
local WEDDING_WRAPPER   = 0x609F60    -- SendWeddingStart 的thin wrapper
local RESERVE_WRAPPER   = 0x609F20    -- ReserveWeddingDate 的thin wrapper

-- TVM 内部已知的 native 调用目标
local GET_STATE_FUNC    = 0xAF5C10    -- GetState(this) - TVM Block2 调用的
local RETURN_STUB       = 0xAF5590    -- TVM Branch1 返回桩 (retn 0x0C)

local LOG_FILE = "C:\\Users\\Administrator\\Desktop\\sendpacket_trace.log"

-- ============================================================
-- 工具函数
-- ============================================================
local logFile = nil

local function logMsg(msg)
    if not logFile then
        logFile = io.open(LOG_FILE, "a")
    end
    local line = string.format("[%s] %s", os.date("%H:%M:%S"), msg)
    print(line)
    if logFile then
        logFile:write(line .. "\n")
        logFile:flush()
    end
end

local function readDword(addr)
    if addr == 0 or addr == nil then return 0 end
    return readInteger(addr) or 0
end

local function getModuleName(addr)
    local modules = enumModules()
    if modules then
        for i, mod in ipairs(modules) do
            if addr >= mod.Address and addr < mod.Address + mod.Size then
                return mod.Name
            end
        end
    end
    return "unknown"
end

-- ============================================================
-- 脚本1: 分析连接对象的 vtable
-- 找出 vtable[0] 的真正地址（运行时）
-- ============================================================
function analyzeConnectionObject()
    logMsg("========== 分析连接对象 ==========")

    local connObjPtr = readDword(CONN_OBJ_ADDR)
    logMsg(string.format("连接对象指针 [0x%08X] = 0x%08X", CONN_OBJ_ADDR, connObjPtr))

    if connObjPtr == 0 then
        logMsg("ERROR: 连接对象为空，请确保已登录游戏")
        return
    end

    local vtablePtr = readDword(connObjPtr)
    logMsg(string.format("VTable指针 [0x%08X] = 0x%08X", connObjPtr, vtablePtr))

    -- 读取前30个vtable条目
    logMsg("VTable 条目:")
    for i = 0, 29 do
        local entry = readDword(vtablePtr + i * 4)
        local modName = getModuleName(entry)
        logMsg(string.format("  vtable[%2d] = 0x%08X  (%s)", i, entry, modName))
    end

    -- 特别关注 vtable[0] - 这应该是 SendPacket
    local sendFunc = readDword(vtablePtr)
    logMsg(string.format("\n>>> vtable[0] (SendPacket) = 0x%08X", sendFunc))
    if sendFunc == SEND_PACKET_TVM then
        logMsg(">>> 确认: vtable[0] == 0x173D98E (TVM保护)")
    else
        logMsg(string.format(">>> 注意: vtable[0] != 0x173D98E, 实际是 0x%08X!", sendFunc))
        logMsg(">>> 这可能是一个非TVM的发送函数!")
    end

    -- 读取连接对象的关键字段
    logMsg("\n连接对象内存dump (前0x200字节关键偏移):")
    local offsets = {0x0, 0x4, 0x8, 0xC, 0x10, 0x14, 0x18, 0x1C,
                     0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90,
                     0x100, 0x110, 0x120, 0x130, 0x140, 0x150, 0x160,
                     0x170, 0x180, 0x190, 0x198, 0x1A0, 0x1B0, 0x1C0}
    for _, off in ipairs(offsets) do
        local val = readDword(connObjPtr + off)
        logMsg(string.format("  +0x%03X = 0x%08X (%d)", off, val, val))
    end

    -- 特别关注 field_0x198 (state字段, TVM检查这个)
    local state = readDword(connObjPtr + 0x198)
    logMsg(string.format("\n>>> field_0x198 (state) = %d  (TVM要求==4才发包)", state))
end


-- ============================================================
-- 脚本2: Hook vtable[0] 入口和 TVM v_exit 点
-- 追踪 TVM 退出后调用的 native 函数
-- ============================================================
local breakpoints = {}

function traceNativeCalls()
    logMsg("========== 追踪 TVM native 调用 ==========")

    -- 方案A: 在 GetState (0xAF5C10) 设断点
    -- TVM Block2 会调用这个函数, 我们可以看到调用栈
    logMsg("在 GetState (0xAF5C10) 设断点...")
    local bp1 = debug_setBreakpoint(GET_STATE_FUNC)
    if bp1 then
        debug_setBreakpoint(GET_STATE_FUNC, 1, bptExecute,
            function(bp)
                logMsg("=== GetState 被调用 ===")
                logMsg(string.format("  ECX (this) = 0x%08X", ECX))
                logMsg(string.format("  返回地址   = 0x%08X", readDword(ESP)))

                -- 打印调用栈
                local sp = ESP
                logMsg("  调用栈:")
                for i = 0, 15 do
                    local retAddr = readDword(sp + i * 4)
                    if retAddr > 0x400000 and retAddr < 0x2000000 then
                        local modName = getModuleName(retAddr)
                        logMsg(string.format("    [ESP+%02X] = 0x%08X (%s)", i*4, retAddr, modName))
                    end
                end

                return 1 -- 继续执行 (不暂停)
            end
        )
        table.insert(breakpoints, GET_STATE_FUNC)
    end

    -- 方案B: 在返回桩 (0xAF5590) 设断点
    -- TVM Branch1 (state!=4) 会跳到这里
    logMsg("在返回桩 (0xAF5590) 设断点...")
    debug_setBreakpoint(RETURN_STUB)
    debug_setBreakpoint(RETURN_STUB, 1, bptExecute,
        function(bp)
            logMsg("=== 返回桩被调用 (state != 4, 发包被跳过!) ===")
            logMsg(string.format("  ESP = 0x%08X", ESP))
            return 1
        end
    )
    table.insert(breakpoints, RETURN_STUB)

    logMsg("断点已设置，请触发一次发包操作...")
end


-- ============================================================
-- 脚本3: 监控所有 call 指令 (通过单步追踪)
-- 更激进的方案: 在 TVM wrapper (0x609F60) 设断点,
-- 然后单步追踪记录所有 call 目标
-- ============================================================
local callTrace = {}
local tracing = false
local traceCount = 0
local MAX_TRACE = 50000  -- 最多追踪5万条指令

function startCallTrace()
    logMsg("========== 开始 Call 追踪 ==========")
    logMsg(string.format("在 wrapper 0x%08X 设断点...", WEDDING_WRAPPER))

    debug_setBreakpoint(WEDDING_WRAPPER)
    debug_setBreakpoint(WEDDING_WRAPPER, 1, bptExecute,
        function(bp)
            logMsg("=== SendWeddingStart wrapper 被调用 ===")
            logMsg("开始单步追踪...")
            tracing = true
            traceCount = 0
            callTrace = {}

            -- 开启单步模式
            debug_continueFromBreakpoint(cycsSingleStep)
            return 2  -- 返回2表示自己处理了continue
        end
    )
    table.insert(breakpoints, WEDDING_WRAPPER)

    -- 注册单步回调
    debug_setBreakpoint(0, 0, bptSingleStep,
        function(bp)
            if not tracing then return 1 end

            traceCount = traceCount + 1

            if traceCount > MAX_TRACE then
                logMsg(string.format("追踪达到上限 %d 条，停止", MAX_TRACE))
                tracing = false
                dumpCallTrace()
                return 1
            end

            -- 读取当前指令
            local eipVal = EIP
            local byte1 = readBytes(eipVal, 1)

            -- 检测 call 指令 (0xE8 = call rel32, 0xFF = call [reg/mem])
            if byte1 == 0xE8 then
                -- call rel32
                local offset = readInteger(eipVal + 1)
                local target = (eipVal + 5 + offset) % 0x100000000
                local modName = getModuleName(target)
                table.insert(callTrace, {
                    from = eipVal,
                    target = target,
                    type = "call_rel32",
                    module = modName,
                    step = traceCount
                })
                logMsg(string.format("  [%5d] CALL 0x%08X -> 0x%08X (%s)",
                    traceCount, eipVal, target, modName))

            elseif byte1 == 0xFF then
                local byte2 = readBytes(eipVal + 1, 1)
                local modrm_reg = math.floor(byte2 / 8) % 8
                if modrm_reg == 2 or modrm_reg == 3 then  -- call [r/m] or call far [r/m]
                    table.insert(callTrace, {
                        from = eipVal,
                        target = 0,  -- indirect, 需要看寄存器
                        type = "call_indirect",
                        step = traceCount
                    })
                end
            end

            -- 检测 ret 指令 (看是否从TVM函数返回了)
            if byte1 == 0xC3 or byte1 == 0xC2 then
                -- 检查返回后的地址是否在 wrapper 范围内
                local retTo = readDword(ESP)
                if retTo >= WEDDING_WRAPPER and retTo <= WEDDING_WRAPPER + 0x30 then
                    logMsg("=== SendPacket 返回到 wrapper! 追踪完成 ===")
                    tracing = false
                    dumpCallTrace()
                    return 1
                end
            end

            debug_continueFromBreakpoint(cycsSingleStep)
            return 2
        end
    )

    logMsg("Call 追踪已就绪，请触发一次发包...")
end

function dumpCallTrace()
    logMsg(string.format("\n========== Call 追踪结果 (%d 个 call) ==========", #callTrace))
    for i, entry in ipairs(callTrace) do
        logMsg(string.format("  #%d [step %d] %s: 0x%08X -> 0x%08X (%s)",
            i, entry.step, entry.type, entry.from, entry.target, entry.module or ""))
    end
    logMsg("==========  追踪结束 ==========")
end


-- ============================================================
-- 脚本4: 监控 Winsock send/WSASend 调用
-- 不管TVM内部怎么走，最终都要调用 Winsock
-- ============================================================
function hookWinsock()
    logMsg("========== Hook Winsock 发送函数 ==========")

    -- 获取 ws2_32.dll 中 send 和 WSASend 的地址
    local ws2 = getAddress("ws2_32.dll")
    if not ws2 or ws2 == 0 then
        logMsg("ws2_32.dll 未加载，尝试加载...")
        -- ws2_32 可能还没加载
        ws2 = getModuleBase("ws2_32.dll")
    end

    local sendAddr = getAddress("ws2_32.send")
    local wsaSendAddr = getAddress("ws2_32.WSASend")

    logMsg(string.format("ws2_32.dll base   = 0x%08X", ws2 or 0))
    logMsg(string.format("ws2_32.send       = 0x%08X", sendAddr or 0))
    logMsg(string.format("ws2_32.WSASend    = 0x%08X", wsaSendAddr or 0))

    if sendAddr and sendAddr ~= 0 then
        logMsg("在 send() 设断点...")
        debug_setBreakpoint(sendAddr)
        debug_setBreakpoint(sendAddr, 1, bptExecute,
            function(bp)
                -- send(SOCKET s, const char* buf, int len, int flags)
                local socket = readDword(ESP + 4)
                local bufPtr = readDword(ESP + 8)
                local bufLen = readDword(ESP + 12)
                local flags  = readDword(ESP + 16)
                local retAddr = readDword(ESP)

                logMsg("=== ws2_32.send() 被调用 ===")
                logMsg(string.format("  socket  = 0x%08X", socket))
                logMsg(string.format("  buf     = 0x%08X", bufPtr))
                logMsg(string.format("  len     = %d", bufLen))
                logMsg(string.format("  flags   = %d", flags))
                logMsg(string.format("  返回到  = 0x%08X (%s)", retAddr, getModuleName(retAddr)))

                -- dump前32字节的发送数据
                if bufPtr ~= 0 and bufLen > 0 then
                    local dumpLen = math.min(bufLen, 64)
                    local bytes = readBytes(bufPtr, dumpLen, true)
                    if bytes then
                        local hex = ""
                        for j = 1, #bytes do
                            hex = hex .. string.format("%02X ", bytes[j])
                            if j % 16 == 0 then hex = hex .. "\n          " end
                        end
                        logMsg(string.format("  数据[%d]: %s", bufLen, hex))
                    end
                end

                -- 打印调用栈 (关键！找出从哪里调用的send)
                logMsg("  调用栈:")
                local ebpVal = EBP
                for i = 0, 10 do
                    local retAddress = readDword(ebpVal + 4)
                    if retAddress and retAddress > 0x10000 then
                        local modName = getModuleName(retAddress)
                        logMsg(string.format("    frame[%d] ret=0x%08X (%s)", i, retAddress, modName))
                    end
                    local nextEbp = readDword(ebpVal)
                    if not nextEbp or nextEbp == 0 or nextEbp <= ebpVal then break end
                    ebpVal = nextEbp
                end

                return 1 -- 继续执行
            end
        )
        table.insert(breakpoints, sendAddr)
    end

    if wsaSendAddr and wsaSendAddr ~= 0 then
        logMsg("在 WSASend() 设断点...")
        debug_setBreakpoint(wsaSendAddr)
        debug_setBreakpoint(wsaSendAddr, 1, bptExecute,
            function(bp)
                local socket = readDword(ESP + 4)
                local retAddr = readDword(ESP)

                logMsg("=== ws2_32.WSASend() 被调用 ===")
                logMsg(string.format("  socket  = 0x%08X", socket))
                logMsg(string.format("  返回到  = 0x%08X (%s)", retAddr, getModuleName(retAddr)))

                -- 调用栈
                logMsg("  调用栈:")
                local ebpVal = EBP
                for i = 0, 10 do
                    local retAddress = readDword(ebpVal + 4)
                    if retAddress and retAddress > 0x10000 then
                        logMsg(string.format("    frame[%d] ret=0x%08X (%s)", i, retAddress, getModuleName(retAddress)))
                    end
                    local nextEbp = readDword(ebpVal)
                    if not nextEbp or nextEbp == 0 or nextEbp <= ebpVal then break end
                    ebpVal = nextEbp
                end

                return 1
            end
        )
        table.insert(breakpoints, wsaSendAddr)
    end

    logMsg("Winsock Hook 已就绪，请触发发包...")
end


-- ============================================================
-- 脚本5: 寻找 socket 句柄
-- 扫描连接对象内存，找到 SOCKET 值
-- ============================================================
function findSocket()
    logMsg("========== 寻找 Socket 句柄 ==========")

    local connObjPtr = readDword(CONN_OBJ_ADDR)
    if connObjPtr == 0 then
        logMsg("ERROR: 连接对象为空")
        return
    end

    -- 方法1: 枚举进程的所有socket句柄
    -- CE没有直接API，但可以通过 NtQuerySystemInformation 间接实现
    -- 这里用简单方法: 扫描连接对象内存中可能的socket值

    logMsg(string.format("扫描连接对象 0x%08X 的内存 (0x400字节)...", connObjPtr))

    -- socket通常是小整数值 (< 0x10000) 且不为0
    local possibleSockets = {}
    for off = 0, 0x3FC, 4 do
        local val = readDword(connObjPtr + off)
        if val > 0 and val < 0x10000 then
            table.insert(possibleSockets, {offset = off, value = val})
        end
    end

    logMsg(string.format("发现 %d 个可能的 socket 值:", #possibleSockets))
    for _, s in ipairs(possibleSockets) do
        logMsg(string.format("  +0x%03X = 0x%04X (%d)", s.offset, s.value, s.value))
    end

    logMsg("\n提示: 用 Winsock hook (hookWinsock) 确认哪个是真正的 socket")
end


-- ============================================================
-- 脚本6: 测量 SendPacket TVM 的执行时间
-- 精确测量每次调用的耗时
-- ============================================================
function measureSendTime()
    logMsg("========== 测量 SendPacket 耗时 ==========")

    local enterTime = 0
    local measurements = {}

    -- 在 wrapper 入口设断点
    debug_setBreakpoint(WEDDING_WRAPPER)
    debug_setBreakpoint(WEDDING_WRAPPER, 1, bptExecute,
        function(bp)
            enterTime = os.clock()
            -- 读取返回地址，在那设断点
            local retAddr = readDword(ESP)

            -- 设一次性断点在返回处
            debug_setBreakpoint(retAddr)
            debug_setBreakpoint(retAddr, 1, bptExecute,
                function(bp2)
                    local elapsed = (os.clock() - enterTime) * 1000  -- ms
                    table.insert(measurements, elapsed)
                    logMsg(string.format("  SendPacket 耗时: %.3f ms (第%d次)", elapsed, #measurements))

                    -- 10次后打印统计
                    if #measurements >= 10 then
                        local sum = 0
                        local minVal, maxVal = 999999, 0
                        for _, v in ipairs(measurements) do
                            sum = sum + v
                            if v < minVal then minVal = v end
                            if v > maxVal then maxVal = v end
                        end
                        logMsg(string.format("\n  统计(%d次): 平均=%.3fms 最小=%.3fms 最大=%.3fms",
                            #measurements, sum/#measurements, minVal, maxVal))
                    end

                    debug_removeBreakpoint(retAddr)
                    return 1
                end
            )
            return 1
        end
    )
    table.insert(breakpoints, WEDDING_WRAPPER)

    logMsg("计时器已就绪，请多次触发发包（至少10次）来收集数据...")
end


-- ============================================================
-- 脚本7: 直接追踪 TVM v_exit 目标
-- TVM v_exit 会恢复原生寄存器并 ret 到 native 函数
-- 我们在 TVM dispatcher 的 v_exit handler 设断点
-- ============================================================
function findTvmExitTargets()
    logMsg("========== 追踪 TVM v_exit 目标 ==========")
    logMsg("方案: 在已知的 TVM 重入点设断点")

    -- 从 TVM 解码文件中，我们知道:
    -- Block2 v_exit 后返回到 0x174A4D1 (Block3的TVM stub)
    -- Sub-Branch B v_exit 后 native函数返回到 0x01741B40
    -- Sub-Branch B 调用的是 VM_REG 中保存的某个 native 函数

    -- 策略: 在 0x174A4D1 设断点 (Block3入口)
    -- 此时 EAX = GetState() 的返回值
    -- 然后在 state==4 的分支中追踪后续 v_exit

    local tvmBlock3Stub = 0x174A4D1
    logMsg(string.format("在 TVM Block3 stub (0x%08X) 设断点...", tvmBlock3Stub))

    debug_setBreakpoint(tvmBlock3Stub)
    debug_setBreakpoint(tvmBlock3Stub, 1, bptExecute,
        function(bp)
            logMsg("=== TVM Block3 进入 ===")
            logMsg(string.format("  EAX (state) = %d", EAX))
            logMsg(string.format("  ECX = 0x%08X", ECX))
            logMsg(string.format("  EDX = 0x%08X", EDX))

            if EAX == 4 then
                logMsg("  >>> state==4, 将进入 Branch2 (发包路径)")
            else
                logMsg("  >>> state!=4, 将进入 Branch1 (直接返回)")
            end
            return 1
        end
    )
    table.insert(breakpoints, tvmBlock3Stub)

    -- 在 Sub-Branch B 的 VEH 重入点附近设断点
    -- 0x173FDCD 是异常入口，VEH 重定向到 0x173FDDA
    local subBranchBEntry = 0x173FDDA  -- VEH重定向后的实际代码
    logMsg(string.format("在 Sub-Branch B 实际入口 (0x%08X) 设断点...", subBranchBEntry))

    debug_setBreakpoint(subBranchBEntry)
    debug_setBreakpoint(subBranchBEntry, 1, bptExecute,
        function(bp)
            logMsg("=== Sub-Branch B 进入 (将调用 native 发包函数) ===")
            logMsg(string.format("  EAX = 0x%08X", EAX))
            logMsg(string.format("  ECX = 0x%08X", ECX))
            logMsg(string.format("  EDX = 0x%08X", EDX))
            logMsg(string.format("  EBX = 0x%08X", EBX))
            logMsg(string.format("  ESI = 0x%08X", ESI))
            logMsg(string.format("  EDI = 0x%08X", EDI))
            logMsg(string.format("  ESP = 0x%08X", ESP))
            logMsg(string.format("  EBP = 0x%08X", EBP))

            -- dump 栈顶32个dword (可能包含native函数地址)
            logMsg("  栈数据:")
            for i = 0, 31 do
                local val = readDword(ESP + i * 4)
                local modName = getModuleName(val)
                local marker = ""
                if val > 0x400000 and val < 0x2000000 then
                    marker = " <-- 可能是函数地址 (" .. modName .. ")"
                end
                logMsg(string.format("    [ESP+%02X] = 0x%08X%s", i*4, val, marker))
            end
            return 1
        end
    )
    table.insert(breakpoints, subBranchBEntry)

    -- 在 native 函数返回后的 TVM 重入点设断点
    local nativeReturnPoint = 0x1741B40
    logMsg(string.format("在 native 返回重入点 (0x%08X) 设断点...", nativeReturnPoint))

    debug_setBreakpoint(nativeReturnPoint)
    debug_setBreakpoint(nativeReturnPoint, 1, bptExecute,
        function(bp)
            logMsg("=== Native 函数已返回, TVM 重入 ===")
            logMsg(string.format("  EAX (native返回值) = 0x%08X", EAX))
            logMsg("  >>> 此时 native 发包函数已经执行完毕")
            return 1
        end
    )
    table.insert(breakpoints, nativeReturnPoint)

    logMsg("TVM Exit 追踪已就绪，请触发一次发包...")
end


-- ============================================================
-- 清理函数
-- ============================================================
function cleanup()
    logMsg("========== 清理断点 ==========")
    for _, addr in ipairs(breakpoints) do
        debug_removeBreakpoint(addr)
        logMsg(string.format("  移除断点: 0x%08X", addr))
    end
    breakpoints = {}
    tracing = false
    if logFile then
        logFile:close()
        logFile = nil
    end
    logMsg("清理完成")
end


-- ============================================================
-- 主菜单
-- ============================================================
function showMenu()
    print("==================================================")
    print("  QQSG SendPacket 分析工具")
    print("==================================================")
    print("  1. analyzeConnectionObject()  - 分析连接对象和vtable")
    print("  2. hookWinsock()              - Hook ws2_32.send/WSASend")
    print("  3. findTvmExitTargets()       - 追踪TVM内部native调用")
    print("  4. measureSendTime()          - 测量SendPacket耗时")
    print("  5. findSocket()               - 搜索socket句柄")
    print("  6. startCallTrace()           - 完整call追踪(慢)")
    print("  7. traceNativeCalls()         - 轻量级native调用追踪")
    print("  8. cleanup()                  - 清理所有断点")
    print("==================================================")
    print("  日志文件: " .. LOG_FILE)
    print("  建议执行顺序: 1 → 2 → 3 → 4")
    print("==================================================")
end

showMenu()
