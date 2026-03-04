--[[
  CE Lua 脚本 v2: 寻找绕过 TVM 的快速发包路径 (修复版)
  =========================================================

  修复:
    1. 移除所有无回调的 debug_setBreakpoint 调用 (之前导致游戏冻结)
    2. 添加 debugProcess() 确保调试器已附加
    3. 添加诊断 hook (GetState) 验证断点系统工作正常
    4. 覆盖更多网络API: send, WSASend, WSASendTo, NtDeviceIoControlFile

  使用方法:
    1. CE 附加到游戏进程
    2. 在 CE Lua Engine 中执行此脚本 (整个文件)
    3. 脚本会自动执行诊断
    4. 按提示调用函数

  注意: 你的 DLL 直接调用 0x173D98E, 不经过 0x609F60 wrapper
        所以我们 hook TVM 内部的 GetState + 网络层
]]

-- ============================================================
-- 初始化
-- ============================================================
local LOG = "C:\\Users\\Administrator\\Desktop\\fast_send_v2.log"
local fLog = nil
local bpList = {}

local function log(msg)
    if not fLog then fLog = io.open(LOG, "w") end
    local s = string.format("[%s] %s", os.date("%H:%M:%S"), msg)
    print(s)
    if fLog then fLog:write(s .. "\n"); fLog:flush() end
end

local function toBP(addr, size, trigger, fn)
    -- 只用一次调用, 带回调, 不会冻结游戏
    debug_setBreakpoint(addr, size or 1, trigger or bptExecute, fn)
    table.insert(bpList, addr)
    return true
end

local function getModName(addr)
    if not addr or addr == 0 then return "NULL" end
    local mods = enumModules()
    if mods then
        for _, m in ipairs(mods) do
            if addr >= m.Address and addr < m.Address + (getModuleSize(m.Name) or 0x1000000) then
                return string.format("%s+0x%X", m.Name, addr - m.Address)
            end
        end
    end
    return string.format("0x%08X", addr)
end

-- EBP chain 调用栈
local function getCallStack(maxFrames)
    local result = {}
    -- 从 ESP 读返回地址
    local espRet = readInteger(ESP)
    if espRet and espRet > 0x10000 then
        table.insert(result, {addr = espRet, src = "[ESP]"})
    end
    -- EBP chain
    local bp = EBP
    for i = 1, (maxFrames or 12) do
        if not bp or bp == 0 or bp > 0x7FFFFFFF then break end
        local ret = readInteger(bp + 4)
        if not ret or ret == 0 then break end
        table.insert(result, {addr = ret, src = string.format("[EBP+%d]", i)})
        local next = readInteger(bp)
        if not next or next <= bp then break end
        bp = next
    end
    return result
end

-- ============================================================
-- 清理 (先定义, 后面用)
-- ============================================================
function cleanup()
    log("清理所有断点...")
    for _, addr in ipairs(bpList) do
        pcall(debug_removeBreakpoint, addr)
    end
    bpList = {}
    if fLog then fLog:close(); fLog = nil end
    print("清理完成")
end

-- 先清理可能存在的旧断点
pcall(cleanup)
fLog = nil  -- 重新开始日志

-- ============================================================
-- Step 0: 诊断 - 确保调试器和断点工作
-- ============================================================
function diagnose()
    log("============ 诊断 ============")

    -- 检查进程
    local pid = getOpenedProcessID()
    log(string.format("进程 PID = %d (0x%X)", pid, pid))
    if pid == 0 then
        log("ERROR: 没有打开进程! 请先在CE中附加到游戏进程")
        return false
    end

    -- 检查关键地址可读性
    local addrs = {
        {0x1363D90, "连接对象指针"},
        {0xAF5C10,  "GetState函数"},
        {0x609F60,  "婚礼wrapper"},
        {0x173D98E, "SendPacket TVM入口"},
    }

    for _, a in ipairs(addrs) do
        local val = readInteger(a[1])
        if val then
            log(string.format("  [OK] 0x%08X (%s) = 0x%08X", a[1], a[2], val))
        else
            log(string.format("  [FAIL] 0x%08X (%s) = 不可读!", a[1], a[2]))
        end
    end

    -- 检查连接对象状态
    local connObj = readInteger(0x1363D90)
    if connObj and connObj ~= 0 then
        local state = readInteger(connObj + 0x198)
        log(string.format("  连接对象 0x%08X, state(+0x198) = %s",
            connObj, state and tostring(state) or "不可读"))
        local vtable = readInteger(connObj)
        if vtable then
            local vf0 = readInteger(vtable)
            log(string.format("  vtable = 0x%08X, vtable[0] = 0x%08X", vtable, vf0 or 0))
        end
    end

    -- 检查 ws2_32
    local sendAddr = getAddress("ws2_32.send")
    local wsaSendAddr = getAddress("ws2_32.WSASend")
    log(string.format("  ws2_32.send    = 0x%08X", sendAddr or 0))
    log(string.format("  ws2_32.WSASend = 0x%08X", wsaSendAddr or 0))

    -- 尝试附加调试器
    log("  尝试附加调试器...")
    local ok, err = pcall(function()
        debugProcess()
    end)
    if ok then
        log("  [OK] 调试器已附加")
    else
        log("  [WARN] debugProcess: " .. tostring(err))
        log("  (如果已附加则忽略此警告)")
    end

    -- 测试断点: 在 GetState 设一个一次性断点
    log("")
    log("设置测试断点 (GetState 0xAF5C10)...")
    log("这个函数在每次 SendPacket 时都会被 TVM 调用")

    local testHit = false
    toBP(0xAF5C10, 1, bptExecute, function()
        if not testHit then
            testHit = true
            log(">>> [诊断OK] GetState 断点触发!")
            log(string.format("    ECX(this) = 0x%08X", ECX))
            local state = readInteger(ECX + 0x198)
            log(string.format("    state     = %s", state and tostring(state) or "?"))
            log(string.format("    返回地址  = 0x%08X (%s)", readInteger(ESP) or 0, getModName(readInteger(ESP))))
            -- 移除测试断点, 避免影响性能
            debug_removeBreakpoint(0xAF5C10)
            log("    (测试断点已自动移除)")
            log("")
            log("诊断通过! 现在可以运行 hookAll()")
        end
        return 1  -- 继续执行, 不暂停
    end)

    log("测试断点已设置, 请触发一次发包 (开启DLL的抢婚礼)")
    log("如果10秒内看到 '诊断OK' 消息, 说明断点系统正常")
    log("")
    return true
end


-- ============================================================
-- Step 1: Hook 所有关键函数
-- ============================================================
local hitCount = {}

function hookAll()
    log("============ 设置所有 Hook ============")

    -- 先清理旧断点
    for _, addr in ipairs(bpList) do
        pcall(debug_removeBreakpoint, addr)
    end
    bpList = {}

    -- 确保调试器附加
    pcall(debugProcess)

    -- -------------------------------------------------------
    -- Hook 1: GetState (0xAF5C10)
    -- TVM 每次 SendPacket 都会调用, 验证发包确实在执行
    -- -------------------------------------------------------
    hitCount.getState = 0
    toBP(0xAF5C10, 1, bptExecute, function()
        hitCount.getState = hitCount.getState + 1
        -- 只打印前5次, 避免刷屏
        if hitCount.getState <= 5 then
            local retAddr = readInteger(ESP) or 0
            log(string.format("[GetState #%d] ECX=0x%08X ret=0x%08X (%s) state=%s",
                hitCount.getState, ECX, retAddr, getModName(retAddr),
                tostring(readInteger(ECX + 0x198))))
        elseif hitCount.getState == 6 then
            log("[GetState] 后续调用省略... (已确认工作)")
        end
        return 1
    end)
    log("  [1/4] GetState (0xAF5C10) - OK")

    -- -------------------------------------------------------
    -- Hook 2: ws2_32.send
    -- -------------------------------------------------------
    local sendAddr = getAddress("ws2_32.send")
    if sendAddr and sendAddr ~= 0 then
        hitCount.send = 0
        toBP(sendAddr, 1, bptExecute, function()
            hitCount.send = hitCount.send + 1
            local socket = readInteger(ESP + 4) or 0
            local bufPtr = readInteger(ESP + 8) or 0
            local bufLen = readInteger(ESP + 12) or 0
            local retAddr = readInteger(ESP) or 0

            log(string.format("[send #%d] socket=%d len=%d caller=%s",
                hitCount.send, socket, bufLen, getModName(retAddr)))

            -- dump 前64字节数据
            if bufPtr ~= 0 and bufLen > 0 then
                local n = math.min(bufLen, 64)
                local bytes = readBytes(bufPtr, n, true)
                if bytes then
                    local hex = ""
                    for j = 1, #bytes do hex = hex .. string.format("%02X ", bytes[j]) end
                    log("  data: " .. hex)
                end
            end

            -- 调用栈 (最关键!)
            log("  调用栈:")
            local stack = getCallStack(12)
            for i, f in ipairs(stack) do
                log(string.format("    %s %s", f.src, getModName(f.addr)))
            end

            return 1
        end)
        log(string.format("  [2/4] ws2_32.send (0x%08X) - OK", sendAddr))
    else
        log("  [2/4] ws2_32.send - 未找到!")
    end

    -- -------------------------------------------------------
    -- Hook 3: ws2_32.WSASend
    -- -------------------------------------------------------
    local wsaSendAddr = getAddress("ws2_32.WSASend")
    if wsaSendAddr and wsaSendAddr ~= 0 then
        hitCount.wsaSend = 0
        toBP(wsaSendAddr, 1, bptExecute, function()
            hitCount.wsaSend = hitCount.wsaSend + 1
            local socket = readInteger(ESP + 4) or 0
            local bufArrayPtr = readInteger(ESP + 8) or 0
            local bufCount = readInteger(ESP + 12) or 0
            local retAddr = readInteger(ESP) or 0

            log(string.format("[WSASend #%d] socket=%d bufCount=%d caller=%s",
                hitCount.wsaSend, socket, bufCount, getModName(retAddr)))

            -- dump WSABUF 数据
            if bufArrayPtr ~= 0 and bufCount > 0 then
                for i = 0, math.min(bufCount - 1, 3) do
                    local bLen = readInteger(bufArrayPtr + i * 8) or 0
                    local bPtr = readInteger(bufArrayPtr + i * 8 + 4) or 0
                    if bPtr ~= 0 and bLen > 0 then
                        local n = math.min(bLen, 64)
                        local bytes = readBytes(bPtr, n, true)
                        if bytes then
                            local hex = ""
                            for j = 1, #bytes do hex = hex .. string.format("%02X ", bytes[j]) end
                            log(string.format("  buf[%d] len=%d: %s", i, bLen, hex))
                        end
                    end
                end
            end

            -- 调用栈
            log("  调用栈:")
            local stack = getCallStack(12)
            for i, f in ipairs(stack) do
                log(string.format("    %s %s", f.src, getModName(f.addr)))
            end

            return 1
        end)
        log(string.format("  [3/4] ws2_32.WSASend (0x%08X) - OK", wsaSendAddr))
    else
        log("  [3/4] ws2_32.WSASend - 未找到!")
    end

    -- -------------------------------------------------------
    -- Hook 4: ntdll.NtDeviceIoControlFile (最底层)
    -- 如果 send/WSASend 都没触发, 可能走这里
    -- -------------------------------------------------------
    local ntdllSend = getAddress("ntdll.NtDeviceIoControlFile")
    if ntdllSend and ntdllSend ~= 0 then
        hitCount.ntIo = 0
        toBP(ntdllSend, 1, bptExecute, function()
            hitCount.ntIo = hitCount.ntIo + 1
            -- 只记录前3次, 这个函数调用非常频繁
            if hitCount.ntIo <= 3 then
                local retAddr = readInteger(ESP) or 0
                log(string.format("[NtDeviceIoControlFile #%d] caller=%s",
                    hitCount.ntIo, getModName(retAddr)))
                log("  调用栈:")
                local stack = getCallStack(8)
                for i, f in ipairs(stack) do
                    log(string.format("    %s %s", f.src, getModName(f.addr)))
                end
            elseif hitCount.ntIo == 4 then
                log("[NtDeviceIoControlFile] 太频繁, 移除hook...")
                debug_removeBreakpoint(ntdllSend)
            end
            return 1
        end)
        log(string.format("  [4/4] NtDeviceIoControlFile (0x%08X) - OK", ntdllSend))
    else
        log("  [4/4] NtDeviceIoControlFile - 未找到")
    end

    log("")
    log("所有 Hook 已设置!")
    log("现在请触发发包 (开启DLL抢婚礼 或 在游戏里手动操作)")
    log("观察哪些 hook 被触发, 特别关注调用栈")
    log("")
end


-- ============================================================
-- 统计函数 - 查看各 hook 命中次数
-- ============================================================
function stats()
    log("============ Hook 命中统计 ============")
    for name, count in pairs(hitCount) do
        log(string.format("  %s: %d 次", name, count))
    end
    if hitCount.getState and hitCount.getState > 0
       and (not hitCount.send or hitCount.send == 0)
       and (not hitCount.wsaSend or hitCount.wsaSend == 0) then
        log("")
        log(">>> GetState 触发但 send/WSASend 都没触发!")
        log(">>> 可能原因:")
        log("    1. 发包是异步的 (先入队列, 后面统一send)")
        log("    2. state != 4, TVM直接返回没真正发包")
        log("    3. 游戏用了其他网络API")
        log("")
        log("建议: 检查 state 值, 运行 checkState()")
    end
end


-- ============================================================
-- 检查连接状态
-- ============================================================
function checkState()
    local connObj = readInteger(0x1363D90)
    if not connObj or connObj == 0 then
        log("ERROR: 连接对象为空!")
        return
    end
    local state = readInteger(connObj + 0x198)
    log(string.format("连接对象 = 0x%08X", connObj))
    log(string.format("state(+0x198) = %d", state or -1))
    if state == 4 then
        log("state==4: TVM 会执行发包路径")
    else
        log(string.format("state==%d: TVM 会直接返回! 不会真正发包!", state or -1))
        log("这就是为什么 send/WSASend 没触发的原因!")
    end
end


-- ============================================================
-- 快捷: 只 hook 网络层 (不 hook GetState, 减少干扰)
-- ============================================================
function hookNetOnly()
    log("============ 只 Hook 网络层 ============")
    pcall(debugProcess)

    local sendAddr = getAddress("ws2_32.send")
    local wsaSendAddr = getAddress("ws2_32.WSASend")

    if sendAddr and sendAddr ~= 0 then
        hitCount.send = 0
        toBP(sendAddr, 1, bptExecute, function()
            hitCount.send = hitCount.send + 1
            local socket = readInteger(ESP + 4) or 0
            local bufLen = readInteger(ESP + 12) or 0
            local retAddr = readInteger(ESP) or 0
            log(string.format("[send #%d] socket=%d len=%d caller=%s",
                hitCount.send, socket, bufLen, getModName(retAddr)))
            -- 调用栈
            local stack = getCallStack(12)
            for i, f in ipairs(stack) do
                log(string.format("  %s %s", f.src, getModName(f.addr)))
            end
            return 1
        end)
        log(string.format("  send (0x%08X) - OK", sendAddr))
    end

    if wsaSendAddr and wsaSendAddr ~= 0 then
        hitCount.wsaSend = 0
        toBP(wsaSendAddr, 1, bptExecute, function()
            hitCount.wsaSend = hitCount.wsaSend + 1
            local socket = readInteger(ESP + 4) or 0
            local retAddr = readInteger(ESP) or 0
            log(string.format("[WSASend #%d] socket=%d caller=%s",
                hitCount.wsaSend, socket, getModName(retAddr)))
            local stack = getCallStack(12)
            for i, f in ipairs(stack) do
                log(string.format("  %s %s", f.src, getModName(f.addr)))
            end
            return 1
        end)
        log(string.format("  WSASend (0x%08X) - OK", wsaSendAddr))
    end

    log("网络层 Hook 就绪, 请操作游戏 (任何操作都行, 比如走路/打开背包)")
    log("这能确认游戏的网络发送到底走哪个 API")
end


-- ============================================================
-- 自动执行诊断
-- ============================================================
print("")
print("==============================================")
print("  QQSG 快速发包分析 v2 (修复版)")
print("==============================================")
print("  命令:")
print("    diagnose()    - 诊断 (自动执行)")
print("    hookAll()     - Hook 全部层")
print("    hookNetOnly() - 只 Hook 网络层")
print("    stats()       - 查看命中统计")
print("    checkState()  - 检查连接状态")
print("    cleanup()     - 清理断点")
print("==============================================")
print("  日志: " .. LOG)
print("==============================================")
print("")

-- 自动运行诊断
diagnose()
