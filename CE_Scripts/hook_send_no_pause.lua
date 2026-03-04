--[[
  CE Lua 脚本 v3: 用 Auto Assembler Hook send() — 不暂停线程
  ============================================================

  原理:
    不用 CE 调试器断点 (会暂停线程)
    而是用 Auto Assembler 在 send() 入口注入一小段汇编代码
    把 socket/len/caller/数据 写到共享内存区域
    Lua 用定时器轮询共享内存, 读取并打印

  优点:
    - 不暂停任何线程
    - 不依赖 CE 调试器
    - 性能开销极小 (几条 mov 指令)
    - 可以抓到每一次 send 调用的数据

  使用:
    1. CE 附加到游戏进程
    2. 执行此脚本
    3. 自动开始记录
    4. 触发发包, 观察输出
    5. 执行 unhook() 停止
]]

local LOG = "C:\\Users\\Administrator\\Desktop\\send_hook_v3.log"
local fLog = nil

local function log(msg)
    if not fLog then fLog = io.open(LOG, "w") end
    local s = string.format("[%s] %s", os.date("%H:%M:%S"), msg)
    print(s)
    if fLog then fLog:write(s .. "\n"); fLog:flush() end
end

-- ============================================================
-- 共享内存布局 (ringbuffer, 可存16条记录)
-- ============================================================
--[[
  offset  size  desc
  0x000   4     writeIndex (生产者递增)
  0x004   4     readIndex  (消费者递增)
  0x008   4     reserved
  0x00C   4     reserved
  0x010   ...   records[0..15], each 0x100 bytes:
    +0x00  4    socket
    +0x04  4    bufLen
    +0x08  4    callerAddr (返回地址 = 谁调用了send)
    +0x0C  4    bufPtr
    +0x10  64   前64字节的发送数据拷贝
    +0x50  4    timestamp (GetTickCount)
    +0x54  ...  padding
]]

local RECORD_SIZE = 0x100
local MAX_RECORDS = 16
local HEADER_SIZE = 0x10
local SHARED_SIZE = HEADER_SIZE + MAX_RECORDS * RECORD_SIZE  -- 0x1010

local sharedMem = nil
local hookInstalled = false
local timerObj = nil

-- ============================================================
-- 安装 hook
-- ============================================================
function install()
    if hookInstalled then
        log("Hook 已经安装, 先执行 unhook()")
        return
    end

    -- 分配共享内存
    sharedMem = allocateMemory(SHARED_SIZE)
    if not sharedMem or sharedMem == 0 then
        log("ERROR: 无法分配共享内存")
        return
    end

    -- 清零
    writeBytes(sharedMem, string.rep("\0", SHARED_SIZE))
    -- 初始化 writeIndex = 0, readIndex = 0
    writeInteger(sharedMem, 0)
    writeInteger(sharedMem + 4, 0)

    log(string.format("共享内存分配在 0x%08X (%d bytes)", sharedMem, SHARED_SIZE))

    -- 获取 send 地址
    local sendAddr = getAddress("ws2_32.send")
    if not sendAddr or sendAddr == 0 then
        log("ERROR: 找不到 ws2_32.send")
        deAlloc(sharedMem)
        return
    end
    log(string.format("ws2_32.send = 0x%08X", sendAddr))

    -- 获取 GetTickCount 地址 (用于记录时间戳)
    local gtcAddr = getAddress("kernel32.GetTickCount")
    log(string.format("kernel32.GetTickCount = 0x%08X", gtcAddr or 0))

    -- Auto Assembler: 在 send() 入口注入记录代码
    local aaScript = string.format([[
[enable]
alloc(sendHook, 512)
alloc(sendOrigBytes, 64)
label(sendReturn)

// 注册符号供 disable 使用
registersymbol(sendHook)
registersymbol(sendOrigBytes)

sendHook:
  // 保存所有寄存器 (不能破坏任何东西)
  pushad
  pushfd

  // 计算 writeIndex
  mov edi, 0x%X              // sharedMem 地址
  mov eax, [edi]             // writeIndex
  mov ecx, eax
  and ecx, 0xF               // index %% 16 (& 0xF)

  // 计算记录地址: edi + 0x10 + ecx * 0x100
  shl ecx, 8                 // ecx * 256
  add ecx, 0x10
  lea esi, [edi + ecx]       // esi = record ptr

  // 此时栈布局 (pushad+pushfd后):
  //   [esp+0x24] = 原始返回地址 (pushfd=4 + pushad=32 = 36 = 0x24)
  //   注意: send 的参数在 pushad 之前的栈上
  //   [esp+0x28] = socket   (原esp+4,  但pushad多了32, pushfd多了4)
  //   [esp+0x2C] = buf ptr  (原esp+8)
  //   [esp+0x30] = len      (原esp+12)
  //   [esp+0x34] = flags    (原esp+16)

  // 记录 socket
  mov edx, [esp+0x28]
  mov [esi+0x00], edx

  // 记录 bufLen
  mov edx, [esp+0x30]
  mov [esi+0x04], edx

  // 记录 caller (返回地址)
  mov edx, [esp+0x24]
  mov [esi+0x08], edx

  // 记录 bufPtr
  mov edx, [esp+0x2C]
  mov [esi+0x0C], edx

  // 拷贝前64字节数据
  push edi
  mov edi, esi
  add edi, 0x10              // dest = record + 0x10
  mov ecx, [esp+0x30+4]     // bufLen (+4 因为我们push了edi)
  cmp ecx, 64
  jle @f
  mov ecx, 64
@@:
  cmp ecx, 0
  jle skipCopy
  push esi
  mov esi, [esp+0x2C+8]     // bufPtr (+8 因为push edi + push esi)
  rep movsb
  pop esi
skipCopy:
  pop edi

  // 记录 GetTickCount
  push eax
  call 0x%X                  // GetTickCount
  mov [esi+0x50], eax
  pop eax                    // 恢复 writeIndex

  // 递增 writeIndex (原子操作)
  inc eax
  mov [edi], eax

  // 恢复寄存器
  popfd
  popad

  // 执行被覆盖的 send 原始指令, 然后跳回
  sendOrigBytes:
  db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0

sendReturn:
  jmp 0x%X

// ===== 修改 send 入口 =====
0x%X:
  jmp sendHook

[disable]
// 恢复原始字节
0x%X:
  db 0,0,0,0,0

unregistersymbol(sendHook)
unregistersymbol(sendOrigBytes)
dealloc(sendHook)
dealloc(sendOrigBytes)
]], sharedMem, gtcAddr or 0, sendAddr + 5, sendAddr, sendAddr)

    -- 先保存 send 的原始字节 (前5字节会被 jmp 覆盖)
    local origBytes = readBytes(sendAddr, 16, true)
    if not origBytes then
        log("ERROR: 无法读取 send 原始字节")
        deAlloc(sharedMem)
        return
    end

    local origHex = ""
    for i = 1, #origBytes do
        origHex = origHex .. string.format("%02X ", origBytes[i])
    end
    log(string.format("send 原始字节: %s", origHex))

    -- 手动方式: 用 code injection 代替复杂的 AA
    -- 更简单可靠: 直接写汇编 hook
    log("")
    log("使用简化 hook 方式...")

    -- 分配 hook 代码区域
    local hookMem = allocateMemory(512)
    if not hookMem or hookMem == 0 then
        log("ERROR: 无法分配 hook 内存")
        deAlloc(sharedMem)
        return
    end

    log(string.format("Hook 代码区域: 0x%08X", hookMem))

    -- 手动构建 hook 的机器码
    -- 简化版: 只记录 caller, socket, len, 和 hit counter
    -- 不拷贝数据 (避免复杂的 rep movsb)
    local code = {}
    local function emit(bytes) for _, b in ipairs(bytes) do table.insert(code, b) end end
    local function emit_dword(val)
        table.insert(code, val % 256)
        table.insert(code, math.floor(val / 0x100) % 256)
        table.insert(code, math.floor(val / 0x10000) % 256)
        table.insert(code, math.floor(val / 0x1000000) % 256)
    end

    -- pushad
    emit({0x60})
    -- pushfd
    emit({0x9C})

    -- mov edi, sharedMem
    emit({0xBF}); emit_dword(sharedMem)

    -- mov eax, [edi]        ; writeIndex
    emit({0x8B, 0x07})

    -- mov ecx, eax
    emit({0x89, 0xC1})
    -- and ecx, 0xF
    emit({0x83, 0xE1, 0x0F})
    -- shl ecx, 8            ; * 256
    emit({0xC1, 0xE1, 0x08})
    -- add ecx, 0x10         ; skip header
    emit({0x83, 0xC1, 0x10})
    -- lea esi, [edi+ecx]    ; record ptr
    emit({0x8D, 0x34, 0x0F})

    -- 栈布局: pushad(32) + pushfd(4) = 36 = 0x24 额外字节
    -- send 参数: [ESP+0x24]=retAddr, [ESP+0x28]=socket, [ESP+0x2C]=buf, [ESP+0x30]=len

    -- mov edx, [esp+0x28]   ; socket
    emit({0x8B, 0x54, 0x24, 0x28})
    -- mov [esi], edx
    emit({0x89, 0x16})

    -- mov edx, [esp+0x30]   ; len
    emit({0x8B, 0x54, 0x24, 0x30})
    -- mov [esi+4], edx
    emit({0x89, 0x56, 0x04})

    -- mov edx, [esp+0x24]   ; caller (return address)
    emit({0x8B, 0x54, 0x24, 0x24})
    -- mov [esi+8], edx
    emit({0x89, 0x56, 0x08})

    -- mov edx, [esp+0x2C]   ; bufPtr
    emit({0x8B, 0x54, 0x24, 0x2C})
    -- mov [esi+0xC], edx
    emit({0x89, 0x56, 0x0C})

    -- inc dword [edi]       ; writeIndex++
    emit({0xFF, 0x07})

    -- popfd
    emit({0x9D})
    -- popad
    emit({0x61})

    -- 执行被覆盖的原始指令 (send的前5字节)
    for i = 1, 5 do
        table.insert(code, origBytes[i])
    end

    -- jmp back to send+5
    emit({0xE9})
    local jmpTarget = (sendAddr + 5) - (hookMem + #code + 4)
    emit_dword(jmpTarget % 0x100000000)

    -- 写入 hook 代码
    writeBytes(hookMem, code)
    log(string.format("Hook 代码写入 %d 字节", #code))

    -- 现在修改 send 的前5字节: jmp hookMem
    -- 先解除页保护
    local jmpToHook = hookMem - (sendAddr + 5)

    -- 构建 jmp 指令
    local jmpBytes = {0xE9,
        jmpToHook % 256,
        math.floor(jmpToHook / 0x100) % 256,
        math.floor(jmpToHook / 0x10000) % 256,
        math.floor(jmpToHook / 0x1000000) % 256
    }

    writeBytes(sendAddr, jmpBytes)
    log(string.format("send 入口已重定向到 0x%08X", hookMem))

    hookInstalled = true
    _G._sendHookInfo = {
        sharedMem = sharedMem,
        hookMem = hookMem,
        sendAddr = sendAddr,
        origBytes = origBytes,
    }

    log("")
    log("Hook 安装成功! 不会暂停任何线程")
    log("现在开启轮询... (自动读取 send 记录)")
    log("")

    startPolling()
end


-- ============================================================
-- 轮询共享内存, 读取并打印 send 记录
-- ============================================================
local lastReadIndex = 0
local totalHits = 0
local callerStats = {}  -- 统计每个 caller 出现次数

function pollOnce()
    if not sharedMem then return end

    local writeIdx = readInteger(sharedMem) or 0

    while lastReadIndex < writeIdx do
        local idx = lastReadIndex % MAX_RECORDS
        local recAddr = sharedMem + HEADER_SIZE + idx * RECORD_SIZE

        local socket   = readInteger(recAddr + 0x00) or 0
        local bufLen   = readInteger(recAddr + 0x04) or 0
        local caller   = readInteger(recAddr + 0x08) or 0
        local bufPtr   = readInteger(recAddr + 0x0C) or 0

        totalHits = totalHits + 1

        -- 获取 caller 所属模块
        local callerMod = "?"
        local mods = enumModules()
        if mods then
            for _, m in ipairs(mods) do
                local mSize = getModuleSize(m.Name) or 0x1000000
                if caller >= m.Address and caller < m.Address + mSize then
                    callerMod = string.format("%s+0x%X", m.Name, caller - m.Address)
                    break
                end
            end
        end

        -- 统计 caller
        local callerKey = string.format("0x%08X", caller)
        callerStats[callerKey] = (callerStats[callerKey] or 0) + 1

        -- 尝试读取发送数据 (bufPtr 可能已经被释放, 用 pcall 保护)
        local dataHex = ""
        if bufPtr ~= 0 and bufLen > 0 then
            local ok, bytes = pcall(readBytes, bufPtr, math.min(bufLen, 32), true)
            if ok and bytes then
                for j = 1, #bytes do
                    dataHex = dataHex .. string.format("%02X ", bytes[j])
                end
            else
                dataHex = "(数据已释放)"
            end
        end

        log(string.format("[send #%d] socket=%d len=%d caller=%s (%s)",
            totalHits, socket, bufLen, callerKey, callerMod))
        if dataHex ~= "" then
            log(string.format("  data: %s", dataHex))
        end

        lastReadIndex = lastReadIndex + 1
    end
end

function startPolling()
    if timerObj then return end
    lastReadIndex = 0
    totalHits = 0
    callerStats = {}

    timerObj = createTimer(nil, false)
    timerObj.Interval = 100  -- 每100ms轮询一次
    timerObj.OnTimer = function(t)
        pollOnce()
    end
    timerObj.Enabled = true

    log("轮询已启动 (每100ms)")
end

function stopPolling()
    if timerObj then
        timerObj.Enabled = false
        timerObj.Destroy()
        timerObj = nil
    end
    log("轮询已停止")
end


-- ============================================================
-- 打印 caller 统计 (找出谁在调 send)
-- ============================================================
function callerReport()
    log("============ Caller 统计 ============")
    log(string.format("总计 %d 次 send 调用", totalHits))

    -- 按次数排序
    local sorted = {}
    for addr, count in pairs(callerStats) do
        table.insert(sorted, {addr = addr, count = count})
    end
    table.sort(sorted, function(a, b) return a.count > b.count end)

    for i, entry in ipairs(sorted) do
        local addr = tonumber(entry.addr)
        local modName = "?"
        if addr then
            local mods = enumModules()
            if mods then
                for _, m in ipairs(mods) do
                    local mSize = getModuleSize(m.Name) or 0x1000000
                    if addr >= m.Address and addr < m.Address + mSize then
                        modName = string.format("%s+0x%X", m.Name, addr - m.Address)
                        break
                    end
                end
            end
        end
        log(string.format("  %s (%s): %d 次", entry.addr, modName, entry.count))
    end

    log("")
    log(">>> 出现最多的 caller 就是发送线程调用 send 的位置")
    log(">>> 从那个地址往上追踪就能找到 发送队列 和 入队函数")
end


-- ============================================================
-- 卸载 hook
-- ============================================================
function unhook()
    log("卸载 hook...")

    -- 停止轮询
    stopPolling()

    -- 恢复 send 原始字节
    if _G._sendHookInfo then
        local info = _G._sendHookInfo
        writeBytes(info.sendAddr, info.origBytes[1], info.origBytes[2],
                   info.origBytes[3], info.origBytes[4], info.origBytes[5])
        log(string.format("send (0x%08X) 原始字节已恢复", info.sendAddr))

        -- 等待一小会确保没有线程还在执行 hook 代码
        sleep(100)

        -- 释放内存
        if info.hookMem then deAlloc(info.hookMem) end
        if info.sharedMem then deAlloc(info.sharedMem) end

        sharedMem = nil
        hookInstalled = false
        _G._sendHookInfo = nil
    end

    -- 最终统计
    callerReport()

    if fLog then fLog:close(); fLog = nil end
    log("Hook 已完全卸载")
end


-- ============================================================
-- 启动
-- ============================================================
print("")
print("==============================================")
print("  QQSG send() Hook v3 (无暂停版)")
print("==============================================")
print("  install()       - 安装 hook 并开始记录")
print("  callerReport()  - 查看 caller 统计")
print("  unhook()        - 卸载 hook 并恢复原始代码")
print("==============================================")
print("  日志: " .. LOG)
print("==============================================")
print("")
print("执行 install() 开始...")
