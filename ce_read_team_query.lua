-- =====================================================
-- CE Lua: 读取 打怪地图查询 玩家数据
-- =====================================================
-- 数据源: CTeamQueryMgr this[76] (offset +0x130/+0x134)
--   访问路径: [[[[0x1351620]+4]+0x0C]+0xC4]+0x130
--   bufBegin = this[76], bufEnd = this[77]
--   元素大小: 44字节 (内联数组, 非指针)
--
-- MapTeamQueryEntry 结构 (44 bytes):
--   +0x00: char szPlayerName[32]  玩家名 (GBK)
--   +0x20: DWORD nLevel           等级
--   +0x24: DWORD flags            bit0=bIsInviting, bit2=bIsLeader
--   +0x28: BYTE  nTeamMemNum      队伍人数 (0=没组队)
--   +0x29: BYTE  statusFlags      bit0=bHasDouble(双倍), bit1=bHasQixin(齐心)
--   +0x2A: BYTE  nJob             职业字节
--   +0x2B: BYTE  nNation          国家 (0=无,1=吴,2=蜀,3=魏)
--
-- nJob 编码: bits[3:0]=基础职业ID, bits[5:4]=进阶等级(tier)
--   tier=0: 基础职业, tier=1: 一转, tier=2: 二转
--   职业名通过 sub_842BE0 从游戏内存表读取
--
-- 来源函数: GetMonsterMapPlayerInfo (sub_65F0E0)
-- 收包: 0x0173D98E (TVM保护)
-- =====================================================

local ENTRY_SIZE = 44  -- 0x2C
local NationNames = { [0]="无", [1]="吴", [2]="蜀", [3]="魏" }

-- 进阶职业名表地址 (sub_842BE0 使用)
local ADV_JOB_TABLE = 0xDDF96C
-- 基础职业名地址 (switch case in sub_842BE0)
local BASE_JOB_ADDRS = {
    [1] = 0x10D4A1C,  -- 将士
    [2] = 0x10D4A14,  -- 豪杰
    [3] = 0x10D4A0C,  -- 阴阳士
    [4] = 0x10D4A04,  -- 仙术士
    [5] = 0x10D49FC,  -- 游侠
    [6] = 0x10D49F4,  -- 幻灵
}

-- GBK → UTF-8 转换 (用于CE控制台正确显示中文)
local function gbkToUtf8(gbkStr)
    if gbkStr == nil or gbkStr == "" then return "" end
    -- 优先用CE内置函数 (系统code page需为936/GBK)
    if ansiToUtf8 then
        local ok, result = pcall(ansiToUtf8, gbkStr)
        if ok and result then return result end
    end
    -- 备用: 调用Windows API MultiByteToWideChar + WideCharToMultiByte
    if executeCodeEx then
        local gbkBuf = allocateMemory(#gbkStr + 1)
        if gbkBuf then
            writeString(gbkBuf, gbkStr)
            -- GBK(936) → UTF-16
            local wideLen = executeCodeEx(0, nil, 'kernel32.MultiByteToWideChar',
                936, 0, gbkBuf, #gbkStr, 0, 0)
            if wideLen > 0 then
                local wideBuf = allocateMemory(wideLen * 2 + 2)
                if wideBuf then
                    executeCodeEx(0, nil, 'kernel32.MultiByteToWideChar',
                        936, 0, gbkBuf, #gbkStr, wideBuf, wideLen)
                    -- UTF-16 → UTF-8
                    local utf8Len = executeCodeEx(0, nil, 'kernel32.WideCharToMultiByte',
                        65001, 0, wideBuf, wideLen, 0, 0, 0, 0)
                    if utf8Len > 0 then
                        local utf8Buf = allocateMemory(utf8Len + 1)
                        if utf8Buf then
                            executeCodeEx(0, nil, 'kernel32.WideCharToMultiByte',
                                65001, 0, wideBuf, wideLen, utf8Buf, utf8Len, 0, 0)
                            local result = readString(utf8Buf, utf8Len)
                            deAlloc(utf8Buf)
                            deAlloc(wideBuf)
                            deAlloc(gbkBuf)
                            return result or gbkStr
                        end
                    end
                    deAlloc(wideBuf)
                end
            end
            deAlloc(gbkBuf)
        end
    end
    return gbkStr  -- 无法转换, 返回原始字节
end

-- 读取GBK字符串并转为UTF-8
local function readGBKString(addr, maxLen)
    if addr == 0 or addr == nil then return "" end
    local bytes = readBytes(addr, maxLen, true)
    if bytes == nil then return "" end
    local s = ""
    for i = 1, #bytes do
        if bytes[i] == 0 then break end
        s = s .. string.char(bytes[i])
    end
    return gbkToUtf8(s)
end

-- 完全模拟 sub_842BE0: 从游戏内存读取职业名
local function getJobName(jobByte)
    if jobByte == 0 then return "未知" end
    local tier = (jobByte >> 4) & 3       -- sub_842CA0
    local classId = jobByte & 0xF
    if tier > 0 and tier <= 2 then
        -- 进阶职业: &unk_DDF96C + 32 * classId + 16 * tier - 48
        local addr = ADV_JOB_TABLE + 32 * classId + 16 * tier - 48
        local name = readGBKString(addr, 16)
        if name ~= "" then return name end
    end
    -- 基础职业
    local addr = BASE_JOB_ADDRS[classId]
    if addr then
        local name = readGBKString(addr, 16)
        if name ~= "" then return name end
    end
    return string.format("Job_%02X", jobByte)
end

-- 获取 CTeamQueryMgr
local function getMgr()
    local root = readInteger(0x1351620)
    if not root or root == 0 then return nil end
    local rootMgr = readInteger(root + 0x04)
    if not rootMgr or rootMgr == 0 then return nil end
    local mgrArray = readInteger(rootMgr + 0x0C)
    if not mgrArray or mgrArray == 0 then return nil end
    return readInteger(mgrArray + 0xC4)
end

-- ====== 主函数 ======
local function dumpMonsterMapPlayers()
    print("\n===== 打怪地图查询 玩家列表 =====")

    local mgr = getMgr()
    if not mgr or mgr == 0 then
        print("  ERROR: CTeamQueryMgr 未找到")
        return
    end
    print(string.format("  CTeamQueryMgr = 0x%08X", mgr))

    local bufBegin = readInteger(mgr + 0x130) or 0  -- this[76]
    local bufEnd   = readInteger(mgr + 0x134) or 0  -- this[77]

    if bufBegin == 0 or bufEnd == 0 or bufEnd <= bufBegin then
        print("  数据为空, 请先打开 打怪地图查询 页面")
        return
    end

    local totalBytes = bufEnd - bufBegin
    local count = math.floor(totalBytes / ENTRY_SIZE)

    print(string.format("  buffer: 0x%08X ~ 0x%08X (%d bytes)", bufBegin, bufEnd, totalBytes))
    print(string.format("  玩家数: %d (每条%d字节)", count, ENTRY_SIZE))
    print("")
    print(string.format("  %-4s %-16s %4s %-10s %-4s %4s %-4s %-4s %-6s",
        "序号", "名字", "等级", "职业", "国家", "队员", "双倍", "齐心", "状态"))
    print(string.rep("-", 82))

    for i = 0, count - 1 do
        local addr = bufBegin + i * ENTRY_SIZE

        -- 读取所有字段
        local name       = readGBKString(addr + 0x00, 32)
        local level      = readInteger(addr + 0x20) or 0
        local flags      = readInteger(addr + 0x24) or 0
        local teamMemNum = readBytes(addr + 0x28, 1, true)
        teamMemNum = teamMemNum and teamMemNum[1] or 0
        local statusByte = readBytes(addr + 0x29, 1, true)
        statusByte = statusByte and statusByte[1] or 0
        local jobByte    = readBytes(addr + 0x2A, 1, true)
        jobByte = jobByte and jobByte[1] or 0
        local nationByte = readBytes(addr + 0x2B, 1, true)
        nationByte = nationByte and nationByte[1] or 0

        -- 解析标志位
        local bIsInviting = (flags & 1) ~= 0           -- +0x24 bit0
        local bIsLeader   = ((flags >> 2) & 1) ~= 0    -- +0x24 bit2
        local bHasDouble  = (statusByte & 1) ~= 0      -- +0x29 bit0
        local bHasQixin   = ((statusByte >> 1) & 1) ~= 0  -- +0x29 bit1

        local jobName    = getJobName(jobByte)
        local nationName = NationNames[nationByte] or "?"

        -- 状态字符串
        local statusParts = {}
        if bIsLeader   then table.insert(statusParts, "队长") end
        if bIsInviting then table.insert(statusParts, "邀请中") end
        local statusStr = #statusParts > 0 and table.concat(statusParts, ",") or ""

        print(string.format("  [%2d] %-16s %3d级 %-10s %-4s  %d人  %-4s %-4s %s",
            i, name, level, jobName, nationName,
            teamMemNum,
            bHasDouble and "是" or "否",
            bHasQixin  and "是" or "否",
            statusStr
        ))
    end

    print(string.rep("-", 82))
    print(string.format("  共 %d 条记录", count))
    print("===== 完成 =====")
end

-- 执行
print("==========================================")
print(" QQSG 打怪地图查询 数据读取器 v4")
print(" 数据源: CTeamQueryMgr this[76]")
print(" 打开 打怪地图查询 页面后执行此脚本")
print("==========================================")
dumpMonsterMapPlayers()
