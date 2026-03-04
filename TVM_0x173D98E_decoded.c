/*
 * TVM 函数 0x173D98E 静态还原结果
 * ===================================
 * 原始入口: 0x173D98E (push 0x2D21F906; call sub_174E143)
 * 保护方式: Themida TVM (Virtual Machine) + VEH异常反分析
 * 协议文件: ov_cproto.bin (收包处理函数)
 *
 * 还原状态:
 *   Block 1  (27步)  ✅ 完全解码 - 栈分配
 *   Block 2  (28步)  ✅ 完全解码 - 获取状态
 *   Block 3  (63步)  ✅ 完全解码 - 比较+条件分支
 *   Branch 1 (37步)  ✅ 完全解码 - 直接返回
 *   Branch 2 (86步)  ✅ 完全解码 - 复杂计算+嵌套分支
 *     Sub-B   (23步)  ✅ 完全解码 - native调用
 *     Sub-A   (??步)  ❌ 阻塞: VEH异常机制未突破
 *
 * 总计: 264+ TVM指令已解码
 */

// ======================== 辅助函数 ========================

// sub_AF5C10 - 获取对象状态 (已反编译)
int __thiscall GetState(void* this) {
    return *((int*)this + 102);  // return this->field_0x198
}

// sub_AF5590 - TVM退出后的返回桩 (retn 0x0C)
// lea esp,[esp+4]; push ebp; mov ebp,[esp+8]; retn 0x0C
// 等效: 清理栈帧并返回调用者

// ======================== 主函数还原 ========================

/*
 * TVM保护的收包处理函数
 *
 * 调用约定: __thiscall (ecx = this指针)
 * 参数: this指针 + 至少3个栈参数 (来自retn 0x0C)
 *
 * 寄存器映射 (TVM虚拟寄存器 → 原生含义):
 *   VM_REG[0xC4] = 原生寄存器保存槽
 *   VM_REG[0x7C] = 保存ecx(this)
 *   VM_REG[0x40] = flags/临时
 *   VM_REG[0xD4] = 保存
 *   VM_REG[0xD8] = 保存
 *   VM_REG[0x9C] = 保存
 *   VM_REG[0x05] = 保存
 *   VM_REG[0xA0] = 保存
 *   VM_REG[0xB0] = 计算中间值
 *   VM_REG[0x34] = 临时存储
 *   VM_REG[0x30] = 计算中间值
 */

void __thiscall TVM_0x173D98E(void* this /*, 栈参数 */)
{
    // ============================================================
    // Block 1 (V_RIP=0x173B940, 27步)
    // TVM入口: 0x173D98E → push 0x2D21F906; call sub_174E143
    // ============================================================

    // 分配约295KB的栈空间
    char stack_frame[0x48028];  // sub esp, 0x48028 via __alloca_probe


    // ============================================================
    // Block 2 (V_RIP=0x1732CB1, 28步)
    // TVM stub: 0x174DACE → push 0xE5A1F8BF; push ecx; jmp 0xCDB500
    //
    // TVM执行:
    //   S01-S08: v_pop_reg 保存8个原生寄存器到VM_REG
    //   S09:     v_transition (切换dispatch key)
    //   S10-S15: 设置参数 (push_reg × 5, pop_reg)
    //   S16-S17: v_push_val 0x00AF5C10 → VM_REG[0xB0] (函数地址)
    //   S18:     v_push_val 0x174A4D1 (Block3返回地址)
    //   S19-S27: push 9个寄存器值到TVM栈 (准备v_exit)
    //   S28:     v_exit → 退出TVM, 调用native函数
    // ============================================================

    int state = GetState(this);  // sub_AF5C10: return this->field_0x198
    // Block2 v_exit后, eax = state, 控制权转到Block3 (0x174A4D1)


    // ============================================================
    // Block 3 (V_RIP=0x1732D45, 63步)
    // TVM stub: 0x174A4D1 → push 0x2FA1F8C0; push ecx; push edx; jmp 0x173B359
    //
    // 这是TVM实现的 CMP + 条件跳转:
    //
    // Phase 1 (S01-S09): 保存8个寄存器 + v_transition
    // Phase 2 (S10-S32): NOR-based CMP(eax, 4)
    //   实现: ~eax + 4 → CF/OF flags
    //         ~(~eax+4) = eax-4 → ZF/SF flags
    //         merge两组flags → 完整CMP flags
    //   使用的flag掩码: 0x815=CF|PF|AF|OF, 0xFFFFF7EA=ZF|SF|其余
    // Phase 3 (S33-S42): 提取ZF
    //   shift_count=6, CMP_flags >> 6, & 0x01 → ZF值
    // Phase 4 (S43-S47): ZF零扩展到32位
    // Phase 5 (S48-S62): 条件分支 (memcpy选择机制)
    //   push两组分支目标(各2个dword):
    //     ZF=0 (eax≠4): target pair A
    //     ZF=1 (eax==4): target pair B
    //   src = TOS + ZF*8, dest = TOS+12, count=8
    //   memcpy(dest, src, 8) → 选择一组目标
    //   adjust_sp +8
    // Phase 6 (S63): v_jmp → 跳转到选中的分支
    // ============================================================

    if (state != 4) {
        goto branch_1_return;
    }
    // else: state == 4, 进入Branch 2


    // ============================================================
    // Branch 2 (V_RIP=0x174704C, 86步)
    // 条件: state == 4
    // 首个handler: 0x173FDED (v_push_esp)
    //
    // Phase 1 (S01-S05): 读栈偏移0x48024处的值
    //   v_push_esp → v_push_val(0x48024) → v_add_nf
    //   → v_load → v_pop_reg[0x34]
    //   等效: temp = *(esp + 0x48024)  // 读取栈帧底部的参数
    // ============================================================

    // 这里 esp+0x48024 指向栈帧分配之前的参数区域
    // 即 this 或调用者传入的某个参数/对象字段
    int val = *(int*)((char*)&stack_frame + 0x48024);


    // ============================================================
    // Phase 2 (S06-S26): NOR-based 计算
    //   S06-S12: DUP val, NOR(val, val) → ~val
    //            再次DUP+NOR → ~~val = val
    //            与 VM_REG[0x30] 做NOR运算
    //   S13-S16: 读栈偏移8处的值 (另一个参数)
    //   S17-S26: 多重NOR计算, 保存到VM_REG[0xB0], VM_REG[0xC4]
    //
    // NOR(A,B) = ~(A|B) 是功能完备门
    // 通过组合NOR可以实现AND/OR/XOR/NOT:
    //   NOT(A)    = NOR(A,A)
    //   AND(A,B)  = NOR(NOR(A,A), NOR(B,B))
    //   OR(A,B)   = NOR(NOR(A,B), NOR(A,B))
    // ============================================================

    // 具体计算语义尚需逐步解码, 大致为:
    int computed_val;  // NOR-chain结果
    // computed_val = some_bitwise_operation(val, vm_reg_0x30, stack_param_at_8);


    // ============================================================
    // Phase 3 (S27-S49): NOR + ADD 计算
    //   S27-S33: NOR+ADD, 保存到VM_REG[0x40]
    //   S34-S49: DUP+NOR_F+NOR+push_val+NOR → 复杂逻辑
    //   可能是某种算术或位掩码计算
    // ============================================================

    // 进一步计算, 结果保存到多个VM寄存器


    // ============================================================
    // Phase 4 (S50-S55): v_transition + v_store
    //   S50: v_transition (切换dispatch上下文/key)
    //   S51: v_push_imm8_sx(0x3FE0)  ← 16位有符号扩展
    //   S52-S54: 计算目标地址
    //   S55: v_store → 写 0x3FE0 到计算出的内存地址
    //
    //   等效: *some_addr = 0x3FE0;
    //   0x3FE0 可能是某种状态值或标志
    // ============================================================

    // 写内存操作
    // *computed_address = 0x3FE0;


    // ============================================================
    // Phase 5 (S56-S70): 移位+布尔操作 (提取条件)
    //   S56-S58: v_push_imm8_u16(shift_count) + v_shr
    //            → 右移提取特定bit
    //   S59-S64: v_nor16 组合
    //            → 16位NOR运算链, 隔离标志位
    //   S65:     v_bool_not → 布尔取反 (0→1, 非零→0)
    //   S66:     v_pop_reg8 → 保存布尔结果
    //   S67-S70: 类型转换 (8bit → 32bit)
    //            push_imm8 + push_reg8 + pop_reg
    //
    //   等效: condition = !(some_flags & mask);
    // ============================================================

    int condition;  // 0 或 1
    // condition = !(computed_val >> N & mask);


    // ============================================================
    // Phase 6 (S71-S86): 条件分支 (memcpy + v_jmp)
    //   与Block3相同的机制:
    //   S71-S74: push 4个dword (两对分支目标):
    //     pair_0 (cond=0): {handler_enc_A, vrip_delta_A}
    //     pair_1 (cond=1): {handler_enc_B, vrip_delta_B}
    //   S75-S80: src = TOS + condition * 8
    //   S81-S83: dest = TOS + 12, count = 8
    //   S84: v_memcpy → 选择一组目标覆盖
    //   S85: v_adjust_sp +8
    //   S86: v_jmp → 跳转
    //
    //   Sub-Branch A (cond=0): handler=0x1730ADB
    //   Sub-Branch B (cond=1): handler=0x173FDCD
    //
    //   两个handler都以异常指令开头 (Themida反分析):
    //     0x1730ADB: C7 A6 → #UD (undefined instruction)
    //     0x173FDCD: 08 00 → AV (access violation)
    //   由VEH(向量化异常处理器)捕获并重定向到实际代码
    // ============================================================

    if (condition) {
        goto sub_branch_B;
    } else {
        goto sub_branch_A;
    }


    // ============================================================
    // Sub-Branch B (V_RIP=0x01745F2D, 23步, cond=1)
    // 异常入口: 0x173FDCD (AV) → VEH重定向 → 0x173FDDA
    // TVM re-entry: push 0x23A1F959; push ecx..edi; jmp sub_173DBDE
    //
    //   S01-S08: v_pop_reg 保存8个寄存器
    //   S09:     v_transition
    //   S10-S12: VM_REG[0x2C] = VM_REG[0x31] (传递参数)
    //   S13:     v_push_val 0x01741B40 (native函数返回后的TVM重入地址)
    //   S14-S22: push 9个寄存器 (准备v_exit)
    //   S23:     v_exit → 退出TVM, 执行native函数
    //
    //   native函数执行完后, ret到0x01741B40,
    //   0x01741B40以`6D`(insd)开头 → 再次触发异常 → VEH重入TVM
    //   (后续TVM执行尚未追踪)
    // ============================================================
sub_branch_B:
    // 调用某个native函数, 参数来自VM寄存器
    // some_native_function(...);
    // 返回后继续TVM执行 (在0x01741B40重入, 尚未追踪)
    // ...
    goto after_sub_branches;  // 推测


    // ============================================================
    // Sub-Branch A (cond=0) ❌ 未解码
    // 异常入口: 0x1730ADB (#UD) → VEH重定向 → ???
    //
    // 已知信息:
    //   - 异常后代码(0x1730AE2): lea esp,[esp+4]; pushfd; push ebp;
    //     push edi; jmp sub_173DBDE
    //   - 但缺少 push encrypted_vrip, 只有3个push (正常需要9个)
    //   - 说明VEH在重定向前会修改CONTEXT,
    //     补充缺失的寄存器保存和encrypted_vrip
    //   - 无法确定VEH传递的V_RIP值, 因此无法继续静态追踪
    //
    // 突破方案:
    //   1. 找到VEH handler (ntdll!RtlAddVectoredExceptionHandler)
    //      Themida通过API hash动态加载, 未在导入表中
    //   2. 动态调试: 在0x1730ADB设断点, 观察VEH修改后的CONTEXT
    //   3. Unicorn模拟: 注册VEH, 模拟异常处理流程
    // ============================================================
sub_branch_A:
    // ??? 未知操作
    // 可能是另一个native函数调用, 或更多TVM计算
    // ...


after_sub_branches:
    // Sub-Branch B 的native函数返回后, TVM在0x01741B40重入
    // 后续流程可能是:
    //   - 更多计算
    //   - 最终恢复寄存器并return
    return;


    // ============================================================
    // Branch 1 (V_RIP=0x17393EF, 37步, state ≠ 4)
    // 首个handler: 0x1735242 (v_pop_reg)
    //
    //   S01-S05: v_pop_reg 保存寄存器
    //   S06-S10: 计算操作 (设置返回值/清理)
    //   S11-S28: push 9个寄存器值
    //   S29-S37: v_push_val(返回地址=0xAF5590) + v_exit
    //
    //   0xAF5590 = 简单的返回桩:
    //     lea esp,[esp+4]; push ebp; mov ebp,[esp+8]; retn 0x0C
    //   即: 清理12字节栈参数并返回
    // ============================================================
branch_1_return:
    return;  // state != 4 时, 函数什么都不做就返回
}


/*
 * ======================== 分析总结 ========================
 *
 * 函数语义 (推测):
 *
 *   void __thiscall PacketHandler(void* this, ...) {
 *       alloca(0x48028);
 *       if (this->field_0x198 != 4)
 *           return;  // 状态不是4, 不处理
 *
 *       // 状态==4时, 执行以下逻辑:
 *       // 1. 从栈帧读取参数
 *       // 2. 对参数进行NOR-chain位运算
 *       // 3. 写 0x3FE0 到某个地址
 *       // 4. 提取条件标志
 *       // 5. 根据条件选择两个子路径之一:
 *       //    - Sub-A: 未知 (VEH阻塞)
 *       //    - Sub-B: 调用native函数, 然后重入TVM继续
 *   }
 *
 * field_0x198 的含义:
 *   - 在 0x4F8BC0 (CMaster::OnAction) 中也有 state != 4 的检查
 *   - 推测 4 = 某种特定的角色/连接状态 (如"已认证"/"战斗中")
 *
 * 0x3FE0 写入:
 *   - Branch 2 Phase 4 写入 0x3FE0 到计算出的地址
 *   - 可能是设置某个状态/标志 (如协议处理标记)
 *
 * ======================== 关键TVM技术 ========================
 *
 * 1. NOR-based比较: CMP(A,B) = merge( flags(~A+B), flags(~(~A+B)) )
 *    - ~A+B 产生 CF/OF
 *    - ~(~A+B) = A-B 产生 ZF/SF
 *    - 掩码合并: (flags1 & 0x815) | (flags2 & 0xFFFFF7EA)
 *
 * 2. 条件分支: memcpy选择, 非传统Jcc
 *    - push两组目标(各8字节), 用 memcpy(dest, src+cond*8, 8) 选一组
 *    - v_jmp根据选中的目标跳转
 *
 * 3. 异常反分析: handler以#UD/AV/GP异常指令开头
 *    - VEH捕获异常, 修改CONTEXT.Eip重定向到实际代码
 *    - 阻止静态反汇编器跟踪控制流
 *
 * 4. 交错式Bytecode: [handler0_addr][handler1_addr][handler0_operand]...
 *    - 不是简单的 [addr][operand] 顺序排列
 */
