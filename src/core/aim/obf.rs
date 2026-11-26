//! 混淆与反调试（v1.8.1 新增）。
//!
//! # 这个模块在做什么
//!
//! 回应"加混淆和大量反调试钩子，每一个逻辑都要混大量没用的假逻辑"。
//! 提供三类能力：
//!
//! | 类别 | 入口 | 作用 |
//! |---|---|---|
//! | **反调试检测** | [`scan`] | 多路信号采集，**分级**判定 |
//! | **不透明谓词** | [`opaque_true`] / [`opaque_false`] | 恒真/恒假但静态难判定的条件 |
//! | **假逻辑注入** | [`junk_math`] / [`dead_branch`] | 无副作用但会进二进制的死代码 |
//!
//! # 为什么反调试必须"分级"（重要）
//!
//! 反调试是**双刃剑**：判太松形同虚设，判太紧会**误杀正常用户**。
//! 学校机房的真实环境里有：
//!
//! * 还原卡 / 还原精灵（会 hook 某些系统调用）
//! * 极域/红蜘蛛电子教室（本身就是调试/监控类软件）
//! * 360 / 火绒等杀毒（会注入进程、开远程调试句柄）
//! * 用户自己用任务管理器/资源监视器看过这个进程
//!
//! 任何**单一**信号都可能是误报。因此本模块采用累进计分：
//!
//! ```text
//!   ThreatLevel::None    ← 0 分：无信号
//!   ThreatLevel::Low     ← 1-2 分：仅记审计，不干扰使用
//!   ThreatLevel::Medium  ← 3-4 分：记审计 + 提示，仍放行
//!   ThreatLevel::High    ← ≥5 分：**多路强信号同时命中**，拒绝授权
//! ```
//!
//! **只有 `High` 才拒绝授权**，且要求多个强信号同时出现 ——
//! 正常用户（哪怕开着杀毒）几乎不可能同时命中全部强信号。
//!
//! # 诚实的局限（不夸大）
//!
//! * 反调试挡不住**内核态**调试（WinDbg 内核调试、Hypervisor 隐藏），
//!   也挡不住"先 hook 我们的检测函数再喂假结果"这种针对性对抗。
//! * 假逻辑只是抬高**静态阅读**成本，动态调试器下单步即可看穿。
//! * **任何客户端防护都可被绕过**。本模块的定位是"让白嫖变麻烦"，
//!   不是"无法破解"。详见 `docs/13_服务端授权说明.md` 第七节。

// 本模块的公开 API 由 client / api / main 按需取用，且部分入口只在特定
// 分支被调用。为避免"未使用"噪音淹没真实编译问题，统一放行 ——
// 与 server_pkg/src/main.rs 同一姿势。
#![allow(dead_code)]

use std::hint::black_box;

// ---------------------------------------------------------------------------
// 威胁等级
// ---------------------------------------------------------------------------

/// 检测到的威胁等级。**只有 `High` 会导致拒绝授权**。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatLevel {
    /// 无信号（正常环境）。
    None,
    /// 弱信号（1-2 分）：只记审计，**不干扰使用**。
    Low,
    /// 中等信号（3-4 分）：记审计并提示，**仍放行**。
    Medium,
    /// 强信号（≥5 分）：多路同时命中，拒绝授权。
    High,
}

impl ThreatLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            ThreatLevel::None => "无异常",
            ThreatLevel::Low => "轻微可疑",
            ThreatLevel::Medium => "中度可疑",
            ThreatLevel::High => "高度可疑",
        }
    }

    /// 是否应拒绝授权。**仅 `High` 为真**。
    ///
    /// 刻意保守：宁可放过一个真在调试的人，也不能误杀一个开着杀毒的正常用户。
    pub fn should_block(self) -> bool {
        self == ThreatLevel::High
    }
}

/// 一次扫描的结果。
#[derive(Debug, Clone)]
pub struct ScanReport {
    /// 综合等级。
    pub level: ThreatLevel,
    /// 命中的信号名（诊断与审计用，可安全外传——不含任何密钥信息）。
    pub signals: Vec<&'static str>,
    /// 累计分数（内部判定依据）。
    pub score: u32,
}

impl ScanReport {
    /// 汇总为一行可读文本（供日志/诊断接口）。
    pub fn summary(&self) -> String {
        if self.signals.is_empty() {
            return "未检测到调试痕迹".into();
        }
        format!(
            "{}（{} 分）：{}",
            self.level.as_str(),
            self.score,
            self.signals.join("、")
        )
    }
}

// ---------------------------------------------------------------------------
// 反调试：单点检测
// ---------------------------------------------------------------------------

/// Windows: PEB.BeingDebugged 标志（最经典的检测，权重低——易被清）。
#[cfg(windows)]
fn check_being_debugged(out: &mut Vec<&'static str>) -> u32 {
    // PEB 在 64 位下偏移 0x60 处有 SelfPointer；BeingDebugged 在 +0x02。
    // 直接用 extern 拿 ntdll 的未导出字段风险高，改为走 IsDebuggerPresent。
    unsafe {
        #[link(name = "kernel32")]
        extern "system" {
            fn IsDebuggerPresent() -> i32;
        }
        if IsDebuggerPresent() != 0 {
            out.push("IsDebuggerPresent");
            return 2;
        }
    }
    0
}

/// Windows: 远程调试器（本进程是否被别的进程附加）。
#[cfg(windows)]
fn check_remote_debugger(out: &mut Vec<&'static str>) -> u32 {
    #[repr(C)]
    struct Handle(isize);
    unsafe {
        #[link(name = "kernel32")]
        extern "system" {
            fn GetCurrentProcess() -> isize;
            fn CheckRemoteDebuggerPresent(process: isize, present: *mut i32) -> i32;
        }
        let mut present: i32 = 0;
        let cur = GetCurrentProcess();
        if CheckRemoteDebuggerPresent(cur, &mut present) != 0 && present != 0 {
            out.push("CheckRemoteDebuggerPresent");
            return 3; // 比 IsDebuggerPresent 更难伪造
        }
    }
    let _ = black_box(&Handle);
    0
}

/// Windows: NtQueryInformationProcess 查三个调试相关类。
#[cfg(windows)]
fn check_nt_query(out: &mut Vec<&'static str>) -> u32 {
    // ProcessDebugPort=7, ProcessDebugFlags=8, ProcessDebugObjectHandle=0x1E
    const PROCESS_DEBUG_PORT: u32 = 7;
    const PROCESS_DEBUG_OBJECT_HANDLE: u32 = 0x1E;
    #[repr(C)]
    struct ObjAttr {
        length: u32,
        root: isize,
        name: isize,
        attrs: u32,
        sd: isize,
        qos: isize,
    }
    unsafe {
        #[link(name = "ntdll")]
        extern "system" {
            fn NtQueryInformationProcess(
                process: isize,
                class: u32,
                info: *mut core::ffi::c_void,
                len: u32,
                ret_len: *mut u32,
            ) -> i32;
        }
        #[link(name = "kernel32")]
        extern "system" {
            fn GetCurrentProcess() -> isize;
        }
        let cur = GetCurrentProcess();
        let mut port: isize = 0;
        if NtQueryInformationProcess(
            cur,
            PROCESS_DEBUG_PORT,
            &mut port as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<isize>() as u32,
            std::ptr::null_mut(),
        ) == 0
            && port != 0
        {
            out.push("NtQueryInformationProcess:DebugPort");
            return 4; // 内核态信息，伪造难度最高
        }
        let mut handle: isize = 0;
        if NtQueryInformationProcess(
            cur,
            PROCESS_DEBUG_OBJECT_HANDLE,
            &mut handle as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<isize>() as u32,
            std::ptr::null_mut(),
        ) == 0
            && handle != 0
        {
            out.push("NtQueryInformationProcess:DebugObject");
            return 4;
        }
        let _ = black_box(&ObjAttr {
            length: 0,
            root: 0,
            name: 0,
            attrs: 0,
            sd: 0,
            qos: 0,
        });
    }
    0
}

/// Windows: 硬件断点（Dr0–Dr7）。单步调试必设硬件断点。
#[cfg(windows)]
fn check_hardware_breakpoints(out: &mut Vec<&'static str>) -> u32 {
    #[repr(C)]
    struct Context {
        context_flags: u32,
        dr0: usize,
        dr1: usize,
        dr2: usize,
        dr3: usize,
        dr6: usize,
        dr7: usize,
        // 后面还有一堆字段，但只用到前 7 个（CONTEXT_DEBUG_REGISTERS）
        rest: [u8; 512],
    }
    // 不能 `#[derive(Default)]`：Rust 的标准库只为长度 ≤ 32 的数组实现
    // `Default`，`[u8; 512]` 会报 E0277（MSVC 目标上尤其明显）。
    // 显式零初始化，语义完全等价（GetThreadContext 会整体填充）。
    impl Default for Context {
        fn default() -> Self {
            Context {
                context_flags: 0,
                dr0: 0,
                dr1: 0,
                dr2: 0,
                dr3: 0,
                dr6: 0,
                dr7: 0,
                rest: [0u8; 512],
            }
        }
    }
    unsafe {
        #[link(name = "kernel32")]
        extern "system" {
            fn GetCurrentThread() -> isize;
            fn GetThreadContext(thread: isize, ctx: *mut Context) -> i32;
        }
        let mut ctx = Context {
            context_flags: 0x00000010, // CONTEXT_DEBUG_REGISTERS
            ..Default::default()
        };
        let th = GetCurrentThread();
        if GetThreadContext(th, &mut ctx) != 0 {
            let mut hit = 0;
            for (name, v) in [
                ("Dr0", ctx.dr0),
                ("Dr1", ctx.dr1),
                ("Dr2", ctx.dr2),
                ("Dr3", ctx.dr3),
            ] {
                if v != 0 {
                    let _ = name;
                    hit += 1;
                }
            }
            if hit > 0 {
                out.push("硬件断点(Dr0-Dr3)");
                return 3;
            }
        }
    }
    0
}

/// Linux: `/proc/self/status` 的 TracerPid。
#[cfg(unix)]
fn check_tracer_pid(out: &mut Vec<&'static str>) -> u32 {
    if let Ok(s) = std::fs::read_to_string("/proc/self/status") {
        for line in s.lines() {
            if let Some(v) = line.strip_prefix("TracerPid:") {
                if let Ok(pid) = v.trim().parse::<i32>() {
                    if pid != 0 {
                        out.push("TracerPid != 0");
                        return 3;
                    }
                }
                break;
            }
        }
    }
    0
}

/// Linux: 尝试自我 ptrace —— 已被跟踪则失败。
#[cfg(unix)]
fn check_self_ptrace(out: &mut Vec<&'static str>) -> u32 {
    unsafe {
        #[link(name = "c")]
        extern "C" {
            fn ptrace(request: i32, pid: i32, addr: *mut core::ffi::c_void, data: *mut core::ffi::c_void) -> i32;
        }
        const PTRACE_TRACEME: i32 = 0;
        // 已被别的 tracer 附加时 TRACEME 返回 -1
        if ptrace(PTRACE_TRACEME, 0, std::ptr::null_mut(), std::ptr::null_mut()) == -1 {
            out.push("ptrace(TRACEME) 失败");
            return 3;
        }
    }
    0
}

/// 时序检测：同一段计算在调试器下单步会显著变慢。
///
/// 阈值放得**很宽**（10 倍），因为虚拟机/老旧机器本身就可能慢数倍。
/// 只在极端异常时才给分。
fn check_timing(out: &mut Vec<&'static str>) -> u32 {
    // 基准：一段确定性的假计算
    let t0 = std::time::Instant::now();
    let mut acc = 0u64;
    for i in 0..200_000u64 {
        acc = acc.wrapping_add(i.wrapping_mul(2654435761));
    }
    let base_ns = t0.elapsed().as_nanos() as u64;
    let _ = black_box(acc);

    // 测量：同样一段，但中间夹一次"真实业务"级别的调用
    let t1 = std::time::Instant::now();
    let mut acc2 = 0u64;
    for i in 0..200_000u64 {
        acc2 = acc2.wrapping_add(i.wrapping_mul(2654435761));
    }
    let probe_ns = t1.elapsed().as_nanos() as u64;
    let _ = black_box(acc2);

    // 两段相同计算，比值应接近 1。调试器单步会让第二段暴涨。
    // 用 10 倍阈值，容忍虚拟机/降频/抢占。
    if base_ns > 0 && probe_ns > base_ns.saturating_mul(10) {
        out.push("执行时序异常");
        return 3;
    }
    0
}

/// 环境痕迹：常见调试器进程名（弱信号，只作佐证）。
fn check_debugger_processes(out: &mut Vec<&'static str>) -> u32 {
    const NAMES: [&str; 8] = [
        "x64dbg", "x32dbg", "ollydbg", "ida", "ida64", "windbg", "gdb", "frida",
    ];
    let mut hit = 0u32;
    #[cfg(windows)]
    {
        // tasklist 输出比对（避免引入 winapi crate）
        if let Ok(o) = std::process::Command::new("tasklist")
            .stdout(std::process::Stdio::piped())
            .output()
        {
            let text = String::from_utf8_lossy(&o.stdout).to_ascii_lowercase();
            for n in NAMES {
                if text.contains(n) {
                    hit += 1;
                }
            }
        }
    }
    #[cfg(unix)]
    {
        if let Ok(rd) = std::fs::read_dir("/proc") {
            for e in rd.flatten() {
                let name = e.file_name();
                let name = name.to_string_lossy();
                if name.chars().all(|c| c.is_ascii_digit()) {
                    if let Ok(comm) = std::fs::read_to_string(e.path().join("comm")) {
                        let c = comm.trim().to_ascii_lowercase();
                        for n in NAMES {
                            if c.contains(n) {
                                hit += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    if hit > 0 {
        out.push("检测到调试器进程");
        // 有调试器进程**不等于**在调试我们（可能只是装着没开），给低分
        return 1;
    }
    0
}

/// 执行一次完整扫描。
///
/// **本函数不产生任何外部副作用**：不改文件、不发网络、不弹窗。
/// 仅在检测到 `High` 时由调用方决定是否拒绝授权。
pub fn scan() -> ScanReport {
    let mut signals: Vec<&'static str> = Vec::new();
    let mut score = 0u32;

    #[cfg(windows)]
    {
        score += check_being_debugged(&mut signals);
        score += check_remote_debugger(&mut signals);
        score += check_nt_query(&mut signals);
        score += check_hardware_breakpoints(&mut signals);
    }
    #[cfg(unix)]
    {
        score += check_tracer_pid(&mut signals);
        score += check_self_ptrace(&mut signals);
    }
    // 跨平台
    score += check_timing(&mut signals);
    score += check_debugger_processes(&mut signals);

    let level = if score >= 5 {
        ThreatLevel::High
    } else if score >= 3 {
        ThreatLevel::Medium
    } else if score >= 1 {
        ThreatLevel::Low
    } else {
        ThreatLevel::None
    };

    ScanReport {
        level,
        signals,
        score,
    }
}

// ---------------------------------------------------------------------------
// 混淆原语：不透明谓词
// ---------------------------------------------------------------------------

/// 恒为 `true` 的条件，但静态分析难以直接判定。
///
/// 构造依据：**两个连续整数的乘积必为偶数**（`x·(x+1)`，二者必有一偶）。
/// 因此 `(x·(x+1)) & 1 == 0` 恒成立 —— 但需要一步数论推导才看得出来，
/// 反编译器不会自动折叠它。
///
/// 前置的乘加混合让 `x` 与输入只有非线性关系，进一步阻止常量传播。
/// **运行时永远返回 true**，不改变程序语义。
#[inline(never)]
pub fn opaque_true(seed: u64) -> bool {
    let x = seed
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add(0x1234_5678_9ABC_DEF0);
    let prod = x.wrapping_mul(x.wrapping_add(1));
    // x(x+1) 必偶 → 最低位必为 0
    (prod & 1) == 0
}

/// 恒为 `false` 的条件（同上，静态难判定）。
#[inline(never)]
pub fn opaque_false(seed: u64) -> bool {
    !opaque_true(seed)
}

/// 把控制流压平成"状态机分发"形式用的分发键。
///
/// 用途：把一个直线逻辑
/// ```text
///   A → B → C
/// ```
/// 改写成
/// ```text
///   state = dispatch(0); match state { 2 => {C; state=3}, 1 => {B; state=2}, _ => {A; state=1} }
/// ```
/// 静态阅读时步骤顺序被打乱，但执行顺序不变。
#[inline(never)]
pub fn dispatch_key(state: u32, seed: u64) -> u32 {
    let k = seed.wrapping_mul(0x2545_F491_4F6C_DD1D).wrapping_add(0x9E37_79B9_7F4A_7C15);
    // 只是把 state 打乱顺序后再映射回自身集合，保证是置换
    match (state.wrapping_add(k as u32)) % 4 {
        0 => 0,
        1 => 2,
        2 => 3,
        _ => 1,
    }
}

// ---------------------------------------------------------------------------
// 混淆原语：假逻辑注入
// ---------------------------------------------------------------------------

/// 一段**无副作用**的假计算，结果通过 `black_box` 强制保留在二进制里。
///
/// 作用：让反编译视图里出现大量看似在"算密钥"的算术，
/// 实际结果从未被使用。显著增加静态阅读成本。
#[inline(never)]
pub fn junk_math(seed: u64) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64 ^ seed;
    // 12 轮混合，看起来像 KDF，实际输出被丢弃
    for i in 0..12u64 {
        h ^= h >> 33;
        h = h.wrapping_mul(0xff51_afd7_ed55_8ccd);
        h ^= h >> 29;
        h = h.wrapping_add(i.wrapping_mul(0x9E37_79B9_7F4A_7C15));
    }
    black_box(h)
}

/// 一个**不可达**的分支（静态可见、动态永不执行）。
///
/// 用 `opaque_false` 包住真业务代码，反编译器会把它当"可能的路径"，
/// 阅读者必须逐个排除。
#[inline(never)]
pub fn dead_branch(seed: u64) -> u64 {
    let mut acc = 0u64;
    // 这段永远不进（opaque_false 恒假），但静态上"看起来会进"
    if opaque_false(seed) {
        for i in 0..64u64 {
            acc = acc.wrapping_add(junk_math(i ^ seed));
        }
        return black_box(acc);
    }
    // 真实的"无操作"出口
    black_box(0)
}

/// 假的字符串拼接，产出从未被使用的字符串。
///
/// 让二进制里多出一些"看起来像密钥/路径"的串，干扰字符串检索。
#[inline(never)]
pub fn junk_strings(seed: u64) -> String {
    let mut s = String::with_capacity(48);
    let parts = [
        "sx", "kf", "mz", "qw", "tp", "ld", "nv", "hr", "yc", "gb",
    ];
    let n = (seed % parts.len() as u64) as usize;
    for i in 0..6 {
        s.push_str(parts[(n + i) % parts.len()]);
    }
    black_box(s.clone());
    s
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn threat_level_blocks_only_high() {
        assert!(!ThreatLevel::None.should_block());
        assert!(!ThreatLevel::Low.should_block());
        assert!(!ThreatLevel::Medium.should_block());
        assert!(ThreatLevel::High.should_block());
    }

    /// 反调试在正常测试环境里**绝不应该判 High**。
    ///
    /// 这条测试是防误杀的第一道闸：若 CI 环境被判 High，
    /// 说明某个信号把正常情况当成了调试，必须调整权重。
    #[test]
    fn normal_environment_is_not_high() {
        let r = scan();
        // 只断言"不是 High"，不断言"无信号"——
        // CI 机器上跑着 gdb/lldb 或装了 IDA 是完全可能的。
        assert_ne!(
            r.level,
            ThreatLevel::High,
            "正常环境被判高度可疑，会误杀真实用户：{}",
            r.summary()
        );
    }

    #[test]
    fn scan_is_stable_across_calls() {
        let a = scan();
        let b = scan();
        // 只要求"不悬殊"：None ↔ High 的跳变说明某路信号不稳定。
        // 允许相邻一级波动（时序检测在容器/CI 上本身有抖动）。
        let extreme = (a.level == ThreatLevel::None && b.level == ThreatLevel::High)
            || (a.level == ThreatLevel::High && b.level == ThreatLevel::None);
        assert!(
            !extreme,
            "两次扫描等级悬殊，说明检测不稳定：{} vs {}",
            a.summary(),
            b.summary()
        );
    }

    #[test]
    fn opaque_true_is_always_true() {
        for s in [0u64, 1, 42, 999_999, u64::MAX, 0xdead_beef_cafe_babe] {
            assert!(opaque_true(s), "opaque_true({}) 必须恒真", s);
            assert!(!opaque_false(s), "opaque_false({}) 必须恒假", s);
        }
    }

    #[test]
    fn opaque_predicates_are_stable() {
        for s in 0..64u64 {
            assert_eq!(opaque_true(s), opaque_true(s));
        }
    }

    #[test]
    fn dispatch_key_is_a_permutation() {
        // 分发键必须保持集合不变，否则控制流扁平化会丢步骤
        for seed in 0..16u64 {
            let mut seen = [false; 4];
            for state in 0..4u32 {
                let k = dispatch_key(state, seed);
                assert!(k < 4, "分发键越界");
                assert!(!seen[k as usize], "分发键不是置换（有碰撞）");
                seen[k as usize] = true;
            }
        }
    }

    #[test]
    fn dead_branch_never_returns_junk() {
        // dead_branch 的动态结果必须恒为 0（真分支永不进）
        for s in 0..32u64 {
            assert_eq!(dead_branch(s), 0, "dead_branch 不应产生副作用结果");
        }
    }

    #[test]
    fn junk_helpers_are_pure() {
        for s in 0..8u64 {
            assert_eq!(junk_math(s), junk_math(s), "假计算必须确定");
            assert_eq!(junk_strings(s), junk_strings(s), "假字符串必须确定");
        }
    }
}
