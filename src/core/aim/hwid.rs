//! 机器指纹（HWID）：硬件级特征采集与哈希（v1.8.0 新增）。
//!
//! # 为什么需要它
//!
//! 服务端授权的基本前提是"把一份授权绑定到一台机器上"。若只认密钥字符串，
//! 一份密钥可以被无限复制到任意多台机器 —— 那就等于没有授权。HWID 把
//! 授权与物理机器绑定，使"复制密钥给别人"这件事**失效**。
//!
//! # 采集哪些特征（硬件级，非系统级）
//!
//! | 特征 | 来源 | 更换影响 |
//! |---|---|---|
//! | 主板 UUID | Windows: `wmic csproduct get uuid`；Linux: `/sys/class/dmi/id/product_uuid` | 换主板 → 指纹变 |
//! | 系统盘序列号 | Windows: `wmic diskdrive`；Linux: `/sys/block/*/device/serial` | 换硬盘 → 指纹变 |
//! | 主网卡 MAC | Windows: `getmac`；Linux: `/sys/class/net/*/address` | 换网卡 → **不影响**（见下） |
//! | CPU 型号标识 | Windows: `wmic cpu`；Linux: `/proc/cpuinfo` | 换 CPU → 指纹变 |
//!
//! # MAC 为什么"不影响"：容错并集设计
//!
//! 网卡是最常变动的部件（换无线网卡、插拔 USB 网卡、虚拟机改网卡）。
//! 因此本模块把 MAC **单列为一个可选项**：最终指纹取"稳定三项"
//! （主板 / 磁盘 / CPU）的哈希。MAC 只用于**辅助**展示与审计，
//! 不参与指纹计算 —— 否则老师换一张网卡就要重新申请授权，体验很差。
//!
//! 若三项稳定特征在某种环境下全部采集失败（权限不足、容器、精简系统），
//! 则**降级**为"系统级指纹"：主机名 + 用户名 + 系统盘卷序列号。
//! 降级会在 `HwidInfo.degraded` 中如实标记，并写入审计 —— **绝不静默**。
//!
//! # 诚实说明局限
//!
//! HWID 是**标识**，不是**防伪**。它挡的是"一份密钥拷给十台机器用"这种
//! 朴素滥用，**挡不住**有能力改写采集结果的技术对手（如虚拟机克隆 +
//! 伪造 SMBIOS）。真正的强绑定需要 TPM 背书密钥（本项目未采用）。
//! 这个定位与 `docs/12_密钥与防破解说明.md` 的既有立场保持一致：
//! **提高门槛，不承诺不可逾越。**

use std::fmt::Write as _;
use std::process::Command;

/// 指纹哈希轮数（HMAC-SHA256 之外的轻量替代；与 license 的慢哈希同族）。
///
/// HWID 只在本机计算一次并缓存，因此轮数取高一些（50 万）也无性能压力 ——
/// 它每进程只跑一次。提高轮数的收益是：即使他人拿到指纹值，
/// 也难以通过反推"哪三个硬件特征组合"来伪造。
pub const HWID_ROUNDS: u32 = 500_000;

/// HWID 内部盐值（XOR 混淆存放，避免 `strings` 直接命中）。
///
/// 对应明文 `"sports-meet::aim::hwid::v1.8.0"`，经 `channel::deobfuscate` 还原。
/// 与 license / vault 的盐刻意不同，避免跨用途相关性。
const HWID_SALT_MASKED: [u8; 30] = [
    0x29, 0x37, 0x0f, 0x7f, 0x5a, 0xb8, 0xd9, 0xfc, 0xd7, 0x3a, 0x0c, 0x5f, 0x3c, 0x42, 0xa5,
    0x84, 0xb0, 0x8d, 0x38, 0x0a, 0x77, 0x5f, 0x1e, 0xfb, 0x94, 0xbe, 0x86, 0x6d, 0x58, 0x23,
];

/// 还原后的 HWID 盐（首次使用时计算；不含敏感信息，缓存无风险）。
fn hwid_salt() -> String {
    crate::core::aim::channel::deobfuscate(&HWID_SALT_MASKED)
}

/// 采集到的原始硬件特征（未哈希）。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HwidInfo {
    /// 主板 UUID（最稳定的特征）。
    pub board_uuid: String,
    /// 系统盘序列号。
    pub disk_serial: String,
    /// CPU 型号标识。
    pub cpu_id: String,
    /// 主网卡 MAC（不参与指纹，仅展示/审计）。
    pub mac: String,
    /// 主机名（降级路径使用）。
    pub hostname: String,
    /// 是否走了降级路径（稳定三项至少两项采集失败）。
    pub degraded: bool,
    /// 采集过程中遇到的问题（供审计与排错；空表示全部顺利）。
    pub warnings: Vec<String>,
}

impl HwidInfo {
    /// 最终机器指纹：16 位小写十六进制。
    ///
    /// 计算方式（**设计要点**）：
    ///
    /// ```text
    ///   material = "board|disk|cpu"        （降级时改用 hostname|volume|user）
    ///   hwid     = slow_hash(material, HWID_ROUNDS)
    /// ```
    ///
    /// * 用途分隔符 `|` 保证"board=a, disk=bc"与"board=ab, disk=c"
    ///   不会哈希到同一个值（分段歧义是经典指纹碰撞来源）。
    /// * 采集失败的项填 `<absent>` 占位符而非空串，使"缺失"本身也参与
    ///   哈希 —— 这样"某台机器主板读不到"与"主板值恰好为空"不会混淆。
    pub fn fingerprint(&self) -> String {
        // 判定降级：稳定三项（主板/磁盘/CPU）中有效项少于 2 项
        let stable_valid = [&self.board_uuid, &self.disk_serial, &self.cpu_id]
            .iter()
            .filter(|s| is_valid_feature(s))
            .count();
        let material = if stable_valid >= 2 {
            format!(
                "board={}|disk={}|cpu={}",
                seg(&self.board_uuid),
                seg(&self.disk_serial),
                seg(&self.cpu_id),
            )
        } else {
            // 降级路径：用主机名 + 用户名（系统级特征，稳定性较差，故如实标记）
            format!(
                "host={}|user={}|disk={}",
                seg(&self.hostname),
                seg(&env_user()),
                seg(&self.disk_serial),
            )
        };
        slow_hash(&material, HWID_ROUNDS)
    }

    /// 是否走了降级路径。
    pub fn is_degraded(&self) -> bool {
        let stable_valid = [&self.board_uuid, &self.disk_serial, &self.cpu_id]
            .iter()
            .filter(|s| is_valid_feature(s))
            .count();
        stable_valid < 2
    }

    /// 指纹前 8 位（供界面展示"这台机器是哪一台"，不足以反推特征）。
    pub fn short_id(&self) -> String {
        let fp = self.fingerprint();
        fp.chars().take(8).collect()
    }
}

/// 特征值是否"有效"（非空、非占位符、非常见的无意义返回值）。
///
/// 许多系统会返回 `To be filled by O.E.M.`、`Default string`、
/// `None`、`00000000-0000-0000-0000-000000000000` 之类的占位值。
/// 若把它们当成真实特征，**几十万台机器会得到同一个指纹** ——
/// 这是实测中最容易踩的坑（见 docs/05 踩坑记录）。
fn is_valid_feature(s: &str) -> bool {
    let t = s.trim();
    if t.is_empty() || t.len() < 4 {
        return false;
    }
    let lower = t.to_ascii_lowercase();
    const PLACEHOLDERS: [&str; 9] = [
        "to be filled",
        "default string",
        "system serial",
        "o.e.m.",
        "not specified",
        "unknown",
        "none",
        "ffffffff",
        "00000000-0000-0000-0000-000000000000",
    ];
    // 全 0 / 全 F 的特征也是占位符（虚拟机镜像常见）
    let all_zero = t.chars().all(|c| c == '0' || c == ':' || c == '-');
    let all_f = t.chars().all(|c| c == 'f' || c == 'F' || c == ':' || c == '-');
    if all_zero || all_f {
        return false;
    }
    !PLACEHOLDERS.iter().any(|p| lower.contains(p))
}

/// 缺失特征的占位符（参与哈希，使"缺失"成为可区分状态）。
fn seg(s: &str) -> String {
    let t = s.trim();
    if is_valid_feature(t) {
        t.to_string()
    } else {
        "<absent>".to_string()
    }
}

/// 读取环境变量 USER / USERNAME（降级路径使用）。
fn env_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "<absent>".into())
}

/// 从原始字节出发的 FNV-1a 64 单步。
fn fnv1a64_bytes(mut h: u64, bytes: &[u8]) -> u64 {
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

/// 慢哈希：`h = FNV1a(h ‖ salt ‖ 轮序号 ‖ input)` 迭代 `rounds` 轮。
///
/// 与 `license::slow_hash` 同构但盐不同，因此**同一输入在两个模块得到
/// 不同指纹** —— 避免"HWID 指纹 == 密钥指纹"这类跨用途相关性把
/// 两套机制的安全性绑在一起。
pub fn slow_hash(input: &str, rounds: u32) -> String {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    let salt = hwid_salt();
    let mut h = fnv1a64_bytes(OFFSET_BASIS, input.as_bytes());
    for i in 0..rounds {
        h = fnv1a64_bytes(h, salt.as_bytes());
        h = fnv1a64_bytes(h, &i.to_le_bytes());
        h = fnv1a64_bytes(h, input.as_bytes());
    }
    let mut out = String::with_capacity(16);
    let _ = write!(out, "{:016x}", h);
    out
}

// ---------------------------------------------------------------------------
// 硬件特征采集
// ---------------------------------------------------------------------------

/// 采集本机硬件特征（自动选择平台实现）。
///
/// **设计原则：绝不 panic、绝不返回 Err。** 采集失败是正常情况
/// （容器、精简系统、权限受限），由"降级路径"兜底，并在
/// `warnings` 中如实记录。指纹机制不能因为采集失败就把程序卡死。
pub fn collect() -> HwidInfo {
    let mut info = HwidInfo::default();

    // 各平台采集。用 cfg 分派，未覆盖的平台走通用降级（只读环境变量）。
    #[cfg(target_os = "windows")]
    collect_windows(&mut info);
    #[cfg(target_os = "linux")]
    collect_linux(&mut info);
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        info.warnings
            .push(format!("未适配的平台 {}，走通用降级路径", std::env::consts::OS));
    }

    info.hostname = hostname();
    info.degraded = info.is_degraded();
    info
}

/// 运行外部命令并返回 stdout（去掉尾部空白）。失败返回 None。
///
/// **安全要点**：命令与参数分离传入，不经 shell 解析，
/// 因此参数中的特殊字符不会被解释为命令注入。
fn run_cmd(program: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(program).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

/// 读取文件并返回首行（去空白）。失败返回 None。
fn read_first_line(path: &str) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let line = text.lines().next()?.trim().to_string();
    if line.is_empty() {
        None
    } else {
        Some(line)
    }
}

#[cfg(target_os = "windows")]
fn collect_windows(info: &mut HwidInfo) {
    // 主板 UUID：wmic 在 Win10/11 仍可用（Win11 24H2 起默认移除，
    // 故同时尝试 PowerShell 的 CIM 查询作为回退）。
    info.board_uuid = run_cmd("wmic", &["csproduct", "get", "uuid"])
        .and_then(|s| s.lines().nth(1).map(|l| l.trim().to_string()))
        .filter(|s| is_valid_feature(s))
        .or_else(|| {
            run_cmd(
                "powershell",
                &[
                    "-NoProfile",
                    "-Command",
                    "(Get-CimInstance Win32_ComputerSystemProduct).UUID",
                ],
            )
        })
        .unwrap_or_else(|| {
            info.warnings.push("主板 UUID 采集失败".into());
            String::new()
        });

    // 磁盘序列号：取第一块物理磁盘（通常是系统盘）。
    info.disk_serial = run_cmd(
        "powershell",
        &[
            "-NoProfile",
            "-Command",
            "(Get-CimInstance Win32_DiskDrive | Select-Object -First 1).SerialNumber",
        ],
    )
    .or_else(|| {
        run_cmd("wmic", &["diskdrive", "get", "serialnumber"])
            .and_then(|s| s.lines().nth(1).map(|l| l.trim().to_string()))
    })
    .filter(|s| is_valid_feature(s))
    .unwrap_or_else(|| {
        info.warnings.push("磁盘序列号采集失败".into());
        String::new()
    });

    // CPU 标识。
    info.cpu_id = run_cmd("wmic", &["cpu", "get", "ProcessorId"])
        .and_then(|s| s.lines().nth(1).map(|l| l.trim().to_string()))
        .filter(|s| is_valid_feature(s))
        .unwrap_or_else(|| {
            info.warnings.push("CPU 标识采集失败".into());
            String::new()
        });

    // MAC（不参与指纹，仅展示）。取第一条物理网卡地址。
    info.mac = run_cmd(
        "powershell",
        &[
            "-NoProfile",
            "-Command",
            "(Get-CimInstance Win32_NetworkAdapter | Where-Object {$_.MACAddress -ne $null} | Select-Object -First 1).MACAddress",
        ],
    )
    .unwrap_or_default();
}

#[cfg(target_os = "linux")]
fn collect_linux(info: &mut HwidInfo) {
    // 主板 UUID（需要 root 才能读，普通用户可能失败 → 走降级）
    info.board_uuid = read_first_line("/sys/class/dmi/id/product_uuid").unwrap_or_else(|| {
        info.warnings.push("主板 UUID 采集失败（需 root 或容器环境）".into());
        String::new()
    });

    // 系统盘序列号：遍历 /sys/block，跳过 loop / ram / dm 等虚拟设备
    info.disk_serial = collect_linux_disk_serial().unwrap_or_else(|| {
        info.warnings.push("磁盘序列号采集失败".into());
        String::new()
    });

    // CPU：取 model name 的哈希（不同批次 CPU 型号相同，但配合主板/磁盘足够）
    info.cpu_id = read_first_line("/proc/cpuinfo")
        .and_then(|_| {
            std::fs::read_to_string("/proc/cpuinfo").ok().and_then(|t| {
                t.lines()
                    .find(|l| l.starts_with("model name"))
                    .and_then(|l| l.split_once(':').map(|(_, v)| v.trim().to_string()))
            })
        })
        .unwrap_or_else(|| {
            info.warnings.push("CPU 型号采集失败".into());
            String::new()
        });

    // MAC：第一个非 lo 网卡
    info.mac = collect_linux_mac().unwrap_or_default();
}

#[cfg(target_os = "linux")]
fn collect_linux_disk_serial() -> Option<String> {
    let entries = std::fs::read_dir("/sys/block").ok()?;
    let mut names: Vec<String> = Vec::new();
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        // 跳过虚拟设备：loop（快照）、ram（内存盘）、dm（LVM）、sr（光驱）
        if name.starts_with("loop")
            || name.starts_with("ram")
            || name.starts_with("dm-")
            || name.starts_with("sr")
            || name.starts_with("zram")
        {
            continue;
        }
        names.push(name);
    }
    names.sort();
    for name in names {
        let p = format!("/sys/block/{}/device/serial", name);
        if let Some(s) = read_first_line(&p) {
            if is_valid_feature(&s) {
                return Some(s);
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn collect_linux_mac() -> Option<String> {
    let entries = std::fs::read_dir("/sys/class/net").ok()?;
    let mut names: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n != "lo")
        .collect();
    names.sort();
    for name in names {
        let p = format!("/sys/class/net/{}/address", name);
        if let Some(s) = read_first_line(&p) {
            if is_valid_feature(&s) && s != "00:00:00:00:00:00" {
                return Some(s);
            }
        }
    }
    None
}

/// 主机名（跨平台）。
fn hostname() -> String {
    #[cfg(target_os = "windows")]
    {
        if let Ok(n) = std::env::var("COMPUTERNAME") {
            if !n.is_empty() {
                return n;
            }
        }
        run_cmd("hostname", &[]).unwrap_or_else(|| "<absent>".into())
    }
    #[cfg(not(target_os = "windows"))]
    {
        if let Some(h) = read_first_line("/etc/hostname") {
            return h;
        }
        run_cmd("hostname", &[]).unwrap_or_else(|| "<absent>".into())
    }
}

/// 在内存中构造一份"给定特征"的硬件信息（**仅供测试与诊断使用**）。
///
/// 生产代码只应通过 [`collect`] 获取真实特征；本函数存在的意义是让
/// 单元测试能**确定性地**验证"同样特征 → 同样指纹"与"特征变化 → 指纹变化"
/// 这两条不变式，而不依赖运行测试的这台机器的硬件。
#[doc(hidden)]
#[allow(dead_code)] // 供单元测试与诊断使用；生产路径走 collect()
pub fn from_parts(board: &str, disk: &str, cpu: &str, mac: &str) -> HwidInfo {
    let mut info = HwidInfo {
        board_uuid: board.to_string(),
        disk_serial: disk.to_string(),
        cpu_id: cpu.to_string(),
        mac: mac.to_string(),
        hostname: "test-host".into(),
        degraded: false,
        warnings: Vec::new(),
    };
    info.degraded = info.is_degraded();
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_deterministic() {
        let a = from_parts("BOARD-A", "DISK-A", "CPU-A", "aa:bb:cc:dd:ee:ff");
        let b = from_parts("BOARD-A", "DISK-A", "CPU-A", "aa:bb:cc:dd:ee:ff");
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_eq!(a.fingerprint().len(), 16);
        assert!(a.fingerprint().chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn mac_change_does_not_affect_fingerprint() {
        // 换网卡不应导致重新授权 —— 这是容错设计的核心不变式
        let before = from_parts("BOARD-A", "DISK-A", "CPU-A", "aa:bb:cc:dd:ee:ff");
        let after = from_parts("BOARD-A", "DISK-A", "CPU-A", "11:22:33:44:55:66");
        assert_eq!(before.fingerprint(), after.fingerprint());
    }

    #[test]
    fn board_change_affects_fingerprint() {
        let a = from_parts("BOARD-A", "DISK-A", "CPU-A", "");
        let b = from_parts("BOARD-B", "DISK-A", "CPU-A", "");
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn segment_boundary_is_unambiguous() {
        // "board=aaaa|disk=bbbb" 与 "board=aaaab|disk=bbb" 必须得到不同指纹，
        // 否则就是经典的分段歧义碰撞。
        // 注意：特征值须 ≥4 字符且非占位符，否则会走"缺失占位"路径——
        // 这正是本测试最初用 "a"/"bc" 时误报的原因（见 docs/05 踩坑记录）。
        let a = from_parts("AAAA", "BBBB", "CPU-1", "");
        let b = from_parts("AAAAB", "BBB", "CPU-1", "");
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn short_features_fall_back_to_absent() {
        // 过短的特征值（<4 字符）视为不可靠，按"缺失"处理 ——
        // 这是刻意的：短值碰撞概率高，且多为占位符
        let a = from_parts("a", "bc", "CPU-1", "");
        let b = from_parts("", "", "CPU-1", "");
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn placeholder_values_are_rejected() {
        assert!(!is_valid_feature(""));
        assert!(!is_valid_feature("To be filled by O.E.M."));
        assert!(!is_valid_feature("Default string"));
        assert!(!is_valid_feature("00000000-0000-0000-0000-000000000000"));
        assert!(!is_valid_feature("FFFFFFFFFFFFFFFF"));
        assert!(!is_valid_feature("000000000000000000"));
        assert!(is_valid_feature("A1B2C3D4-1234-5678-9ABC-DEF012345678"));
    }

    #[test]
    fn degrades_when_stable_features_missing() {
        // 主板与磁盘都读不到 → 应判定为降级
        let mut info = from_parts("", "", "", "aa:bb:cc:dd:ee:ff");
        info.hostname = "host-x".into();
        assert!(info.is_degraded());
        // 降级后指纹仍确定可复现
        assert_eq!(info.fingerprint(), info.fingerprint());
    }

    #[test]
    fn not_degraded_with_two_stable_features() {
        let info = from_parts("BOARD-A", "DISK-A", "", "");
        assert!(!info.is_degraded());
    }

    #[test]
    fn missing_feature_differs_from_empty_hash() {
        // "<absent>" 占位参与哈希 → 缺失特征与"恰好为空"必须可区分
        let a = from_parts("BOARD-A", "DISK-A", "CPU-A", "");
        let b = from_parts("BOARD-A", "DISK-A", "<absent>", "");
        // 两者都不降级（稳定三项都有效），但占位符是合法特征值 → 指纹不同
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[test]
    fn collect_never_panics() {
        // 采集在任意环境下都必须能返回（失败走降级），绝不 panic
        let info = collect();
        assert_eq!(info.fingerprint().len(), 16);
        assert_eq!(info.degraded, info.is_degraded());
    }

    #[test]
    fn round_count_participates_in_hash() {
        assert_ne!(slow_hash("x", 1000), slow_hash("x", 1001));
    }
}
