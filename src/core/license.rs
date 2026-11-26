//! 密钥机制与开发者模式（v1.5.1）。
//!
//! # 设计目标
//!
//! 1. **密钥只存哈希**：源码中不出现任何明文密钥，只保存一枚"密钥指纹"
//!    （`LICENSE_FINGERPRINT`）。使用者必须通过 `--devkey <明文>` 传入，
//!    进程内即时求哈希后与指纹做常量时间比较，比对完即丢弃明文。
//! 2. **错误密钥静默降级**：密钥不匹配时**不报错、不提示、不退出**，
//!    程序按完全正常的方式启动（只是开发者模式保持锁定）。这样攻击者
//!    无法通过"试错 + 观察反馈"来爆破 —— 没有反馈信道，穷举成本全在
//!    本地计算上。
//! 3. **慢哈希**：单次校验做 `KDF_ROUNDS` 轮 FNV-1a 迭代（默认 20 万轮，
//!    约数十毫秒量级），把在线爆破速率压到可接受范围。FNV 本身不是密码学
//!    哈希，但作为"给暴力枚举加一道计算税"的手段足够，且**零依赖**。
//! 4. **开发者模式是可上锁的状态机**：解锁 ≠ 一劳永逸。提供 `lock()`，
//!    且解锁状态写入哈希链审计（actor = `devmode`），留下不可抵赖的痕迹。
//!
//! # 安全边界说明（对应《自我约束文档》规则 9）
//!
//! 规则 9 要求"安全边界只紧不松"。开发者模式**确实**放松了边界，因此
//! 本模块强制叠加**三重条件**，缺一不可：
//!
//! | 条件 | 含义 | 由谁保证 |
//! |---|---|---|
//! | `--devkey` 匹配 | 持有密钥 | `License::verify` |
//! | 请求来自回环地址 | `127.0.0.1` / `::1` | `http::is_loopback` |
//! | 传入 `--i-know-the-risk` | 启动时显式确认风险 | `main.rs` |
//!
//! 三者任意一条不满足，`dev_mode` 恒为 `Locked`，程序其余功能不受影响。

use std::sync::atomic::{AtomicBool, Ordering};

/// 密钥指纹（哈希值，非明文）。
///
/// # 如何更换密钥（v1.9.1 起改为构建期注入）
///
/// 1. 选定新明文密钥，例如 `my-new-secret`；
/// 2. 运行 `sports-meet --devkey-fingerprint my-new-secret` 读取指纹；
/// 3. 把指纹写入项目根目录 `keys/devkey.fp`（一行，16 位十六进制）；
/// 4. 重新编译。`keys/` 目录**绝不进任何交付包**（与 issuer.key 同级保管）。
///
/// 回退策略（build.rs 决定）：
/// * debug/test 构建：回退到演示密钥 `THZX-2026-DEV` 的指纹（仅本地开发用）；
/// * release 构建：**空串** —— 任何密钥都不匹配，开发者模式整体停用。
///   发行包不再内置演示密钥（v1.9.1 加固，修复"演示密钥随产品分发"问题）。
mod devfp {
    include!(concat!(env!("OUT_DIR"), "/devkey_fp.rs"));
}

pub const LICENSE_FINGERPRINT: &str = devfp::DEVKEY_FINGERPRINT;

/// 本构建是否配置了开发者密钥指纹。
///
/// 为 `false`（发行构建缺 `keys/devkey.fp`）时，开发者模式不可用，
/// `status_json_fields` 会如实上报"未配置"。
pub const DEVKEY_CONFIGURED: bool = devfp::DEVKEY_CONFIGURED;

/// 慢哈希迭代轮数。
///
/// 20 万轮 FNV-1a 在实测环境（`-O` 构建）约 **30 ms** —— 用户几乎无感，
/// 但把爆破速率压到约 30 次/秒/线程级。每次迭代都把上一轮结果混入，
/// 避免化简。
pub const KDF_ROUNDS: u32 = 200_000;

/// 慢哈希使用的内部盐值（与审计模块的链式哈希刻意区分开）。
const KDF_SALT: &str = "sports-meet::license::v1.5.1";

/// 从原始字节出发的 FNV-1a 64 单步（避免为每个字节分配字符串）。
fn fnv1a64_bytes(mut h: u64, bytes: &[u8]) -> u64 {
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

/// 慢哈希：把 `input` 与盐反复迭代 `rounds` 轮，返回 16 位小写十六进制。
///
/// 迭代方式为 `h = FNV1a(h_as_bytes || salt || input)`，每一轮都依赖
/// 上一轮的全部输出，因此无法通过预计算中间表来加速（无彩虹表空间）。
pub fn slow_hash(input: &str, rounds: u32) -> String {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    let mut h = fnv1a64_bytes(OFFSET_BASIS, input.as_bytes());
    for i in 0..rounds {
        // 把轮序号也拌进去，进一步打散不同轮次之间的结构相似性
        h = fnv1a64_bytes(h, KDF_SALT.as_bytes());
        h = fnv1a64_bytes(h, &i.to_le_bytes());
        h = fnv1a64_bytes(h, input.as_bytes());
    }
    format!("{:016x}", h)
}

/// 按生产参数（`KDF_ROUNDS`）计算指纹，供 CLI 工具与测试使用。
pub fn fingerprint(input: &str) -> String {
    slow_hash(input, KDF_ROUNDS)
}

/// 常量时间字符串比较（长度不同直接返回 false，长度本身不是秘密）。
fn const_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// 开发者模式锁定状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevMode {
    /// 未解锁（默认）。所有安全边界按常规执行。
    Locked,
    /// 已解锁。跳过二次确认与危险操作限制，全部动作写审计。
    Unlocked,
}

impl DevMode {
    pub fn tag(self) -> &'static str {
        match self {
            DevMode::Locked => "locked",
            DevMode::Unlocked => "unlocked",
        }
    }

    /// 是否已解锁。供 `http::dispatch_inner` 与诊断接口使用。
    pub fn is_unlocked(self) -> bool {
        matches!(self, DevMode::Unlocked)
    }
}

/// 密钥持有者与开发者模式状态机。
///
/// # 状态来源
///
/// `status()` 的返回值由三个独立输入共同决定，任缺其一即为 `Locked`：
/// * `enabled`  —— 启动参数是否带 `--devkey`（且匹配指纹）
/// * `risk_acked` —— 是否带 `--i-know-the-risk`
/// * `unlocked` —— 运行期是否通过 `unlock()` 上锁/解锁
pub struct License {
    /// 密钥是否匹配（`--devkey` 的校验结果）。
    enabled: bool,
    /// 使用者是否显式确认知晓风险。
    risk_acked: bool,
    /// 运行期解锁状态。
    unlocked: AtomicBool,
    /// 最近一次成功解锁的 `--devkey` 派生出的流密钥种子。
    ///
    /// 数据加密需要一把"能复现的"密钥，而明文密钥用完即弃，故在首次
    /// 校验通过时立刻派生出流密钥种子并缓存于此。未解锁时为 `None`。
    stream_seed: Option<String>,
}

impl License {
    /// 创建密钥持有者。
    ///
    /// * `key`：命令行传入的明文密钥（`None` 表示未传 `--devkey`）
    /// * `risk_acked`：是否传了 `--i-know-the-risk`
    ///
    /// 密钥不匹配时**不打印任何提示**，仅 `enabled = false`。
    ///
    /// v1.9.1：`LICENSE_FINGERPRINT` 为空（发行构建未配置 `keys/devkey.fp`）
    /// 时视为"本构建无开发者密钥" —— 不做哈希计算，开发者模式整体停用。
    /// 这一分支同时挡掉"照抄文档里的演示密钥就能解锁"的路径。
    pub fn new(key: Option<&str>, risk_acked: bool) -> Self {
        if LICENSE_FINGERPRINT.is_empty() {
            return Self {
                enabled: false,
                risk_acked,
                unlocked: AtomicBool::new(false),
                stream_seed: None,
            };
        }
        let (enabled, seed) = match key {
            Some(k) if !k.is_empty() => {
                let fp = fingerprint(k);
                if const_time_eq(&fp, LICENSE_FINGERPRINT) {
                    // 派生流密钥种子：与指纹同源但换盐，避免"指纹泄露
                    // 即可推出加密密钥"这类线性关系。
                    (true, Some(slow_hash(&format!("{}::stream", k), 1)))
                } else {
                    (false, None)
                }
            }
            _ => (false, None),
        };
        Self {
            enabled,
            risk_acked,
            unlocked: AtomicBool::new(false),
            stream_seed: seed,
        }
    }

    /// 密钥是否正确（`--devkey` 校验通过）。
    pub fn key_ok(&self) -> bool {
        self.enabled
    }

    /// 是否显式确认了风险（`--i-know-the-risk`）。
    ///
    /// 当前 `status_json_fields()` 直接读取字段完成同样的事；本方法是
    /// 给外部调用方（如将来新增的扩展）一个语义明确的只读访问器。
    #[allow(dead_code)]
    pub fn risk_acked(&self) -> bool {
        self.risk_acked
    }

    /// 三重条件是否齐备 —— 只有齐备时**才允许**调用 `unlock()`。
    ///
    /// 注意这里是"准入门槛"，不代表已解锁。
    pub fn can_unlock(&self) -> bool {
        self.enabled && self.risk_acked
    }

    /// 当前开发者模式状态（不含来源判定，来源由 `http::is_loopback` 负责）。
    pub fn mode(&self) -> DevMode {
        if self.can_unlock() && self.unlocked.load(Ordering::SeqCst) {
            DevMode::Unlocked
        } else {
            DevMode::Locked
        }
    }

    /// 尝试解锁。成功返回 `true`。
    ///
    /// 调用方**必须先**自行判定请求来自回环地址；本方法只检查
    /// 密钥与风险确认两项，因为来源属于传输层信息，不该由本模块臆测。
    pub fn unlock(&self) -> bool {
        if !self.can_unlock() {
            return false;
        }
        self.unlocked.store(true, Ordering::SeqCst);
        true
    }

    /// 上锁。返回此前是否处于解锁状态。
    pub fn lock(&self) -> bool {
        self.unlocked.swap(false, Ordering::SeqCst)
    }

    /// 供数据保险库使用的流密钥种子。
    ///
    /// **只有密钥正确时才返回 `Some`** —— 未持密钥的运行实例无法解密
    /// 加密数据，这是"数据文件加密"能真正挡住拷走数据盘的原因。
    pub fn stream_seed(&self) -> Option<&str> {
        self.stream_seed.as_deref()
    }

    /// 供 `/api/dev/status` 返回的脱敏状态（**绝不含密钥或种子**）。
    ///
    /// 返回 `(&'static str, Json)` 而非字符串对，是为了让 JSON 里
    /// 布尔值保持 `true/false`、数字保持数值 —— 早期版本把它全转成
    /// 字符串，前端拿到 `"false"` 做真值判断时**永远为真**，是个典型的
    /// 隐蔽坑（`"false"` 在 JS 里是 truthy）。
    pub fn status_json_fields(&self) -> Vec<(&'static str, crate::core::json::Json)> {
        use crate::core::json::Json;
        vec![
            ("key_present", Json::Bool(self.enabled)),
            ("risk_acked", Json::Bool(self.risk_acked)),
            ("can_unlock", Json::Bool(self.can_unlock())),
            ("dev_mode", Json::s(self.mode().tag())),
            (
                "fingerprint_prefix",
                // 只暴露前 4 位，便于运维核对"装的是不是同一把密钥"，
                // 不足以反推明文。未配置指纹（发行构建缺 keys/devkey.fp）
                // 时如实上报，避免对空串切片 panic。
                Json::s(if LICENSE_FINGERPRINT.is_empty() {
                    "（本构建未配置开发者密钥）".to_string()
                } else {
                    LICENSE_FINGERPRINT[..4].to_string()
                }),
            ),
            ("kdf_rounds", Json::Int(KDF_ROUNDS as i64)),
            // v1.9.1：发行构建是否内置了开发者密钥指纹。
            // 为 false 时 `--devkey` 一律无效（见 build.rs::gen_devkey_fp）。
            ("devkey_configured", Json::Bool(DEVKEY_CONFIGURED)),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 演示密钥与指纹的对应关系（见 docs/12 说明）。
    const DEMO_KEY: &str = "THZX-2026-DEV";

    #[test]
    fn fingerprint_is_deterministic() {
        // 同一输入多次调用必须完全一致（否则密钥无法复现）
        let a = slow_hash(DEMO_KEY, 1000);
        let b = slow_hash(DEMO_KEY, 1000);
        assert_eq!(a, b);
        assert_eq!(a.len(), 16);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint_rejects_wrong_rounds() {
        // 轮数不同 → 结果不同（证明轮数是参与运算的，不是装饰参数）
        assert_ne!(slow_hash(DEMO_KEY, 1000), slow_hash(DEMO_KEY, 1001));
    }

    #[test]
    fn demo_key_matches_constant() {
        // v1.9.1 起指纹由 build.rs 注入：发行构建（release）未配置
        // keys/devkey.fp 时为空串 —— 演示密钥校验只对配置了指纹的构建有意义。
        if LICENSE_FINGERPRINT.is_empty() {
            println!("本构建未配置开发者密钥指纹（预期：release 无 keys/devkey.fp），跳过");
            return;
        }
        // 这条测试同时充当"指纹常量没写错"的守门人：
        // 若有人改了 LICENSE_FINGERPRINT 却忘了同步文档，这里会红。
        assert_eq!(fingerprint(DEMO_KEY), LICENSE_FINGERPRINT);
    }

    /// v1.9.1：空指纹（发行构建未配置 keys/devkey.fp）必须锁死开发者模式，
    /// 且不因指纹为空而 panic。
    #[test]
    fn empty_fingerprint_locks_dev_mode() {
        if !LICENSE_FINGERPRINT.is_empty() {
            return; // 仅在"未配置指纹"的构建里运行
        }
        let lic = License::new(Some(DEMO_KEY), true);
        assert!(!lic.key_ok());
        assert!(!lic.can_unlock());
        assert!(!lic.unlock());
        assert_eq!(lic.mode(), DevMode::Locked);
        // 状态输出不得 panic，且要如实上报"未配置"
        let fields = lic.status_json_fields();
        let prefix = fields
            .iter()
            .find(|(k, _)| *k == "fingerprint_prefix")
            .map(|(_, v)| v.to_string())
            .unwrap_or_default();
        assert!(prefix.contains("未配置"), "应上报未配置：{}", prefix);
    }

    #[test]
    fn wrong_key_is_silent_and_locked() {
        let lic = License::new(Some("wrong-key"), true);
        assert!(!lic.key_ok());
        assert!(!lic.can_unlock());
        assert_eq!(lic.mode(), DevMode::Locked);
        assert!(lic.stream_seed().is_none());
        // 即使显式调用 unlock 也必须失败
        assert!(!lic.unlock());
        assert_eq!(lic.mode(), DevMode::Locked);
    }

    #[test]
    fn no_key_means_locked() {
        let lic = License::new(None, true);
        assert!(!lic.key_ok());
        assert_eq!(lic.mode(), DevMode::Locked);
        // 空字符串等同于未传
        let lic2 = License::new(Some(""), true);
        assert!(!lic2.key_ok());
    }

    #[test]
    fn correct_key_without_risk_ack_cannot_unlock() {
        // 三重条件之一缺失 → 不得解锁
        let lic = License::new(Some(DEMO_KEY), false);
        assert!(lic.key_ok());
        assert!(!lic.risk_acked());
        assert!(!lic.can_unlock());
        assert!(!lic.unlock());
        assert_eq!(lic.mode(), DevMode::Locked);
    }

    #[test]
    fn correct_key_with_risk_ack_unlocks_and_locks() {
        let lic = License::new(Some(DEMO_KEY), true);
        assert!(lic.can_unlock());
        assert_eq!(lic.mode(), DevMode::Locked); // 默认仍锁定
        assert!(lic.unlock());
        assert_eq!(lic.mode(), DevMode::Unlocked);
        assert!(lic.lock()); // 首次上锁返回 true
        assert_eq!(lic.mode(), DevMode::Locked);
        assert!(!lic.lock()); // 已锁定，再上锁返回 false
    }

    #[test]
    fn stream_seed_only_with_correct_key() {
        let ok = License::new(Some(DEMO_KEY), true);
        let s1 = ok.stream_seed().expect("正确密钥应能派生出种子");
        let s2 = ok.stream_seed().unwrap();
        assert_eq!(s1, s2, "派生必须可复现");
        assert_eq!(s1.len(), 16);

        let bad = License::new(Some("nope"), true);
        assert!(bad.stream_seed().is_none());
    }

    #[test]
    fn status_fields_never_leak_secret() {
        let lic = License::new(Some(DEMO_KEY), true);
        let fields = lic.status_json_fields();
        let joined: String = fields
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(";");
        // 明文密钥与完整种子都绝不能出现在状态输出里
        assert!(!joined.contains(DEMO_KEY));
        assert!(!joined.contains(LICENSE_FINGERPRINT));
        assert!(!joined.contains(lic.stream_seed().unwrap()));
    }

    #[test]
    fn status_fields_keep_native_types() {
        // 回归：布尔字段一度被序列化成字符串 "false"，而 JS 里
        // `"false"` 是 truthy，前端真值判断会全部走反。
        let lic = License::new(Some(DEMO_KEY), true);
        let f = lic.status_json_fields();
        let get = |k: &str| f.iter().find(|(n, _)| *n == k).map(|(_, v)| v.clone());
        assert!(matches!(
            get("key_present"),
            Some(crate::core::json::Json::Bool(true))
        ));
        assert!(matches!(
            get("risk_acked"),
            Some(crate::core::json::Json::Bool(true))
        ));
        assert!(matches!(
            get("can_unlock"),
            Some(crate::core::json::Json::Bool(true))
        ));
        assert!(matches!(
            get("kdf_rounds"),
            Some(crate::core::json::Json::Int(_))
        ));
        // dev_mode / 指纹前缀仍是字符串
        assert!(matches!(
            get("dev_mode"),
            Some(crate::core::json::Json::Str(_))
        ));
    }

    #[test]
    fn const_time_eq_edge_cases() {
        assert!(const_time_eq("", ""));
        assert!(!const_time_eq("", "a"));
        assert!(!const_time_eq("abc", "abd"));
    }

    /// 打印指纹的小工具：`cargo test print_fingerprint -- --nocapture`
    #[test]
    fn print_fingerprint() {
        println!(
            "演示密钥 {} 的指纹 = {}（KDF_ROUNDS={}）",
            DEMO_KEY,
            fingerprint(DEMO_KEY),
            KDF_ROUNDS
        );
        // 仅为可读性，不做断言
    }
}
