//! 免费试用密钥与分散冗余记录（v1.8.2 新增）。
//!
//! # 需求落地
//!
//! 1. **内置免费试用密钥** `ky-2026tonghezhongxue`，试用 **30 分钟**，**一次性**；
//! 2. key 的**真实记录 12 份**，分散在系统各个角落；
//! 3. **120 份假记录**混淆，让攻击者分不清哪份是真的；
//! 4. 记录**伪装成系统组件**（文件名与去向都像系统自己的日志/缓存）。
//!
//! # 为什么记录要分散 + 伪装
//!
//! "一次性"的本质是**记住"这个试用已经被用掉了"**。只记一处，
//! 用户删掉那个文件就恢复了 —— 等于没做。
//!
//! 分散到多个位置后，攻击者必须**找出并清除全部位置**才能重置试用。
//! 而位置清单只有反编译才能看到；再叠加 120 份假记录后，
//! "按文件名筛"这一招也失效了 —— 只能逐个解密验证。
//!
//! # 伪装成系统组件（安全边界，必读）
//!
//! 记录的文件名刻意做成 `ntuser.dat.LOG1`、`PerfDisk.dat`、`IconCache.db`
//! 这类**系统组件风格**的名字，混在用户目录里不显眼。
//!
//! > **边界声明**：伪装**不等于**写真正的系统文件。
//! > 本模块**只写入用户可写目录**（`%APPDATA%` / `%LOCALAPPDATA%` /
//! > `%TEMP%` / `Documents` / 程序自身目录 / `HKCU` 注册表），**绝不**触碰
//! > `C:\Windows\System32`、`C:\Program Files` 或任何真实系统文件 ——
//! > 那是破坏性操作，会触发权限提升提示，也可能损坏系统。
//! > 文件名"像"系统组件，但物理位置始终在**用户空间**。
//!
//! # 一致性模型（关键设计）
//!
//! 多份记录最大的风险是**互相矛盾**：一份说"已用完"、另一份说"刚开始"，
//! 程序该听谁的？本模块采用**最严格原则**：
//!
//! ```text
//!   判定时（读取）：
//!     · 任一份记录 consumed == true       → 整体判定已消耗
//!     · 否则取所有记录中**最早**的 started_at → 对攻击者最不利
//!     · 任一份与本机指纹不符               → 忽略该份（可能是别处拷来的）
//!
//!   写入时：
//!     · 同一状态写到**所有**位置
//! ```
//!
//! 因此删掉其中几份**不会**让试用复活 —— 剩下的份仍然作数。
//!
//! # 诚实的局限（必须说明）
//!
//! * **纯本地的"一次性"不是真正的一次性**。若攻击者反编译拿到全部位置
//!   清单，可一次性清空所有记录与假记录。本方案把成本从"删一个文件"
//!   抬到"定位并清除 130+ 个分散文件 + 注册表项"，但**不保证**不可重置。
//! * 真正的一次性必须**服务端参与**（联网登记试用消耗）。
//!   本模块提供 [`TrialPolicy::require_online_confirm`] 开关：开启后试用
//!   密钥首次使用必须向服务端登记，服务端拒绝重复登记 —— 那才是硬一次性。
//! * 假记录只增加**定位成本**，动态分析下可被逐一验证后排除。

use std::path::{Path, PathBuf};

use crate::core::aim::channel as ch;
use crate::core::aim::hwid;
use crate::core::json::Json;

// ---------------------------------------------------------------------------
// 常量
// ---------------------------------------------------------------------------

/// 内置试用密钥明文。
///
/// **不在二进制里以明文出现**：只存其 XOR 混淆形式（见 [`TRIAL_KEY_MASKED`]），
/// 这样 `strings` 扫不到试用密钥本身。
pub const TRIAL_KEY_PLAINTEXT: &str = "ky-2026tonghezhongxue";

/// 试用时长（分钟）。
pub const TRIAL_MINUTES: i64 = 30;

/// 永久免费模式下 `TrialState::Active` 携带的"剩余秒数"哨兵值（v1.9.2）。
///
/// 取 100 年量级：既远大于任何真实倒计时，又不会在 `Active(secs)` 的
/// 算术里溢出。用哨兵而不是新增枚举变体，是为了让所有既有的
/// `Active(_) => true` 判定点**一行不改**就继续成立。
pub const PERPETUAL_REMAINING: i64 = 100 * 365 * 86400;

/// 试用记录文件魔数。
///
/// 首字节取 `0x89`（与 PNG 同风格），让文件在十六进制编辑器里
/// "看起来像某种二进制格式"，而非一眼可读的明文明细。
pub const TRIAL_MAGIC: [u8; 4] = [0x89, b'T', b'R', b'I'];

/// 试用记录格式版本。
pub const TRIAL_VERSION: u8 = 1;

/// 真实记录的份数（≥10，满足"10 份以上"）。
pub const REAL_SLOTS: usize = 12;

/// 假记录的份数（≥100，满足"100 份以上"）。
pub const FAKE_SLOTS: usize = 120;

/// 试用密钥明文的 XOR 混淆形式（算法同 [`ch::obfuscate`]）。
///
/// 由 `obfuscate(b"ky-2026tonghezhongxue")` 在编译期算出，
/// 由测试 `masked_key_roundtrips_to_plaintext` 守住与明文的一致性。
const TRIAL_KEY_MASKED: [u8; 64] = [
    0x31, 0x3e, 0x4d, 0x3f, 0x1e, 0xf9, 0xc2, 0xe5, 0xdd, 0x31, 0x1f, 0x0d, 0x63, 0x59, 0xa4,
    0x86, 0xe4, 0xd0, 0x28, 0x08, 0x7b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
];

// ---------------------------------------------------------------------------
// 记录结构
// ---------------------------------------------------------------------------

/// 一条试用状态记录（单点存储）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrialRecord {
    /// 试用开始时间（Unix 秒）。0 = 尚未开始。
    pub started_at: i64,
    /// 试用结束时间（Unix 秒）。0 = 尚未开始。
    pub expire_at: i64,
    /// 本机机器指纹的慢哈希（绑定机器，防把记录拷到别处白用）。
    pub hwid_hash: String,
    /// 试用是否已被消耗（一次性标记）。
    pub consumed: bool,
    /// 记录自身的完整性校验（防手工篡改单个字段）。
    pub mac: u64,
}

impl TrialRecord {
    /// 新建一条"刚开始"的记录。
    fn fresh(hwid_hash: String, now: i64) -> TrialRecord {
        let mut r = TrialRecord {
            started_at: now,
            expire_at: now + TRIAL_MINUTES * 60,
            hwid_hash,
            consumed: false,
            mac: 0,
        };
        r.mac = r.compute_mac();
        r
    }

    /// 计算记录 MAC（覆盖全部业务字段，含机器指纹）。
    ///
    /// 用 FNV 而非 HMAC：记录只在**本机**校验，不需要抗伪造 ——
    /// 需要的是"改一个字段就得重算其余字段"，从而提高手工篡改成本。
    fn compute_mac(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let prime: u64 = 0x0000_0100_0000_01b3;
        let mix = |bytes: &[u8], h: &mut u64| {
            for b in bytes {
                *h ^= *b as u64;
                *h = h.wrapping_mul(prime);
            }
        };
        mix(b"sports-meet::trial::record::v1.8.2", &mut h);
        mix(&self.started_at.to_le_bytes(), &mut h);
        mix(&self.expire_at.to_le_bytes(), &mut h);
        mix(self.hwid_hash.as_bytes(), &mut h);
        mix(&[u8::from(self.consumed)], &mut h);
        h
    }

    /// 校验自身完整性。
    fn is_intact(&self) -> bool {
        self.mac == self.compute_mac()
    }

    /// 序列化为 JSON。
    fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("version", Json::Int(TRIAL_VERSION as i64));
        o.set("started_at", Json::Int(self.started_at));
        o.set("expire_at", Json::Int(self.expire_at));
        o.set("hwid_hash", Json::s(self.hwid_hash.clone()));
        o.set("consumed", Json::Bool(self.consumed));
        o.set("mac", Json::s(format!("{:016x}", self.mac)));
        o
    }

    /// 从 JSON 反序列化（**校验 MAC**：不符返回 `None`）。
    fn from_json(j: &Json) -> Option<TrialRecord> {
        let r = TrialRecord {
            started_at: j.get_i64("started_at").unwrap_or(0),
            expire_at: j.get_i64("expire_at").unwrap_or(0),
            hwid_hash: j.get_str("hwid_hash").unwrap_or("").to_string(),
            consumed: j.get_bool("consumed").unwrap_or(false),
            mac: u64::from_str_radix(j.get_str("mac").unwrap_or(""), 16).unwrap_or(0),
        };
        if !r.is_intact() {
            return None;
        }
        Some(r)
    }
}

// ---------------------------------------------------------------------------
// 存储位置（伪装成系统组件）
// ---------------------------------------------------------------------------

/// 一个记录存放位置。
#[derive(Debug, Clone)]
struct Slot {
    /// 位置编号（参与密钥派生，使各位置密文不同）。
    id: u8,
    /// 完整路径。以 `Reg:` 开头表示注册表项。
    path: PathBuf,
    /// 是否注册表位置。
    is_registry: bool,
}

/// 系统组件风格的假文件名表。
///
/// 取名原则：**看起来像 Windows 自己的组件产物**，但**不指向**任何真实
/// 系统文件的路径 —— 全部位于用户可写目录，绝不覆盖系统文件。
const SYSTEMISH_NAMES: [&str; 24] = [
    "ntuser.dat.LOG1",
    "ntuser.ini",
    "PerfDisk.dat",
    "PerfNet.dat",
    "IconCache.db",
    "thumbcache_256.db",
    "UsrClass.dat",
    "Sam.log",
    "SoftwareDistribution.log",
    "DirectX.log",
    "D3DSCache.dll",
    "FontCache.dat",
    "Settings.dat",
    "StateStore.log",
    "WMI_DATA.log",
    "RegistryPolicy.dat",
    "AppxManifest.cache",
    "ResourcePolicy.db",
    "ShellCache.bin",
    "TileCache.log",
    "ActivationStore.dat",
    "DiagnosticLog.db",
    "IndexerLog.log",
    "SearchIndex.dat",
];

/// 位置的"根"抽象：把真实环境变量解析集中到一处。
///
/// **为什么需要它**：记录要散落到 `%APPDATA%`、`%TEMP%`、`HOME` 等真实
/// 用户目录；若测试直接命中这些真实目录，测试之间会**互相污染**
/// （上一个测试留下的记录被下一个测试读到），也无法断言"干净起点"。
///
/// 因此把"根目录"抽成枚举：生产用 [`PathRoot::Real`]（读真实环境变量），
/// 测试用 [`PathRoot::Fake`]（全部落在同一临时目录下的子路径）。
/// 两条路径的**相对结构完全一致**，所以生产代码走的是与测试同一套逻辑。
#[derive(Debug, Clone)]
pub(crate) enum PathRoot {
    /// 真实环境：读 `APPDATA` / `LOCALAPPDATA` / `TEMP` / `HOME` 等。
    Real,
    /// 测试环境：所有根都落到这个临时目录下。
    /// 仅由 crate 内测试构造，故 lib 构建下视为"未构造"。
    #[allow(dead_code)]
    Fake(PathBuf),
}

impl PathRoot {
    /// 取一个"根"（如 `APPDATA` 的等价物）。
    ///
    /// 测试模式下返回 `<base>/<name>`，并保证目录存在。
    fn get(&self, env_key: &str) -> Option<PathBuf> {
        match self {
            PathRoot::Real => std::env::var(env_key).ok().map(PathBuf::from),
            PathRoot::Fake(base) => {
                let p = base.join(env_key.to_ascii_lowercase());
                let _ = std::fs::create_dir_all(&p);
                Some(p)
            }
        }
    }

    /// 可执行文件所在目录。
    fn exe_dir(&self) -> Option<PathBuf> {
        match self {
            PathRoot::Real => std::env::current_exe()
                .ok()
                .and_then(|e| e.parent().map(PathBuf::from)),
            PathRoot::Fake(base) => {
                let p = base.join("exe");
                let _ = std::fs::create_dir_all(&p);
                Some(p)
            }
        }
    }

    /// 是否处于测试模式（测试模式下跳过注册表位置：`reg` 命令在
    /// 真机上会污染用户注册表，绝不能由单元测试触发）。
    #[allow(dead_code)]
    fn is_fake(&self) -> bool {
        matches!(self, PathRoot::Fake(_))
    }
}

/// 枚举全部**真实**记录位置（恰好 `REAL_SLOTS` 个）。
///
/// 覆盖 Windows 与 Linux 各自的多个用户可写目录，**刻意不集中在数据目录** ——
/// 攻击者最可能先想到"程序的数据目录"，那里只放一份兜底。
fn real_slots_in(data_dir: &Path, root: &PathRoot) -> Vec<Slot> {
    let mut v: Vec<Slot> = Vec::with_capacity(REAL_SLOTS);
    let push = |v: &mut Vec<Slot>, p: PathBuf, reg: bool| {
        if v.len() < REAL_SLOTS {
            let id = (v.len() + 1) as u8;
            v.push(Slot {
                id,
                path: p,
                is_registry: reg,
            });
        }
    };

    // —— 1. 程序数据目录（唯一"明显"的位置，仅作兜底）——
    push(&mut v, data_dir.join("DiagnosticLog.db"), false);

    // —— 2. 程序可执行文件所在目录 ——
    if let Some(d) = root.exe_dir() {
        push(&mut v, d.join("FontCache.dat"), false);
    }

    #[cfg(windows)]
    {
        if let Some(a) = root.get("APPDATA") {
            push(&mut v, a.join("Microsoft\\Windows\\usrclass.dat.LOG1"), false);
            push(&mut v, a.join("Microsoft\\Crypto\\RSA\\PerfDisk.dat"), false);
        }
        if let Some(l) = root.get("LOCALAPPDATA") {
            push(&mut v, l.join("Microsoft\\Windows\\Caches\\IconCache.db"), false);
            push(
                &mut v,
                l.join("Microsoft\\Windows\\Explorer\\thumbcache_256.db.LOG1"),
                false,
            );
            push(&mut v, l.join("Packages\\StateStore.log"), false);
        }
        if let Some(p) = root.get("PROGRAMDATA") {
            push(&mut v, p.join("Microsoft\\WMI\\Settings\\PerfNet.dat"), false);
            push(
                &mut v,
                p.join("Microsoft\\Diagnosis\\RegistryPolicy.dat"),
                false,
            );
        }
        if let Some(t) = root.get("TEMP") {
            push(&mut v, t.join("D3DSCache.log"), false);
            push(&mut v, t.join("Cab\\DirectX.log"), false);
        }
        if let Some(u) = root.get("USERPROFILE") {
            push(&mut v, u.join("Documents\\ShellCache.bin"), false);
            push(
                &mut v,
                u.join("AppData\\LocalLow\\Microsoft\\CryptnetUrlCache\\Settings.dat"),
                false,
            );
        }
        // —— 注册表（伪装成系统策略项，均在 HKCU 下，无需管理员权限）——
        // 测试模式跳过：单元测试绝不去改用户真实注册表。
        if !root.is_fake() {
            push(
                &mut v,
                PathBuf::from(
                    "Reg:HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FileExts\\TrialPolicy",
                ),
                true,
            );
            push(
                &mut v,
                PathBuf::from(
                    "Reg:HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\PushNotifications\\StateStore",
                ),
                true,
            );
            push(
                &mut v,
                PathBuf::from(
                    "Reg:HKCU\\Software\\Classes\\Local Settings\\MuiCache\\ResourcePolicy",
                ),
                true,
            );
        }
    }

    #[cfg(unix)]
    {
        if let Some(h) = root.get("HOME") {
            push(&mut v, h.join(".cache/fontconfig/PerfDisk.dat"), false);
            push(
                &mut v,
                h.join(".local/share/gnome-settings-daemon/IconCache.db"),
                false,
            );
            push(&mut v, h.join(".config/dconf/usrclass.dat.LOG1"), false);
            push(
                &mut v,
                h.join(".cache/thumbnails/large/thumbcache_256.db"),
                false,
            );
            push(&mut v, h.join(".local/state/dconf/StateStore.log"), false);
        }
        // 这两个是全局路径：测试模式改到 base 下，避免污染真机
        match root {
            PathRoot::Real => {
                push(&mut v, PathBuf::from("/tmp/.X11-unix/PerfNet.dat"), false);
                push(
                    &mut v,
                    PathBuf::from("/var/tmp/systemd-private/DiagnosticLog.db"),
                    false,
                );
            }
            PathRoot::Fake(base) => {
                push(&mut v, base.join("tmp/.X11-unix/PerfNet.dat"), false);
                push(
                    &mut v,
                    base.join("tmp/systemd-private/DiagnosticLog.db"),
                    false,
                );
            }
        }
    }

    // —— 兜底：环境变量缺失时用编号名补足，仍散落在数据目录子路径下 ——
    // 名字取系统风格名单中的下几个，避免出现 "1.LOG1" 这种一眼可疑的命名。
    let mut extra = 0usize;
    while v.len() < REAL_SLOTS {
        let base = SYSTEMISH_NAMES[(extra + 12) % SYSTEMISH_NAMES.len()];
        extra += 1;
        push(
            &mut v,
            data_dir
                .join("Microsoft")
                .join("Caches")
                .join(format!("{}.{}", base, extra)),
            false,
        );
    }
    v
}

/// 生产路径：读真实环境变量。
#[allow(dead_code)]
fn real_slots(data_dir: &Path) -> Vec<Slot> {
    real_slots_in(data_dir, &PathRoot::Real)
}

/// 生成 `FAKE_SLOTS` 个**假记录**位置。
///
/// 假记录的命名与真记录**同源**（同一套系统风格名 + 编号后缀），
/// 因此"按文件名筛"无法区分真假 —— 只能逐个解密验证。
///
/// **唯一性保证**：目录编号 `i % 8`、名字主干 `i % 24`、后缀 `i % 5`
/// 三者的周期分别是 8 / 24 / 5，两两互素，故 `i` 在 `0..120` 内
/// **绝不会**产生重复路径（否则会互相覆盖，实际落盘数少于 `FAKE_SLOTS`）。
fn fake_slots_in(data_dir: &Path, _root: &PathRoot) -> Vec<Slot> {
    let mut v = Vec::with_capacity(FAKE_SLOTS);
    for i in 0..FAKE_SLOTS {
        let dir = match i % 8 {
            0 => data_dir.join("Microsoft/Windows/Caches"),
            1 => data_dir.join("Microsoft/Windows/Explorer"),
            2 => data_dir.join("Microsoft/Crypto/RSA"),
            3 => data_dir.join("Microsoft/Diagnosis"),
            4 => data_dir.join("Microsoft/WMI"),
            5 => data_dir.join("Packages"),
            6 => data_dir.join("Cab"),
            _ => data_dir.join("LocalLow"),
        };
        let base = SYSTEMISH_NAMES[i % SYSTEMISH_NAMES.len()];
        let name = match i % 5 {
            // 后缀里带 `i`，保证同一 (dir, base) 组合下名字仍唯一
            0 => format!("{}.LOG{}", base, i),
            1 => format!("{}-{}.dat", base, i),
            2 => format!("{}_bak{}.db", base, i),
            3 => format!("{}.{}.cache", base, i),
            _ => format!("{}_tmp{}.tmp", base, i),
        };
        // 假槽位用 200..255 段的编号，与真槽位（1..=12）天然错开
        let id = 200u8.wrapping_add((i % 56) as u8);
        v.push(Slot {
            id,
            path: dir.join(name),
            is_registry: false,
        });
    }
    debug_assert_eq!(
        {
            let mut paths: Vec<String> = v.iter().map(|s| s.path.display().to_string()).collect();
            let n = paths.len();
            paths.sort();
            paths.dedup();
            paths.len() == n
        },
        true,
        "假记录路径出现重复，会导致互相覆盖、实际落盘数 < FAKE_SLOTS"
    );
    v
}

/// 生产路径：假记录位置只依赖数据目录。
#[allow(dead_code)]
fn fake_slots(data_dir: &Path) -> Vec<Slot> {
    fake_slots_in(data_dir, &PathRoot::Real)
}

// ---------------------------------------------------------------------------
// 试用策略与状态
// ---------------------------------------------------------------------------

/// 试用策略。
#[derive(Debug, Clone)]
pub struct TrialPolicy {
    /// 是否允许内置试用密钥。
    pub enabled: bool,
    /// **永久免费模式**（v1.9.2）。
    ///
    /// 开启后：试用不再限时、不再一次性 —— 只要实例授权判定需要它，
    /// 就一直是"可用"状态，且不读写任何试用记录。
    ///
    /// 这是**产品定位的选择**，不是"补丁"：本软件按买断/免费方案发布，
    /// 试用即完整功能，因此不需要计时与消耗标记。旧的限时逻辑（30 分钟、
    /// 一次性、分散冗余记录）保留在代码里，供将来需要"限时演示版"时
    /// 把 `perpetual` 置回 `false` 使用。
    pub perpetual: bool,
    /// 是否要求联网向服务端登记（**真正的一次性**）。
    ///
    /// 开启后：试用密钥首次使用必须联网，由服务端登记"该指纹已用过试用"；
    /// 断网时无法启用试用。关闭后仅靠本地分散记录（可被彻底清除后重置）。
    pub require_online_confirm: bool,
}

impl Default for TrialPolicy {
    fn default() -> Self {
        TrialPolicy {
            enabled: true,
            perpetual: true, // v1.9.2：默认永久免费
            require_online_confirm: false,
        }
    }
}

/// 试用判定结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrialState {
    /// 试用可用（剩余秒数）。
    Active(i64),
    /// 试用已到期（已开始过，且已过 30 分钟）。
    Expired,
    /// 试用已被消耗（一次性已用掉）。
    Consumed,
    /// 本机从未用过试用。
    NeverUsed,
    /// 试用功能被策略关闭。
    Disabled,
}

impl TrialState {
    /// 当前是否处于可用的试用中。
    ///
    /// v1.9.2：永久免费模式下 `gather()` 恒返回 `Active`，因此这里无需特判。
    pub fn is_granted(&self) -> bool {
        matches!(self, TrialState::Active(_))
    }

    /// 供界面展示的一句话。
    pub fn message(&self) -> String {
        match self {
            // v1.9.2：永久免费模式下剩余秒数用 `PERPETUAL_REMAINING` 表示，
            // 展示为"永久"而不是一个会让人以为在倒计时的数字。
            TrialState::Active(secs) if *secs >= PERPETUAL_REMAINING => {
                "免费使用中（无到期限制）".into()
            }
            TrialState::Active(secs) => {
                let (m, s) = (secs / 60, secs % 60);
                if m > 0 {
                    format!("免费试用中，剩余 {} 分 {} 秒", m, s)
                } else {
                    format!("免费试用中，剩余 {} 秒", s)
                }
            }
            TrialState::Expired => "免费试用已结束（30 分钟已用尽）".into(),
            TrialState::Consumed => "免费试用已使用过（一次性，每台机器仅一次）".into(),
            TrialState::NeverUsed => "尚未使用免费试用".into(),
            TrialState::Disabled => "本实例未启用免费试用".into(),
        }
    }
}

// ---------------------------------------------------------------------------
// 试用管理器
// ---------------------------------------------------------------------------

/// 试用管理器：负责判定、启用、落盘（分散 + 冗余）。
pub struct TrialManager {
    /// 本机机器指纹（完整值，仅内部使用，不落盘）。
    /// 保留它是为了将来需要"指纹参与本地派生"时不改结构体。
    #[allow(dead_code)]
    hwid: String,
    /// 本机机器指纹的慢哈希（写进记录，避免明文指纹落盘）。
    hwid_hash: String,
    /// 程序数据目录。
    data_dir: PathBuf,
    /// 策略。
    policy: TrialPolicy,
    /// 位置根（生产＝真实环境变量；测试＝临时目录，避免污染真机）。
    root: PathRoot,
}

impl TrialManager {
    /// 构造管理器（**不做任何 IO**）。用于生产环境。
    pub fn new(hwid: &str, data_dir: &Path, policy: TrialPolicy) -> TrialManager {
        TrialManager::with_root(hwid, data_dir, policy, PathRoot::Real)
    }

    /// 指定位置根构造（测试用：所有位置落到 `base` 下，不碰真实 HOME）。
    /// 生产代码走 [`TrialManager::new`]；此入口保留给 crate 内测试注入根。
    #[allow(dead_code)]
    pub(crate) fn with_root(
        hwid: &str,
        data_dir: &Path,
        policy: TrialPolicy,
        root: PathRoot,
    ) -> TrialManager {
        TrialManager {
            hwid: hwid.to_string(),
            hwid_hash: hwid::slow_hash(hwid, 20_000),
            data_dir: data_dir.to_path_buf(),
            policy,
            root,
        }
    }

    /// 本管理器当前使用的全部真实位置。
    fn slots(&self) -> Vec<Slot> {
        real_slots_in(&self.data_dir, &self.root)
    }

    /// 本管理器当前使用的全部假位置。
    fn fakes(&self) -> Vec<Slot> {
        fake_slots_in(&self.data_dir, &self.root)
    }

    /// 当前策略。
    pub fn policy(&self) -> &TrialPolicy {
        &self.policy
    }

    /// 机器指纹哈希前 8 位（脱敏展示用）。
    pub fn hwid_short(&self) -> String {
        self.hwid_hash.chars().take(8).collect()
    }

    /// 输入的密钥是否是内置试用密钥。
    ///
    /// 用**常量时间比较**，避免时序侧信道；密钥明文不落盘、不进日志。
    pub fn is_trial_key(&self, key: &str) -> bool {
        let want = ch::deobfuscate(&TRIAL_KEY_MASKED);
        const_time_eq_str(key.trim(), want.trim())
    }

    // -- 存储层 ------------------------------------------------------------

    /// 派生某个位置的记录密钥（**位置号参与**，故各位置密文互不相同）。
    fn slot_key(&self, slot_id: u8) -> String {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let prime: u64 = 0x0000_0100_0000_01b3;
        let mix = |bytes: &[u8], h: &mut u64| {
            for b in bytes {
                *h ^= *b as u64;
                *h = h.wrapping_mul(prime);
            }
        };
        mix(b"sports-meet::trial::slot::v1.8.2", &mut h);
        mix(self.hwid_hash.as_bytes(), &mut h);
        mix(&[slot_id], &mut h);
        format!("{:016x}", h)
    }

    /// 加密一条记录为可落盘的字节串：
    /// `MAGIC(4) ‖ VER(1) ‖ <channel::seal 帧>`。
    fn seal_record(&self, slot_id: u8, r: &TrialRecord) -> Vec<u8> {
        let key = self.slot_key(slot_id);
        let frame = ch::seal(&key, "sysc", 0, r.to_json().to_string().as_bytes());
        let mut out = Vec::with_capacity(frame.len() + 5);
        out.extend_from_slice(&TRIAL_MAGIC);
        out.push(TRIAL_VERSION);
        out.extend_from_slice(&frame);
        out
    }

    /// 解密一个位置的记录。任何一步不符均返回 `None`。
    fn open_record(&self, slot_id: u8, raw: &[u8]) -> Option<TrialRecord> {
        if raw.len() < 5 || raw[..4] != TRIAL_MAGIC || raw[4] != TRIAL_VERSION {
            return None;
        }
        let key = self.slot_key(slot_id);
        let opened = ch::open(&key, &raw[5..]).ok()?;
        let text = String::from_utf8(opened.plaintext).ok()?;
        let j = Json::parse(&text).ok()?;
        let r = TrialRecord::from_json(&j)?;
        // 记录必须属于本机（指纹哈希不符 → 可能是从别处拷来的，忽略）
        if r.hwid_hash != self.hwid_hash {
            return None;
        }
        Some(r)
    }

    /// 读一个位置。
    fn read_slot(&self, slot: &Slot) -> Option<TrialRecord> {
        if slot.is_registry {
            return self.read_registry(slot);
        }
        let raw = std::fs::read(&slot.path).ok()?;
        self.open_record(slot.id, &raw)
    }

    /// 写一个位置（**先写临时文件再原子 rename**，避免半截文件）。
    fn write_slot(&self, slot: &Slot, r: &TrialRecord) -> bool {
        if slot.is_registry {
            return self.write_registry(slot, r);
        }
        if let Some(d) = slot.path.parent() {
            if std::fs::create_dir_all(d).is_err() {
                return false;
            }
        }
        let sealed = self.seal_record(slot.id, r);
        let tmp = slot.path.with_extension("tmpw");
        if std::fs::write(&tmp, &sealed).is_err() {
            return false;
        }
        if std::fs::rename(&tmp, &slot.path).is_err() {
            let _ = std::fs::remove_file(&tmp);
            return false;
        }
        true
    }

    // -- 注册表（Windows）--------------------------------------------------

    #[cfg(windows)]
    fn read_registry(&self, slot: &Slot) -> Option<TrialRecord> {
        let key = slot
            .path
            .to_string_lossy()
            .trim_start_matches("Reg:")
            .to_string();
        let out = std::process::Command::new("reg")
            .args(["query", &key, "/v", "d"])
            .output()
            .ok()?;
        if !out.status.success() {
            return None;
        }
        // 输出形如：  d    REG_BINARY    8A,3F,...
        let text = String::from_utf8_lossy(&out.stdout);
        let mut bytes: Vec<u8> = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if !line.starts_with("d") {
                continue;
            }
            if let Some(idx) = line.find("REG_BINARY") {
                let hex = &line[idx + "REG_BINARY".len()..];
                for tok in hex.split(',') {
                    let t = tok.trim();
                    if t.len() <= 2 {
                        if let Ok(b) = u8::from_str_radix(t, 16) {
                            bytes.push(b);
                        }
                    }
                }
            }
        }
        if bytes.is_empty() {
            return None;
        }
        self.open_record(slot.id, &bytes)
    }

    #[cfg(windows)]
    fn write_registry(&self, slot: &Slot, r: &TrialRecord) -> bool {
        let key = slot
            .path
            .to_string_lossy()
            .trim_start_matches("Reg:")
            .to_string();
        let sealed = self.seal_record(slot.id, r);
        let hex: Vec<String> = sealed.iter().map(|b| format!("{:02x}", b)).collect();
        std::process::Command::new("reg")
            .args([
                "add",
                &key,
                "/v",
                "d",
                "/t",
                "REG_BINARY",
                "/d",
                &hex.join(","),
                "/f",
            ])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    #[cfg(not(windows))]
    fn read_registry(&self, _slot: &Slot) -> Option<TrialRecord> {
        None
    }

    #[cfg(not(windows))]
    fn write_registry(&self, _slot: &Slot, _r: &TrialRecord) -> bool {
        false
    }

    // -- 核心判定 ----------------------------------------------------------

    /// 读取**所有**位置的记录，按"最严格原则"汇总体征。
    ///
    /// 汇总规则：
    /// * 任一份 `consumed == true` → `Consumed`
    /// * 否则取**最早**的 `started_at` 与对应 `expire_at`
    /// * 已过期 → `Expired`；无任何有效记录 → `NeverUsed`
    fn gather(&self) -> TrialState {
        // v1.9.2：永久免费模式 —— 不读任何记录，恒为可用。
        // 也正因为不读，本机历史上残留的"已消耗/已过期"记录不会把用户锁死
        // （从限时演示版升级上来的用户不需要清理任何文件）。
        if self.policy.perpetual {
            return TrialState::Active(PERPETUAL_REMAINING);
        }
        let now = ch::now_secs();
        let mut found: Vec<TrialRecord> = Vec::new();
        for s in &self.slots() {
            if let Some(r) = self.read_slot(s) {
                found.push(r);
            }
        }

        if found.is_empty() {
            return TrialState::NeverUsed;
        }
        // ① 任一份已消耗 → 整体已消耗（删几份翻不了案）
        if found.iter().any(|r| r.consumed) {
            return TrialState::Consumed;
        }
        // ② 取最早的开始时间（想靠删记录"变晚"是没用的）
        let earliest = found.iter().map(|r| r.started_at).min().unwrap_or(0);
        let expire = found
            .iter()
            .filter(|r| r.started_at == earliest)
            .map(|r| r.expire_at)
            .max()
            .unwrap_or(0);

        if expire <= now {
            TrialState::Expired
        } else {
            TrialState::Active(expire - now)
        }
    }

    /// 查询当前试用状态（只读，不落盘）。
    pub fn status(&self) -> TrialState {
        if !self.policy.enabled {
            return TrialState::Disabled;
        }
        self.gather()
    }

    /// 当前是否为永久免费模式。
    pub fn is_perpetual(&self) -> bool {
        self.policy.perpetual
    }

    /// 用内置试用密钥启用试用。
    ///
    /// # 行为
    ///
    /// * 试用已消耗 / 已过期 → `Err(...)`（**不重置**）
    /// * 试用正在进行中 → 返回当前剩余时间（**幂等**，不重新计时）
    /// * 从未用过 → 开始计时，并把状态写入**全部**位置
    ///
    /// # 诚实说明
    ///
    /// "一次性"靠本地分散记录实现。若攻击者反编译后清空全部位置与假记录，
    /// 试用可被重置。要硬一次性请开启
    /// [`TrialPolicy::require_online_confirm`] 并在服务端登记。
    pub fn activate_trial(&self) -> Result<TrialState, String> {
        if !self.policy.enabled {
            return Err("本实例未启用免费试用".into());
        }
        // v1.9.2：永久免费模式下无需"启用"动作，也不写记录。
        if self.policy.perpetual {
            return Ok(TrialState::Active(PERPETUAL_REMAINING));
        }
        let now = ch::now_secs();
        match self.gather() {
            TrialState::NeverUsed => {
                let rec = TrialRecord::fresh(self.hwid_hash.clone(), now);
                let mut ok = 0usize;
                for s in &self.slots() {
                    if self.write_slot(s, &rec) {
                        ok += 1;
                    }
                }
                if ok == 0 {
                    return Err("无法写入试用记录（磁盘权限不足？）".into());
                }
                // 同步撒一批假记录，进一步混淆真实位置
                self.sow_fake_records();
                Ok(TrialState::Active(TRIAL_MINUTES * 60))
            }
            // 幂等：已在试用中，不重新计时
            TrialState::Active(secs) => Ok(TrialState::Active(secs)),
            TrialState::Consumed => Err("免费试用已使用过（一次性，每台机器仅一次）".into()),
            TrialState::Expired => Err("免费试用已结束（30 分钟已用尽）".into()),
            TrialState::Disabled => Err("本实例未启用免费试用".into()),
        }
    }

    /// 把试用标记为已消耗（到期或主动结束时调用）。
    ///
    /// 写入**全部**位置 —— 删几份不影响其余份作数。
    pub fn mark_consumed(&self) {
        let now = ch::now_secs();
        let mut rec = TrialRecord::fresh(self.hwid_hash.clone(), now);
        rec.consumed = true;
        rec.mac = rec.compute_mac();
        for s in &self.slots() {
            let _ = self.write_slot(s, &rec);
        }
    }

    /// 写入 `FAKE_SLOTS` 份假记录。
    ///
    /// 假记录内容是"不属于本机"的随机状态，加密格式与真记录**完全一致** ——
    /// 即使被解密验证，也会因指纹不符被排除，不会干扰真实判定。
    pub fn sow_fake_records(&self) {
        for (i, s) in self.fakes().iter().enumerate() {
            let mut rec = TrialRecord {
                started_at: 0,
                expire_at: 0,
                hwid_hash: format!("fake-{:016x}", (i as u64).wrapping_mul(0x9E37_79B9)),
                consumed: i % 3 == 0,
                mac: 0,
            };
            rec.mac = rec.compute_mac();
            let _ = self.write_slot(s, &rec);
        }
    }

    /// 清空全部记录（含假记录）。
    ///
    /// **仅供测试与"停用试用"的管理操作**，正常业务路径不调用。
    pub fn clear_all(&self) {
        for s in self.slots().iter().chain(self.fakes().iter())
        {
            if !s.is_registry {
                let _ = std::fs::remove_file(&s.path);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 工具函数
// ---------------------------------------------------------------------------

/// 常量时间字符串比较（时序侧信道防护）。
fn const_time_eq_str(a: &str, b: &str) -> bool {
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    if ab.len() != bb.len() {
        return false;
    }
    ab.iter()
        .zip(bb.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 每个测试用独立临时目录，避免互相串扰。
    ///
    /// 关键：管理器使用 [`PathRoot::Fake`] 指向该临时目录，
    /// **绝不写入真实 HOME / 注册表** —— 否则测试之间会互相污染，
    /// 也会污染开发者真机。
    fn tmp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sm-trial-{}-{}-{}",
            tag,
            std::process::id(),
            ch::now_millis()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    /// 构造一个**限时试用**（非永久）的管理器。
    ///
    /// v1.9.2 起 `TrialPolicy::default()` 是永久免费，而本模块大部分用例
    /// 验的恰恰是**限时/一次性**那套逻辑（计时、消耗、分散记录、防篡改）。
    /// 这些逻辑仍在代码里生效（把 `perpetual` 置 false 即可恢复演示版），
    /// 所以测试必须显式关掉永久模式，否则测的就不是原来那条路径了。
    fn mgr(tag: &str) -> (PathBuf, TrialManager) {
        let d = tmp_dir(tag);
        let m = TrialManager::with_root(
            "trial-hwid-0123456789abcdef",
            &d,
            TrialPolicy {
                enabled: true,
                perpetual: false,
                require_online_confirm: false,
            },
            PathRoot::Fake(d.clone()),
        );
        (d, m)
    }

    /// 永久免费模式下的管理器（新增用例用）。
    fn perm_mgr(tag: &str) -> (PathBuf, TrialManager) {
        let d = tmp_dir(tag);
        let m = TrialManager::with_root(
            "trial-hwid-0123456789abcdef",
            &d,
            TrialPolicy::default(),
            PathRoot::Fake(d.clone()),
        );
        (d, m)
    }

    #[test]
    fn trial_key_matches_and_rejects_others() {
        let (_d, m) = mgr("key");
        assert!(m.is_trial_key("ky-2026tonghezhongxue"));
        assert!(m.is_trial_key("  ky-2026tonghezhongxue  "), "应容忍首尾空格");
        assert!(!m.is_trial_key("ky-2026tonghezhongxueX"), "多一位也不行");
        assert!(!m.is_trial_key("ky-2026tonghezhongx"), "少一位也不行");
        assert!(!m.is_trial_key(""));
        assert!(!m.is_trial_key("THZX-P-00000000-000000000000"));
    }

    #[test]
    fn masked_key_roundtrips_to_plaintext() {
        assert_eq!(
            ch::deobfuscate(&TRIAL_KEY_MASKED),
            TRIAL_KEY_PLAINTEXT,
            "混淆数组必须能还原出试用密钥（否则内置试用永远无法通过）"
        );
    }

    #[test]
    fn fresh_machine_never_used() {
        let (_d, m) = mgr("fresh");
        assert_eq!(m.status(), TrialState::NeverUsed);
    }

    #[test]
    fn activate_starts_trial_and_is_idempotent() {
        let (d, m) = mgr("activate");
        match m.activate_trial().expect("应能启用试用") {
            TrialState::Active(secs) => {
                assert!(secs > 29 * 60, "刚启用剩余应接近 30 分钟：{}", secs);
                assert!(secs <= 30 * 60);
            }
            other => panic!("应进入试用，实际 {:?}", other),
        }
        // 幂等：再次启用不重新计时
        let a = m.status();
        let b = m.activate_trial().expect("再次调用应成功");
        assert_eq!(a, b, "重复启用不得重置计时");
        m.clear_all();
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **核心需求**：一次性。启用并标记消耗后，不得再次启用。
    #[test]
    fn trial_is_one_shot() {
        let (d, m) = mgr("oneshot");
        m.activate_trial().expect("首次应成功");
        m.mark_consumed();
        let e = m.activate_trial().expect_err("消耗后不得再启用");
        assert!(e.contains("一次性"), "提示应说明一次性：{}", e);
        assert_eq!(m.status(), TrialState::Consumed);
        m.clear_all();
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **核心需求**：30 分钟时效。到期后不得继续使用。
    #[test]
    fn expired_trial_is_rejected() {
        let (d, m) = mgr("expired");
        let now = ch::now_secs();
        let mut rec = TrialRecord::fresh(m.hwid_hash.clone(), now - 31 * 60);
        rec.expire_at = now - 60; // 已过期 1 分钟
        rec.mac = rec.compute_mac();
        for s in &m.slots() {
            m.write_slot(s, &rec);
        }
        assert_eq!(m.status(), TrialState::Expired);
        assert!(m.activate_trial().is_err(), "过期后不得重新启用");
        m.clear_all();
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **核心需求**：删掉几份记录，试用不会复活。
    #[test]
    fn deleting_some_records_does_not_revive_trial() {
        let (d, m) = mgr("redundant");
        m.activate_trial().expect("应能启用");
        m.mark_consumed();

        let mut removed = 0;
        for s in m.slots().iter().take(6) {
            if !s.is_registry && std::fs::remove_file(&s.path).is_ok() {
                removed += 1;
            }
        }
        assert!(removed >= 4, "至少应删掉几份，实际 {}", removed);
        assert_eq!(
            m.status(),
            TrialState::Consumed,
            "删掉部分记录不得让试用复活"
        );
        m.clear_all();
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **核心需求**：真实记录 ≥10 份。
    #[test]
    fn real_slots_are_at_least_ten() {
        let (_d, m) = mgr("realslots");
        let slots = m.slots();
        assert!(slots.len() >= 10, "真实记录必须 ≥10 份，实际 {}", slots.len());
        // 位置编号必须互不相同（否则密钥相同、密文相同，冗余就失效了）
        let mut ids: Vec<u8> = slots.iter().map(|s| s.id).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), slots.len(), "位置编号不得重复");
    }

    /// **核心需求**：100 份以上假记录，且真实落盘。
    #[test]
    fn fake_records_exceed_100() {
        assert!(FAKE_SLOTS >= 100, "假记录必须 ≥100，实际 {}", FAKE_SLOTS);
        let (d, m) = mgr("fake");
        m.activate_trial().expect("应能启用");
        m.sow_fake_records();

        let slots = m.fakes();
        // ① 槽位定义本身不得有重复路径（重复会互相覆盖）
        let mut defined: Vec<String> = slots.iter().map(|s| s.path.display().to_string()).collect();
        let n = defined.len();
        defined.sort();
        defined.dedup();
        assert_eq!(defined.len(), n, "假记录路径有重复，会互相覆盖");

        // ② 磁盘上**真实存在**的假记录文件数必须 ≥100
        let on_disk = slots
            .iter()
            .filter(|s| !s.is_registry && s.path.exists())
            .count();
        assert!(
            on_disk >= 100,
            "磁盘上应有 ≥100 份假记录，实际 {}（定义 {} 份）",
            on_disk,
            n
        );
        // 假记录不得干扰真实判定
        assert!(matches!(m.status(), TrialState::Active(_)));
        m.clear_all();
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 各位置密文必须**互不相同**（同密文会暴露"这些文件是一伙的"）。
    #[test]
    fn slot_ciphertexts_differ_across_positions() {
        let (d, m) = mgr("cipher");
        m.activate_trial().expect("应能启用");
        let slots = m.slots();
        let mut blobs: Vec<Vec<u8>> = Vec::new();
        for s in &slots {
            if s.is_registry {
                continue;
            }
            if let Ok(b) = std::fs::read(&s.path) {
                // 跳过文件头（魔数+版本），比较密文主体
                if b.len() > 5 {
                    blobs.push(b[5..].to_vec());
                }
            }
        }
        assert!(blobs.len() >= 2, "至少要有两份可比对");
        for i in 0..blobs.len() {
            for j in (i + 1)..blobs.len() {
                assert_ne!(
                    blobs[i], blobs[j],
                    "位置 {} 与 {} 的密文相同，冗余位置会被一眼识破",
                    i, j
                );
            }
        }
        m.clear_all();
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 记录文件必须是**系统组件风格**的名字（不能一看就是本软件的文件）。
    ///
    /// 只检查**文件名**与**相对路径片段**，不检查绝对路径前缀 ——
    /// 绝对路径里可能包含测试临时目录名（含 "trial"）等无关内容。
    #[test]
    fn record_filenames_look_like_system_components() {
        let (_d, m) = mgr("names");
        for s in m.slots() {
            let name = s
                .path
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase())
                .unwrap_or_default();
            assert!(!name.is_empty(), "文件名不得为空");
            // 注册表项：检查键名末段
            let subject = if s.is_registry {
                s.path
                    .to_string_lossy()
                    .rsplit('\\')
                    .next()
                    .unwrap_or("")
                    .to_lowercase()
            } else {
                name.clone()
            };
            for bad in ["sports", "trial", "license", "tonghe", "同和", "aim", "sm_"] {
                assert!(
                    !subject.contains(bad),
                    "文件名/键名不该包含 {:?}（太明显）：{}",
                    bad,
                    s.path.display()
                );
            }
        }
        // 文件名必须"像"系统组件：命中名单，或符合"名单名 + 后缀"的变体。
        // 不能出现自造的、一看就不是系统文件的名字。
        let names: Vec<String> = m
            .slots()
            .iter()
            .filter(|s| !s.is_registry)
            .map(|s| s.path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        for n in &names {
            let lower = n.to_lowercase();
            let looks_ok = SYSTEMISH_NAMES.iter().any(|base| {
                let base_lower = base.to_lowercase();
                // 完整同名，或"名单名 + 后缀/扩展名变体"，或"名单名主干 + 任意后缀"
                lower == base_lower
                    || lower.starts_with(&base_lower)
                    || lower.starts_with(base_lower.split('.').next().unwrap_or(&base_lower))
            });
            assert!(
                looks_ok,
                "文件名 {:?} 不属于系统组件风格（太可疑），全部：{:?}",
                n, names
            );
        }
    }

    /// **边界检查**：只写用户空间，绝不出现 System32 / Program Files。
    #[test]
    fn never_targets_real_system_directories() {
        let (_d, m) = mgr("bounds");
        let all: Vec<Slot> = m
            .slots()
            .into_iter()
            .chain(m.fakes().into_iter())
            .collect();
        for s in all {
            let p = s.path.to_string_lossy().to_lowercase().replace('\\', "/");
            for forbidden in ["windows/system32", "program files", "system32/", "/etc/"] {
                assert!(
                    !p.contains(forbidden),
                    "绝不允许写入真实系统目录 {}：{}",
                    forbidden,
                    s.path.display()
                );
            }
        }
    }

    /// 真记录与假记录的**文件格式完全一致**（否则按格式就能筛出来）。
    #[test]
    fn fake_and_real_records_share_format() {
        let (d, m) = mgr("format");
        m.activate_trial().expect("应能启用");
        m.sow_fake_records();

        let real = m.slots().into_iter().next().unwrap();
        let fake = m.fakes().into_iter().next().unwrap();
        let rb = std::fs::read(&real.path).unwrap();
        let fb = std::fs::read(&fake.path).unwrap();
        assert_eq!(rb[..4], TRIAL_MAGIC);
        assert_eq!(fb[..4], TRIAL_MAGIC, "假记录必须用同一魔数");
        assert_eq!(rb[4], TRIAL_VERSION);
        assert_eq!(fb[4], TRIAL_VERSION, "假记录必须用同一版本号");
        assert!(fb.len() > 5, "假记录必须有实际内容");
        m.clear_all();
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 从别处拷来的记录（指纹不符）必须被忽略。
    #[test]
    fn foreign_record_is_ignored() {
        let (d, m) = mgr("foreign");
        let other = TrialManager::new(
            "another-machine-hwid-zzzz",
            &d,
            TrialPolicy {
                enabled: true,
                perpetual: false,
                require_online_confirm: false,
            },
        );
        other.activate_trial().expect("另一台机器应能启用");
        assert_eq!(
            m.status(),
            TrialState::NeverUsed,
            "别处拷来的记录不得被当成本机的"
        );
        m.clear_all();
        other.clear_all();
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 记录被篡改一个字节后，必须解密失败 / MAC 校验失败。
    #[test]
    fn tampered_record_is_rejected() {
        let (d, m) = mgr("tamper");
        m.activate_trial().expect("应能启用");
        let slot = m.slots().into_iter().next().unwrap();
        let mut raw = std::fs::read(&slot.path).unwrap();
        let mid = raw.len() / 2;
        raw[mid] ^= 0xff;
        assert!(m.open_record(slot.id, &raw).is_none(), "被篡改的记录必须被拒");
        m.clear_all();
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 记录 MAC 必须能发现**单字段**篡改。
    #[test]
    fn record_mac_catches_field_tampering() {
        let mut r = TrialRecord::fresh("h".into(), 1000);
        assert!(r.is_intact());
        r.expire_at += 1;
        assert!(!r.is_intact(), "改到期时间必须被 MAC 发现");
        r.mac = r.compute_mac();
        assert!(r.is_intact(), "重算 MAC 后应恢复完整");
        r.consumed = true;
        assert!(!r.is_intact(), "改消耗标记必须被 MAC 发现");
    }

    /// 位置编号必须实质影响密钥（否则各位置密文相同）。
    #[test]
    fn slot_key_depends_on_slot_id() {
        let (_d, m) = mgr("slotkey");
        assert_ne!(m.slot_key(1), m.slot_key(2), "不同位置密钥必须不同");
        assert_eq!(m.slot_key(1), m.slot_key(1), "同一位置密钥必须确定");
    }

    // ── v1.9.2：永久免费模式 ──────────────────────────────────────────

    /// 永久模式下：从未用过 → 直接可用，且不落任何记录。
    #[test]
    fn perpetual_is_granted_without_touching_disk() {
        let (d, m) = perm_mgr("perm-fresh");
        assert!(m.is_perpetual());
        assert_eq!(m.status(), TrialState::Active(PERPETUAL_REMAINING));
        assert!(m.status().is_granted());
        // 关键：不写记录 —— 否则又回到"能撤销"的状态
        assert!(
            m.slots().iter().all(|s| m.read_slot(s).is_none()),
            "永久模式不应写任何试用记录"
        );
        // 启用动作是幂等的空操作
        assert_eq!(
            m.activate_trial(),
            Ok(TrialState::Active(PERPETUAL_REMAINING))
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 永久模式下：本机残留的「已消耗」记录不得把用户锁死。
    ///
    /// 这是升级路径的实际场景 —— 老用户跑过限时试用、记录还在盘上，
    /// 换到新版本必须直接可用，不能要求他们手工删文件。
    #[test]
    fn perpetual_ignores_consumed_record_on_disk() {
        let (d, m) = perm_mgr("perm-consumed");
        // 先用限时模式把试用跑成"已消耗"
        let limited = TrialManager::with_root(
            "trial-hwid-0123456789abcdef",
            &d,
            TrialPolicy {
                enabled: true,
                perpetual: false,
                require_online_confirm: false,
            },
            PathRoot::Fake(d.clone()),
        );
        let _ = limited.activate_trial();
        limited.mark_consumed();
        assert_eq!(limited.status(), TrialState::Consumed);
        // 永久模式：无视残留记录
        assert_eq!(m.status(), TrialState::Active(PERPETUAL_REMAINING));
        assert!(m.status().is_granted());
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 永久模式下的文案不能暗示倒计时（否则用户会以为还会过期）。
    #[test]
    fn perpetual_message_has_no_countdown() {
        let msg = TrialState::Active(PERPETUAL_REMAINING).message();
        assert!(!msg.contains("剩余"), "永久模式不应显示剩余时间：{}", msg);
        assert!(msg.contains("无到期") || msg.contains("永久"), "应明示不过期：{}", msg);
    }

    /// 策略关闭优先于永久：`enabled=false` 时仍然不可用。
    #[test]
    fn disabled_beats_perpetual() {
        let d = tmp_dir("perm-disabled");
        let m = TrialManager::with_root(
            "hw",
            &d,
            TrialPolicy {
                enabled: false,
                perpetual: true,
                require_online_confirm: false,
            },
            PathRoot::Fake(d.clone()),
        );
        assert_eq!(m.status(), TrialState::Disabled);
        assert!(!m.status().is_granted());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn disabled_policy_blocks_trial() {
        let d = tmp_dir("disabled");
        let m = TrialManager::new(
            "hw",
            &d,
            TrialPolicy {
                enabled: false,
                perpetual: true,
                require_online_confirm: false,
            },
        );
        assert_eq!(m.status(), TrialState::Disabled);
        assert!(m.activate_trial().is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn trial_state_messages_are_readable() {
        assert!(TrialState::Active(1800).message().contains("30 分"));
        assert!(TrialState::Active(45).message().contains("45 秒"));
        assert!(TrialState::Consumed.message().contains("一次性"));
        assert!(TrialState::Expired.message().contains("30 分钟"));
        assert!(TrialState::NeverUsed.message().contains("尚未"));
        assert!(TrialState::granted_is_consistent());
    }

    impl TrialState {
        /// 测试辅助：确认 `is_granted` 只对 `Active` 为真。
        fn granted_is_consistent() -> bool {
            TrialState::Active(1).is_granted()
                && !TrialState::Expired.is_granted()
                && !TrialState::Consumed.is_granted()
                && !TrialState::NeverUsed.is_granted()
                && !TrialState::Disabled.is_granted()
        }
    }
}
