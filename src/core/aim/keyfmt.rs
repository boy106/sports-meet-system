//! 48 位混合字符密钥（v1.9.0 新增 · 便携激活码）。
//!
//! # 形态
//!
//! 密钥共 **48 位**，按「数字 → 英文字母 → 符号 → 汉字」四类**交替**循环
//! 12 组。每位字符从本类的固定字符表中取值：
//!
//! ```text
//!   字符表与容量（每组 = 数字 × 字母 × 符号 × 汉字）：
//!     数字   10 个（0-9）
//!     字母   52 个（a-z A-Z）
//!     符号   32 个
//!     汉字 3500 个（U+4E00 起）
//!   每组容量 10 × 52 × 32 × 3500 = 58,240,000 ≈ 25.8 位
//!   12 组合计 ≈ 309.5 位
//! ```
//!
//! 48 位字符不是"逐位拼比特"，而是作为一个**混合进位制大整数**：
//! 304 位（38 字节）的有效数据被转换成 12 组循环字符，余下的约 5.5 位
//! 容量兼作格式校验（编码不下的值一律判为"无法识别"）。
//!
//! # 密钥里装了什么（全部加密）
//!
//! ```text
//!   38 字节 = 密文(26) + 认证标签(10) + CRC16(2)
//!   明文(26 字节)：
//!     [0]      魔数 0xA7
//!     [1]      (格式版本 << 4) | 授权类型
//!     [2..8]   机器指纹摘要（48 位，绑定本机）
//!     [8..12]  生效日期（Unix 天，0 = 立即）        ← key 有效时间（起）
//!     [12..16] 到期日期（Unix 天，0xFFFFFFFF = 永久）← key 有效时间（止）
//!     [16..19] 累计使用时长上限（秒，0 = 不限）      ← 使用时间
//!     [19..21] 使用次数上限（次，0 = 不限）          ← 使用次数
//!     [21..23] 功能开关位图（16 位）                 ← 使用功能的限制
//!     [23..26] 密钥编号（24 位，签发时随机）
//! ```
//!
//! # 安全设计与诚实声明（必读）
//!
//! **48 位字符装不下 Ed25519 完整签名**（签名 512 位 > 总容量约 310 位），
//! 因此本格式采用「AEAD」：密文 + 80 位认证标签，密钥由
//! **二进制内置主密钥 + 机器指纹**派生（hwid 参与派生 → 换机连解密都失败）。
//!
//! 这意味着：
//! *  Casual 攻击者（改密钥、抄别人的密钥）—— **完全无效**：标签不符即拒；
//! *  能完整逆向二进制的对手 —— 可提取内置主密钥后自行签发。
//!   这是 48 位约束下的工程折中：**抬门槛，非数学不可行**。
//!
//! 对"不可伪造"有硬要求的场景，请改用 `asym.rs` 的 Ed25519 离线许可文件
//! （`data/license.lic`，私钥离线、公钥验签，客户端无签发能力）——
//! 两条路径在 `client.rs` 中并存，文件许可优先级更高。
//!
//! 主密钥**不写死在源码里**：由 `build.rs` 从 `keys/aim.secret`
//! （与 `keys/issuer.key` 同一保管级别，绝不出现在任何交付包中）
//! 读取后掩码注入。缺失时本模块整体停用（返回明确错误），
//! 不影响程序其余功能。

#![allow(dead_code)]

use crate::core::aim::asym::sha512;

/// 密钥位数（字符数）。
pub const KEY_LEN: usize = 48;

/// 每组循环的字符类数：数字、字母、符号、汉字。
const CLASSES: usize = 4;
/// 循环组数：48 / 4 = 12。
const CYCLES: usize = KEY_LEN / CLASSES;

/// 数字表（10 值）。
const DIGITS: &[u8] = b"0123456789";
/// 英文字母表（52 值）。
const LETTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
/// 符号表（32 值）。刻意避开空格与不可打印字符。
const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:'\",.<>/?\\|~`";
/// 汉字表起点（U+4E00）。
const HANZI_BASE: u32 = 0x4E00;
/// 汉字表大小（3500 值）。
const HANZI_COUNT: u32 = 3500;

/// 每组混合进位制的基数：10 × 52 × 32 × 3500。
const CYCLE_RADIX: u64 = DIGITS.len() as u64 * LETTERS.len() as u64 * SYMBOLS.len() as u64 * HANZI_COUNT as u64;

/// 有效数据字节数：38 字节 = 304 位（< 12 组容量 ≈ 309.5 位，余量兼作校验）。
const DATA_BYTES: usize = 38;

/// 明文长度（字节）。
const PLAIN_LEN: usize = 26;
/// 认证标签长度（字节，80 位）。
const TAG_LEN: usize = 10;
/// CRC16 长度（字节）。
const CRC_LEN: usize = 2;

/// 明文魔数。
const PLAIN_MAGIC: u8 = 0xA7;
/// 密钥格式版本（高 4 位）。
const FORMAT_VERSION: u8 = 1;

/// 永久有效的到期日标记。
pub const DAY_PERPETUAL: u32 = 0xFFFF_FFFF;

// ---------------------------------------------------------------------------
// 功能开关（使用功能的限制）
// ---------------------------------------------------------------------------

/// 基础积分（录入/排名/赋分）—— 任何授权都隐含具备。
pub const FEAT_BASIC: u16 = 1 << 0;
/// 导出（Excel / CSV / 报表下载）。
pub const FEAT_EXPORT: u16 = 1 << 1;
/// 智能解析与参赛推荐。
pub const FEAT_SMART: u16 = 1 << 2;
/// 赛程编排。
pub const FEAT_SCHEDULE: u16 = 1 << 3;
/// 打印 / 证书类输出。
pub const FEAT_PRINT: u16 = 1 << 4;
/// 批量能力（整班报名、批量导入）。
pub const FEAT_MULTI: u16 = 1 << 5;
/// 全部功能。
pub const FEAT_ALL: u16 = FEAT_BASIC | FEAT_EXPORT | FEAT_SMART | FEAT_SCHEDULE | FEAT_PRINT | FEAT_MULTI;

/// 授权类型（密钥第 2 字节低 4 位）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyKind {
    /// 试用版（短时效、通常限次数）。
    Trial,
    /// 标准版。
    Standard,
    /// 专业版（全功能）。
    Pro,
    /// 教育版（学校优惠）。
    Edu,
    /// 体验版（演示用途）。
    Demo,
}

impl KeyKind {
    pub fn as_str(self) -> &'static str {
        match self {
            KeyKind::Trial => "trial",
            KeyKind::Standard => "standard",
            KeyKind::Pro => "pro",
            KeyKind::Edu => "edu",
            KeyKind::Demo => "demo",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            KeyKind::Trial => "试用版",
            KeyKind::Standard => "标准版",
            KeyKind::Pro => "专业版",
            KeyKind::Edu => "教育版",
            KeyKind::Demo => "体验版",
        }
    }

    fn from_u8(v: u8) -> Option<KeyKind> {
        match v {
            0 => Some(KeyKind::Trial),
            1 => Some(KeyKind::Standard),
            2 => Some(KeyKind::Pro),
            3 => Some(KeyKind::Edu),
            4 => Some(KeyKind::Demo),
            _ => None,
        }
    }

    /// 是否为短时效类型（映射到授权体系的"临时授权"）。
    pub fn is_short_lived(self) -> bool {
        matches!(self, KeyKind::Trial | KeyKind::Demo)
    }
}

/// 签发参数（`tools/issue_license.py issue-key` 的对侧结构，测试亦用）。
#[derive(Debug, Clone)]
pub struct KeyParams {
    pub kind: KeyKind,
    /// 生效日期（Unix 天；0 = 立即生效）。
    pub valid_from_day: u32,
    /// 到期日期（Unix 天；`DAY_PERPETUAL` = 永久）。
    pub valid_until_day: u32,
    /// 累计使用时长上限（秒；0 = 不限）。
    pub usage_seconds_limit: u32,
    /// 使用次数上限（次；0 = 不限）。
    pub usage_count_limit: u16,
    /// 功能位图。
    pub feature_flags: u16,
    /// 密钥编号（24 位）。
    pub key_id: u32,
}

/// 解析成功并验签通过的密钥许可。
#[derive(Debug, Clone)]
pub struct KeyLicense {
    pub kind: KeyKind,
    pub valid_from_day: u32,
    pub valid_until_day: u32,
    pub usage_seconds_limit: u32,
    pub usage_count_limit: u16,
    pub feature_flags: u16,
    pub key_id: u32,
}

impl KeyLicense {
    /// 是否永久有效。
    pub fn perpetual(&self) -> bool {
        self.valid_until_day == DAY_PERPETUAL
    }

    /// 功能是否允许。
    pub fn feature_allowed(&self, flag: u16) -> bool {
        self.feature_flags & flag != 0
    }

    /// 到期日（Unix 天）换算为 `(年, 月, 日)`；永久返回 None。
    pub fn until_ymd(&self) -> Option<(i64, u32, u32)> {
        if self.perpetual() {
            return None;
        }
        Some(day_to_ymd(self.valid_until_day))
    }

    /// 一句话描述（日志 / 界面用）。
    pub fn describe(&self) -> String {
        let until = match self.until_ymd() {
            Some((y, m, d)) => format!("{:04}-{:02}-{:02}", y, m, d),
            None => "永久".to_string(),
        };
        format!(
            "{}（有效期至 {}，次数上限 {}，时长上限 {}）",
            self.kind.label(),
            until,
            if self.usage_count_limit == 0 {
                "不限".to_string()
            } else {
                self.usage_count_limit.to_string()
            },
            if self.usage_seconds_limit == 0 {
                "不限".to_string()
            } else {
                format!("{} 小时", self.usage_seconds_limit / 3600)
            },
        )
    }
}

/// Unix 天 → 公历日期（Howard Hinnant 算法，与 client.rs 保持一致）。
pub fn day_to_ymd(day: u32) -> (i64, u32, u32) {
    let z = day as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// 当前 Unix 天（日期边界按 UTC 计算，仅用于授权判定）。
pub fn today_day(now_secs: i64) -> u32 {
    (now_secs.div_euclid(86400)) as u32
}

// ---------------------------------------------------------------------------
// 主密钥（build.rs 注入，缺失则停用）
// ---------------------------------------------------------------------------

mod secret {
    include!(concat!(env!("OUT_DIR"), "/keyfmt_secret.rs"));
}

/// 还原主密钥用的异或掩码（刻意与生成文件分离，增大"一眼看穿"的成本）。
///
/// 说明：这是**混淆**而非密码学保护 —— 真正的边界是"提取它需要完整逆向"，
/// 以及完整性自校验（integrity）对 patch 行为的发现能力。
/// 与 `build.rs` 的 `UNMASK` 必须逐字节一致（改这里必须同步改那里）。
const UNMASK: [u8; 32] = [
    0x5a, 0x3c, 0x91, 0xe7, 0x0b, 0xd4, 0x68, 0x2f, 0xab, 0x13, 0x77, 0xc8, 0x4e, 0x9d, 0x21, 0xf6,
    0x8b, 0x54, 0x02, 0xbf, 0x6d, 0x31, 0xa9, 0x1c, 0xef, 0x47, 0x93, 0x25, 0xda, 0x08, 0x71, 0xc4,
];

/// 本构建是否配置了主密钥（`keys/aim.secret` 经 build.rs 注入）。
pub fn master_secret_configured() -> bool {
    secret::CONFIGURED
}

/// 取内置主密钥（未配置时返回全零，调用方应先检查 `master_secret_configured`）。
///
/// 对 `usage` 模块公开：计量文件的加密密钥也由它派生。
pub fn master_secret() -> [u8; 32] {
    let masked = secret::MASTER_MASKED;
    let mut s = [0u8; 32];
    for i in 0..32 {
        s[i] = masked[i] ^ UNMASK[i];
    }
    s
}

/// 排障解锁码（v1.9.1 加固）：由**主密钥**派生，16 位十六进制。
///
/// 为什么需要它：`--aim-allow-unlicensed` 原本是一个裸开关 —— 任何拿到
/// 发行二进制的人加这个参数就免费使用，**连破解都不用**（`strings` 一搜
/// 就有）。这是比"改一处判定"低得多的门槛，等于给白嫖者留了正门。
///
/// 现在：发行构建（release）下，该参数必须同时提供本函数算出的解锁码，
/// 否则拒绝启动。管理员在构建机上用
/// `python3 tools/issue_license.py unlock-code --secret keys/aim.secret`
/// 即可取得；攻击者要伪造，必须先从这个二进制里把掩码后的主密钥抠出来
/// 再还原 —— 而那一步又会被完整性自校验拦住（改二进制必红）。
///
/// 与 48 位密钥同一保管级别：**绝不出现在任何交付文档里**。
pub fn unlock_code(secret: &[u8; 32]) -> String {
    let k = derive(b"SM1ULK", secret, "");
    let tag = mac(&k, b"unlicensed-gate", "");
    let mut s = String::with_capacity(16);
    for b in &tag[..8] {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// 校验排障解锁码（常数时间比较，不泄露前缀匹配长度）。
///
/// 主密钥未配置（源码直接 `cargo build` 且无 `keys/`）时恒为 false：
/// 这种构建本来就该走 `--aim-allow-unlicensed` 的开发豁免（debug），
/// 而不是靠解锁码。
pub fn verify_unlock_code(text: &str) -> bool {
    if !master_secret_configured() {
        return false;
    }
    let want = unlock_code(&master_secret());
    let got = text.trim().to_ascii_lowercase();
    let a = want.as_bytes();
    let b = got.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// 304 位大整数（5 × 64 位 limb，小端）与混合进位制转换
// ---------------------------------------------------------------------------

/// 大整数类型：320 位（有效数据只用到 304 位，第 5 limb 恒 < 2^48）。
type Big = [u64; 5];

fn big_from_bytes(b: &[u8; DATA_BYTES]) -> Big {
    let mut v = [0u64; 5];
    for i in 0..5 {
        let mut limb = 0u64;
        for j in 0..8 {
            let idx = i * 8 + j;
            if idx < DATA_BYTES {
                limb |= (b[idx] as u64) << (8 * j);
            }
        }
        v[i] = limb;
    }
    v
}

fn big_to_bytes(v: &Big) -> [u8; DATA_BYTES] {
    let mut b = [0u8; DATA_BYTES];
    for i in 0..5 {
        for j in 0..8 {
            let idx = i * 8 + j;
            if idx < DATA_BYTES {
                b[idx] = (v[i] >> (8 * j)) as u8;
            }
        }
    }
    b
}

/// 大整数除以单个 u64，返回余数（商写回 `v`）。
fn big_divmod_small(v: &mut Big, d: u64) -> u64 {
    let mut rem: u128 = 0;
    for i in (0..5).rev() {
        let cur = (rem << 64) | v[i] as u128;
        v[i] = (cur / d as u128) as u64;
        rem = cur % d as u128;
    }
    rem as u64
}

/// 大整数 = 大整数 × m + r（`m`、`r` 为 u64；容量保证不进位）。
fn big_muladd_small(v: &mut Big, m: u64, r: u64) {
    let mut carry: u128 = r as u128;
    for i in 0..5 {
        let cur = (v[i] as u128) * (m as u128) + carry;
        v[i] = cur as u64;
        carry = cur >> 64;
    }
    debug_assert_eq!(carry, 0, "混合进位制编码溢出（数据超过 304 位）");
}

/// 把一组循环的四个字符值打包成一个"循环数字"。
fn pack_cycle(dv: u64, lv: u64, sv: u64, hv: u64) -> u64 {
    dv + DIGITS.len() as u64 * (lv + LETTERS.len() as u64 * (sv + SYMBOLS.len() as u64 * hv))
}

/// 拆开一个"循环数字"为四个字符值。
fn unpack_cycle(cv: u64) -> (usize, usize, usize, u32) {
    let dv = (cv % DIGITS.len() as u64) as usize;
    let lv = ((cv / DIGITS.len() as u64) % LETTERS.len() as u64) as usize;
    let sv = ((cv / (DIGITS.len() as u64 * LETTERS.len() as u64)) % SYMBOLS.len() as u64) as usize;
    let hv = (cv / (DIGITS.len() as u64 * LETTERS.len() as u64 * SYMBOLS.len() as u64)) as u32;
    (dv, lv, sv, hv)
}

/// 38 字节数据 → 48 位混合字符密钥。
pub fn encode_key(data: &[u8; DATA_BYTES]) -> String {
    let mut v = big_from_bytes(data);
    // 从末组开始取余数（大整数 → 混合进位制）
    let mut cycles = [(0u64, 0u64, 0u64, 0u64); CYCLES];
    for c in (0..CYCLES).rev() {
        let cv = big_divmod_small(&mut v, CYCLE_RADIX);
        let (dv, lv, sv, hv) = unpack_cycle(cv);
        cycles[c] = (dv as u64, lv as u64, sv as u64, hv as u64);
    }
    let mut s = String::with_capacity(KEY_LEN * 3);
    for (dv, lv, sv, hv) in cycles.iter() {
        s.push(DIGITS[*dv as usize] as char);
        s.push(LETTERS[*lv as usize] as char);
        s.push(SYMBOLS[*sv as usize] as char);
        s.push(char::from_u32(HANZI_BASE + *hv as u32).unwrap_or('一'));
    }
    s
}

/// 字符类别名（报错用）。
fn class_name(k: usize) -> &'static str {
    match k {
        0 => "数字",
        1 => "英文字母",
        2 => "符号",
        _ => "汉字",
    }
}

/// 48 位混合字符密钥 → 38 字节数据。
///
/// 错误信息**指定位号与期望类别** —— 用户抄录错位时能自己改回来。
pub fn decode_key(text: &str) -> Result<[u8; DATA_BYTES], String> {
    let chars: Vec<char> = text.trim().chars().collect();
    if chars.len() != KEY_LEN {
        return Err(format!(
            "密钥位数不正确：应为 {} 位（数字/字母/符号/汉字交替），实为 {} 位",
            KEY_LEN,
            chars.len()
        ));
    }
    let mut v: Big = [0u64; 5];
    for c in 0..CYCLES {
        let mut cv_parts = [0u64; CLASSES];
        for k in 0..CLASSES {
            let ch = chars[c * CLASSES + k];
            let value = match k {
                0 => DIGITS.iter().position(|&b| b as char == ch),
                1 => LETTERS.iter().position(|&b| b as char == ch),
                2 => SYMBOLS.iter().position(|&b| b as char == ch),
                _ => {
                    let cp = ch as u32;
                    if cp >= HANZI_BASE && cp < HANZI_BASE + HANZI_COUNT {
                        Some((cp - HANZI_BASE) as usize)
                    } else {
                        None
                    }
                }
            };
            match value {
                Some(v) => cv_parts[k] = v as u64,
                None => {
                    return Err(format!(
                        "第 {} 位应为{}：收到「{}」不在字符表内（请检查是否抄错）",
                        c * CLASSES + k + 1,
                        class_name(k),
                        ch
                    ))
                }
            }
        }
        let cv = pack_cycle(cv_parts[0], cv_parts[1], cv_parts[2], cv_parts[3]);
        big_muladd_small(&mut v, CYCLE_RADIX, cv);
    }
    // 容量校验：12 组共约 309.5 位，有效数据只占 304 位 ——
    // 高出的约 5.5 位必须为零（签发方永远产出零，抄错/篡改极难凑出零）
    if v[4] >> 48 != 0 {
        return Err("密钥内容超出有效范围（格式校验失败）".to_string());
    }
    Ok(big_to_bytes(&v))
}

// ---------------------------------------------------------------------------
// CRC-16/CCITT-FALSE（poly 0x1021, init 0xFFFF）
// ---------------------------------------------------------------------------

fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// ---------------------------------------------------------------------------
// 加密封装（密文 + 认证标签）
// ---------------------------------------------------------------------------

/// 机器指纹摘要（48 位）。
pub fn hwid48(hwid: &str) -> [u8; 6] {
    let h = sha512(hwid.as_bytes());
    let mut o = [0u8; 6];
    o.copy_from_slice(&h[..6]);
    o
}

/// 由「主密钥 + 机器指纹」派生用途密钥。
///
/// hwid 参与派生是硬约束：**换机器连解密都失败**，
/// 而不是"解密成功但指纹字段不匹配"（后者留出了伪造窗口）。
fn derive(tag: &[u8], secret: &[u8; 32], hwid: &str) -> [u8; 32] {
    let mut input = Vec::with_capacity(tag.len() + 32 + 6);
    input.extend_from_slice(tag);
    input.extend_from_slice(secret);
    input.extend_from_slice(&hwid48(hwid));
    let h = sha512(&input);
    let mut o = [0u8; 32];
    o.copy_from_slice(&h[..32]);
    o
}

/// SHA-512 计数器模式密钥流。
fn keystream(key: &[u8; 32], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 64);
    let mut counter: u64 = 0;
    while out.len() < len {
        let mut block = Vec::with_capacity(35);
        block.extend_from_slice(key);
        block.extend_from_slice(b"KS");
        block.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&sha512(&block));
        counter += 1;
    }
    out.truncate(len);
    out
}

/// 认证标签：`SHA512(用途标签 ‖ MAC密钥 ‖ 密文 ‖ 指纹摘要)[..10]`。
fn mac(key: &[u8; 32], ciphertext: &[u8], hwid: &str) -> [u8; TAG_LEN] {
    let mut input = Vec::with_capacity(6 + 32 + ciphertext.len() + 6);
    input.extend_from_slice(b"SM1TAG");
    input.extend_from_slice(key);
    input.extend_from_slice(ciphertext);
    input.extend_from_slice(&hwid48(hwid));
    let h = sha512(&input);
    let mut o = [0u8; TAG_LEN];
    o.copy_from_slice(&h[..TAG_LEN]);
    o
}

// ---------------------------------------------------------------------------
// 明文打包
// ---------------------------------------------------------------------------

fn pack_plain(p: &KeyParams, hwid: &str) -> [u8; PLAIN_LEN] {
    let mut b = [0u8; PLAIN_LEN];
    b[0] = PLAIN_MAGIC;
    b[1] = (FORMAT_VERSION << 4) | (p.kind as u8 & 0x0F);
    b[2..8].copy_from_slice(&hwid48(hwid));
    b[8..12].copy_from_slice(&p.valid_from_day.to_be_bytes());
    b[12..16].copy_from_slice(&p.valid_until_day.to_be_bytes());
    let secs = p.usage_seconds_limit.to_be_bytes();
    b[16..19].copy_from_slice(&secs[1..]); // 24 位
    b[19..21].copy_from_slice(&p.usage_count_limit.to_be_bytes());
    b[21..23].copy_from_slice(&p.feature_flags.to_be_bytes());
    let kid = (p.key_id & 0xFF_FFFF).to_be_bytes();
    b[23..26].copy_from_slice(&kid[1..]); // 24 位
    b
}

fn unpack_plain(b: &[u8; PLAIN_LEN]) -> Result<KeyParams, String> {
    if b[0] != PLAIN_MAGIC {
        return Err("密钥内容无法识别（魔数不符）".to_string());
    }
    let fmt = b[1] >> 4;
    if fmt != FORMAT_VERSION {
        return Err(format!("密钥格式版本不受支持：v{}", fmt));
    }
    let kind = KeyKind::from_u8(b[1] & 0x0F).ok_or("密钥授权类型无法识别")?;
    let valid_from = u32::from_be_bytes([b[8], b[9], b[10], b[11]]);
    let valid_until = u32::from_be_bytes([b[12], b[13], b[14], b[15]]);
    let usage_seconds = u32::from_be_bytes([0, b[16], b[17], b[18]]);
    let usage_count = u16::from_be_bytes([b[19], b[20]]);
    let features = u16::from_be_bytes([b[21], b[22]]);
    let key_id = u32::from_be_bytes([0, b[23], b[24], b[25]]);
    Ok(KeyParams {
        kind,
        valid_from_day: valid_from,
        valid_until_day: valid_until,
        usage_seconds_limit: usage_seconds,
        usage_count_limit: usage_count,
        feature_flags: features,
        key_id,
    })
}

// ---------------------------------------------------------------------------
// 签发 / 验密钥
// ---------------------------------------------------------------------------

/// 用指定主密钥签发一枚 48 位密钥（Python 签发端与测试共用此逻辑）。
pub fn issue_key(secret: &[u8; 32], hwid: &str, p: &KeyParams) -> String {
    let plain = pack_plain(p, hwid);
    let k_enc = derive(b"SM1K1", secret, hwid);
    let ks = keystream(&k_enc, PLAIN_LEN);
    let mut cipher = [0u8; PLAIN_LEN];
    for i in 0..PLAIN_LEN {
        cipher[i] = plain[i] ^ ks[i];
    }
    let k_mac = derive(b"SM1K2", secret, hwid);
    let tag = mac(&k_mac, &cipher, hwid);
    let mut data = [0u8; DATA_BYTES];
    data[..PLAIN_LEN].copy_from_slice(&cipher);
    data[PLAIN_LEN..PLAIN_LEN + TAG_LEN].copy_from_slice(&tag);
    let crc = crc16(&data[..PLAIN_LEN + TAG_LEN]);
    data[PLAIN_LEN + TAG_LEN..].copy_from_slice(&crc.to_be_bytes());
    encode_key(&data)
}

/// 用指定主密钥解析并验证一枚密钥。
///
/// 校验顺序（错误信息据此分层，指引导用户）：
/// 1. 格式与 CRC（抄录错误）；
/// 2. 认证标签（篡改 / 非本构建签发）；
/// 3. 明文结构；
/// 4. 生效 / 到期时间。
pub fn open_key_with_secret(
    secret: &[u8; 32],
    text: &str,
    hwid: &str,
    now_secs: i64,
) -> Result<KeyLicense, String> {
    let data = decode_key(text)?;
    let cipher = &data[..PLAIN_LEN];
    let tag: &[u8; TAG_LEN] = data[PLAIN_LEN..PLAIN_LEN + TAG_LEN]
        .try_into()
        .map_err(|_| "密钥长度异常".to_string())?;
    let crc_stored = u16::from_be_bytes([data[PLAIN_LEN + TAG_LEN], data[PLAIN_LEN + TAG_LEN + 1]]);
    if crc_stored != crc16(&data[..PLAIN_LEN + TAG_LEN]) {
        return Err("密钥校验位不符：可能抄录有误（请核对每一位字符）".to_string());
    }

    let k_mac = derive(b"SM1K2", secret, hwid);
    if &mac(&k_mac, cipher, hwid) != tag {
        return Err("密钥验签未通过：密钥可能被篡改，或不是由本产品签发体系签发的".to_string());
    }

    let k_enc = derive(b"SM1K1", secret, hwid);
    let ks = keystream(&k_enc, PLAIN_LEN);
    let mut plain = [0u8; PLAIN_LEN];
    for i in 0..PLAIN_LEN {
        plain[i] = cipher[i] ^ ks[i];
    }
    let p = unpack_plain(&plain)?;

    if p.valid_from_day > 0 && today_day(now_secs) < p.valid_from_day {
        let (y, m, d) = day_to_ymd(p.valid_from_day);
        return Err(format!(
            "密钥尚未生效（生效日期：{:04}-{:02}-{:02}）",
            y, m, d
        ));
    }
    if p.valid_until_day != DAY_PERPETUAL && today_day(now_secs) > p.valid_until_day {
        let (y, m, d) = day_to_ymd(p.valid_until_day);
        return Err(format!("密钥已过期（有效期至：{:04}-{:02}-{:02}）", y, m, d));
    }

    Ok(KeyLicense {
        kind: p.kind,
        valid_from_day: p.valid_from_day,
        valid_until_day: p.valid_until_day,
        usage_seconds_limit: p.usage_seconds_limit,
        usage_count_limit: p.usage_count_limit,
        feature_flags: p.feature_flags,
        key_id: p.key_id,
    })
}

/// 用**二进制内置主密钥**解析并验证一枚密钥（发行版入口）。
pub fn open_key(text: &str, hwid: &str, now_secs: i64) -> Result<KeyLicense, String> {
    if !master_secret_configured() {
        return Err("本构建未配置密钥主密钥（keys/aim.secret 缺失），无法校验激活密钥".to_string());
    }
    open_key_with_secret(&master_secret(), text, hwid, now_secs)
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// 测试主密钥（与生产密钥无关；生产密钥只存在于 keys/aim.secret）。
    const TEST_SECRET: [u8; 32] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x00, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2,
        0xe1, 0xf0,
    ];
    const HW: &str = "test-hwid-0123456789abcdef";

    fn params() -> KeyParams {
        KeyParams {
            kind: KeyKind::Pro,
            valid_from_day: 0,
            valid_until_day: DAY_PERPETUAL,
            usage_seconds_limit: 0,
            usage_count_limit: 0,
            feature_flags: FEAT_ALL,
            key_id: 0xABCDEF,
        }
    }

    #[test]
    fn key_is_48_chars_with_alternating_classes() {
        let key = issue_key(&TEST_SECRET, HW, &params());
        let chars: Vec<char> = key.chars().collect();
        assert_eq!(chars.len(), KEY_LEN, "密钥必须恰好 48 位");
        for (i, ch) in chars.iter().enumerate() {
            let ok = match i % 4 {
                0 => ch.is_ascii_digit(),
                1 => ch.is_ascii_alphabetic(),
                2 => SYMBOLS.contains(&(*ch as u8)),
                _ => (*ch as u32) >= HANZI_BASE && (*ch as u32) < HANZI_BASE + HANZI_COUNT,
            };
            assert!(ok, "第 {} 位「{}」类别不符（应按 数字/字母/符号/汉字 交替）", i + 1, ch);
        }
    }

    /// **跨语言金向量**：与 tools/issue_license.py 的 issue-key 输出必须
    /// 逐字节一致（Python 端用同一把测试主密钥 + 同一组参数先行算出）。
    /// 任一环节（字节序 / 派生标签 / 进位制 / 字符表）跑偏，此测试即红。
    #[test]
    fn cross_language_vector_matches_python() {
        let p = KeyParams {
            kind: KeyKind::Edu,
            valid_from_day: 20_000,
            valid_until_day: 21_000,
            usage_seconds_limit: 7200,
            usage_count_limit: 42,
            feature_flags: FEAT_BASIC | FEAT_EXPORT | FEAT_SCHEDULE,
            key_id: 0x123456,
        };
        let key = issue_key(&TEST_SECRET, HW, &p);
        assert_eq!(
            key,
            "0v{个2I=啩2Y'丩4G@娵7T{媊0Z|佇4O^媀5p|交2Q/匲0w+劕7K{儨3Y,嚝"
        );
    }

    #[test]
    fn roundtrip_preserves_all_fields() {        let p = KeyParams {
            kind: KeyKind::Edu,
            valid_from_day: 20_000,
            valid_until_day: 21_000,
            usage_seconds_limit: 7200,
            usage_count_limit: 42,
            feature_flags: FEAT_BASIC | FEAT_EXPORT | FEAT_SCHEDULE,
            key_id: 0x123456,
        };
        let key = issue_key(&TEST_SECRET, HW, &p);
        let lic = open_key_with_secret(&TEST_SECRET, &key, HW, 20_500 * 86400).expect("应能验过");
        assert_eq!(lic.kind, KeyKind::Edu);
        assert_eq!(lic.valid_from_day, 20_000);
        assert_eq!(lic.valid_until_day, 21_000);
        assert_eq!(lic.usage_seconds_limit, 7200);
        assert_eq!(lic.usage_count_limit, 42);
        assert_eq!(lic.feature_flags, FEAT_BASIC | FEAT_EXPORT | FEAT_SCHEDULE);
        assert_eq!(lic.key_id, 0x123456);
    }

    #[test]
    fn wrong_machine_fails() {
        let key = issue_key(&TEST_SECRET, HW, &params());
        let e = open_key_with_secret(&TEST_SECRET, &key, "other-machine", 20_000 * 86400)
            .unwrap_err();
        // 换机器：解密密钥即不同，必在验签阶段失败
        assert!(e.contains("验签") || e.contains("篡改"), "换机应验签失败：{}", e);
    }

    #[test]
    fn wrong_secret_fails() {
        let key = issue_key(&TEST_SECRET, HW, &params());
        let mut other = TEST_SECRET;
        other[0] ^= 0xff;
        assert!(open_key_with_secret(&other, &key, HW, 20_000 * 86400).is_err());
    }

    #[test]
    fn tampered_char_detected() {
        let key = issue_key(&TEST_SECRET, HW, &params());
        let mut chars: Vec<char> = key.chars().collect();
        // 改最低位字符（末位汉字 → 换成表内另一个汉字）：数值变化小、不会越界，
        // 必须由 CRC/标签层识破（而不是碰巧被容量校验捡漏）
        let last = chars.len() - 1;
        chars[last] = if chars[last] == char::from_u32(HANZI_BASE + 1000).unwrap() {
            char::from_u32(HANZI_BASE + 1234).unwrap()
        } else {
            char::from_u32(HANZI_BASE + 1000).unwrap()
        };
        let tampered: String = chars.into_iter().collect();
        let e = open_key_with_secret(&TEST_SECRET, &tampered, HW, 20_000 * 86400).unwrap_err();
        // 要么 CRC 拦住，要么标签拦住
        assert!(e.contains("抄录") || e.contains("验签") || e.contains("篡改"), "{}", e);
    }

    #[test]
    fn typo_outside_table_detected() {
        let key = issue_key(&TEST_SECRET, HW, &params());
        let mut chars: Vec<char> = key.chars().collect();
        // 把某位的汉字换成不在表内的汉字（模拟抄错成生僻字）
        chars[3] = '龠';
        let bad: String = chars.into_iter().collect();
        let e = open_key_with_secret(&TEST_SECRET, &bad, HW, 20_000 * 86400).unwrap_err();
        assert!(e.contains("字符表") || e.contains("抄录") || e.contains("验签"), "{}", e);
    }

    #[test]
    fn not_yet_valid_rejected() {
        let p = KeyParams {
            valid_from_day: 21_000,
            ..params()
        };
        let key = issue_key(&TEST_SECRET, HW, &p);
        let e = open_key_with_secret(&TEST_SECRET, &key, HW, 20_000 * 86400).unwrap_err();
        assert!(e.contains("尚未生效"), "{}", e);
    }

    #[test]
    fn expired_rejected() {
        let p = KeyParams {
            valid_until_day: 20_000,
            ..params()
        };
        let key = issue_key(&TEST_SECRET, HW, &p);
        let e = open_key_with_secret(&TEST_SECRET, &key, HW, 21_000 * 86400).unwrap_err();
        assert!(e.contains("已过期"), "{}", e);
    }

    #[test]
    fn perpetual_never_expires() {
        let p = KeyParams {
            valid_until_day: DAY_PERPETUAL,
            ..params()
        };
        let key = issue_key(&TEST_SECRET, HW, &p);
        let lic = open_key_with_secret(&TEST_SECRET, &key, HW, 90_000 * 86400).expect("永久有效");
        assert!(lic.perpetual());
    }

    #[test]
    fn feature_flags_gate_correctly() {
        let p = KeyParams {
            feature_flags: FEAT_BASIC | FEAT_EXPORT,
            ..params()
        };
        let key = issue_key(&TEST_SECRET, HW, &p);
        let lic = open_key_with_secret(&TEST_SECRET, &key, HW, 20_000 * 86400).unwrap();
        assert!(lic.feature_allowed(FEAT_EXPORT));
        assert!(!lic.feature_allowed(FEAT_SMART));
        assert!(!lic.feature_allowed(FEAT_SCHEDULE));
    }

    #[test]
    fn wrong_length_rejected() {
        assert!(decode_key("abc").is_err());
        let key = issue_key(&TEST_SECRET, HW, &params());
        let mut chars: Vec<char> = key.chars().collect();
        chars.pop();
        let short: String = chars.into_iter().collect();
        assert!(decode_key(&short).is_err());
    }

    #[test]
    fn day_to_ymd_matches_known_dates() {
        assert_eq!(day_to_ymd(0), (1970, 1, 1));
        assert_eq!(day_to_ymd(10957), (2000, 1, 1));
        assert_eq!(day_to_ymd(20454), (2026, 1, 1));
    }

    #[test]
    fn deterministic_issue_same_params() {
        // 同一参数两次签发应得到完全相同的密钥（随机性由 key_id 提供）
        let a = issue_key(&TEST_SECRET, HW, &params());
        let b = issue_key(&TEST_SECRET, HW, &params());
        assert_eq!(a, b);
    }

    #[test]
    fn different_key_id_different_key() {
        let mut p = params();
        p.key_id = 1;
        let a = issue_key(&TEST_SECRET, HW, &p);
        p.key_id = 2;
        let b = issue_key(&TEST_SECRET, HW, &p);
        assert_ne!(a, b);
    }

    #[test]
    fn embedded_secret_not_configured_gives_clear_error() {
        // 测试构建未提供 keys/aim.secret → master_secret_configured() 为 false，
        // open_key 必须给出明确错误而非 panic
        if !master_secret_configured() {
            let key = issue_key(&TEST_SECRET, HW, &params());
            let e = open_key(&key, HW, 20_000 * 86400).unwrap_err();
            assert!(e.contains("主密钥"), "{}", e);
        }
    }

    #[test]
    fn crc16_known_vector() {
        // CRC-16/CCITT-FALSE("123456789") = 0x29B1
        assert_eq!(crc16(b"123456789"), 0x29B1);
    }

    #[test]
    fn mixed_radix_roundtrip_extremes() {
        // 全 0 / 全 1 数据的编解码往返
        for data in [[0u8; DATA_BYTES], [0xFFu8; DATA_BYTES]] {
            // 全 1 数据（304 位全 1）超过 12 组容量吗？不超（309.5 > 304）
            let key = encode_key(&data);
            let back = decode_key(&key).expect("往返应成功");
            assert_eq!(back, data);
        }
    }

    #[test]
    fn capacity_rejects_out_of_range_value() {
        // 全部取最大值 → V = RADIX^12 - 1 ≈ 2^309.5 > 2^304 → 必须拒识
        let mut s = String::new();
        for _ in 0..CYCLES {
            s.push(DIGITS[9] as char);
            s.push(LETTERS[51] as char);
            s.push(SYMBOLS[31] as char);
            s.push(char::from_u32(HANZI_BASE + 3499).unwrap());
        }
        assert!(decode_key(&s).is_err(), "越界值必须被拒");
    }

    #[test]
    fn pack_unpack_cycle_roundtrip() {
        for &(dv, lv, sv, hv) in &[
            (0u64, 0u64, 0u64, 0u64),
            (9, 51, 31, 3499),
            (3, 17, 12, 1234),
        ] {
            let cv = pack_cycle(dv, lv, sv, hv);
            assert_eq!(unpack_cycle(cv), (dv as usize, lv as usize, sv as usize, hv as u32));
        }
    }
}
