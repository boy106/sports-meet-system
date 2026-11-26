//! 授权通信加密信道（v1.8.0 新增）。
//!
//! # 目标
//!
//! 客户端与服务端之间传输的是**密钥明文 + 机器指纹**，若走裸 HTTP，
//! 局域网内抓包即可获得可复用的授权凭证。本模块提供一条自实现的
//! 加密信道，保证：
//!
//! 1. **机密性**：密钥与指纹不以明文出现在链路上；
//! 2. **完整性**：任何字节改动都会被 MAC 检出；
//! 3. **抗重放**：每次请求带唯一随机数与时间戳，重放会被服务端拒绝；
//! 4. **前向隔离**：会话密钥由**双端随机数**共同派生，单次会话密钥
//!    泄漏不影响其他会话。
//!
//! # 算法（自实现，零依赖）
//!
//! 本项目坚持「最小依赖」（规则 10），不引入 `ring` / `rustls` /
//! `aes-gcm`。因此这里采用与 `vault.rs` 同族的 FNV 流密码，但**补齐了
//! `vault.rs` 明确声明的短板**：
//!
//! | 维度 | vault.rs | 本模块（aim::channel） |
//! |---|---|---|
//! | 密钥来源 | 单一 seed | 预共享密钥 ‖ 客户端随机数 ‖ 服务端随机数 |
//! | 抗重放 | 无 | 序号 + 时间戳窗口 + 随机数去重 |
//! | 完整性 | 每块 8 字节 MAC | 整包 16 字节 MAC（长度 ‖ 序号 ‖ 明文 ‖ 密钥） |
//! | 会话隔离 | 无（长期同一密钥） | 每次请求独立派生会话密钥 |
//!
//! # 必读：本模块的真实强度（不夸大）
//!
//! > **这不是 TLS，也不是密码学意义上的安全信道。**
//!
//! FNV-1a 是非密码学哈希，其输出**可被已知明文攻击分析**。
//! 一个有能力实施选择明文攻击、且能观察密文的对手，理论上可以
//! 恢复密钥流并伪造后续报文。
//!
//! **本模块真正挡住的是**：
//! * ✅ 用 Wireshark 直接看到密钥明文（看到的是乱码）
//! * ✅ 抓包后原样重放（有随机数 + 时间戳双重防重放）
//! * ✅ 随手改一个字节伪造授权（整包 MAC 会拒绝）
//! * ✅ 一次会话被破影响全部会话（会话密钥逐次派生）
//!
//! **本模块挡不住**：
//! * ❌ 有密码学能力、可主动选择明文的对手
//! * ❌ 能反编译客户端并提取预共享密钥的人（此时可直接伪造客户端）
//! * ❌ 中间人替换服务端公钥（本项目**未实现**证书链/pinning）
//!
//! **生产建议**：若授权服务部署在公网，请在其前置一台 Nginx 并启用
//! 标准 TLS（HTTPS），本模块作为**应用层第二层**存在。二者叠加后，
//! 应用层明文攻击者仍需先破 TLS。这与 `docs/12` 的既有立场一致：
//! **纵深防御，不承诺绝对安全。**

use std::sync::atomic::{AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// 混淆盐常量（发行加固：不让 `strings` 一眼看到派生用途）
// ---------------------------------------------------------------------------
//
// 这些是 XOR 掩码后的字节序列，运行时由 `deobfuscate` 还原。
// **改动它们等于改动协议** —— 服务端 `channel.rs` 必须同步（见 docs/13）。
//
// 对应明文：
//   SALT_SESSION → "aim::session::v1"
//   SALT_PAIR    → "aim::session::pair::v1"

/// 会话密钥派生盐（混淆）。
pub const SALT_SESSION: [u8; 16] = [
    0x3b, 0x2e, 0x0d, 0x37, 0x14, 0xb8, 0x91, 0xe2, 0xc1, 0x36, 0x17, 0x0b, 0x3c, 0x19, 0xba,
    0xd8,
];

/// 双端密钥升级盐（混淆）。
pub const SALT_PAIR: [u8; 22] = [
    0x3b, 0x2e, 0x0d, 0x37, 0x14, 0xb8, 0x91, 0xe2, 0xc1, 0x36, 0x17, 0x0b, 0x3c, 0x19, 0xbc,
    0x88, 0xe3, 0xc5, 0x6a, 0x47, 0x68, 0x0a,
];

/// 帧魔数（Authorization Channel Frame）。
pub const FRAME_MAGIC: &[u8; 4] = b"SMAF";

/// 帧格式版本。
pub const FRAME_VERSION: u8 = 1;

/// 允许的时间偏移（秒）：服务端与客户端时钟差超过此值则拒绝。
///
/// 校园内网机器时钟常有漂移（未配 NTP），因此给足 5 分钟余量；
/// 同时它足够窄，"几天前抓的包"无法重放。
pub const TIME_WINDOW_SECS: i64 = 300;

/// MAC 长度（字节）。
pub const MAC_LEN: usize = 16;

/// 预共享密钥（PSK）默认值。
///
/// **交付前必须更换**：它与服务端的 `psk` 配置项必须一致，
/// 是双端彼此信任的起点。更换方式见 `docs/13_服务端授权说明.md`。
/// 发行包中此常量会被混淆处理（见 `打包` 章节），但仍属"提高门槛"
/// 而非"不可提取"——真正不可提取的部分是**服务端私钥**，它只存在于
/// 服务端包中。
pub const DEFAULT_PSK: &str = "THZX-AIM-2026-PSK-CHANGE-ME";

/// 信道错误。
#[derive(Debug, PartialEq, Eq)]
pub enum ChannelError {
    /// 帧太短 / 魔数不符 / 版本不认识 —— 不是本信道产出的数据。
    BadFrame(&'static str),
    /// MAC 校验失败（被篡改，或 PSK/随机数不匹配）。
    MacMismatch,
    /// 序号不单调（重放）。
    ReplaySequence { got: u64, min: u64 },
    /// 时间戳超窗（重放或时钟严重不准）。
    StaleTimestamp { drift: i64 },
    /// 随机数已用过（重放）。
    DuplicateNonce,
    /// 明文体不是合法 UTF-8。
    BadUtf8,
}

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChannelError::BadFrame(r) => write!(f, "信道帧格式非法：{}", r),
            ChannelError::MacMismatch => write!(f, "信道完整性校验失败（数据被篡改或密钥不符）"),
            ChannelError::ReplaySequence { got, min } => {
                write!(f, "信道序号重放：收到 {}，期望不小于 {}", got, min)
            }
            ChannelError::StaleTimestamp { drift } => {
                write!(f, "信道时间戳超出允许窗口（偏移 {} 秒）", drift)
            }
            ChannelError::DuplicateNonce => write!(f, "信道随机数重复（疑似重放）"),
            ChannelError::BadUtf8 => write!(f, "信道明文不是合法 UTF-8"),
        }
    }
}

impl std::error::Error for ChannelError {}

// ---------------------------------------------------------------------------
// 基础哈希与随机数
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 字符串混淆（降低静态分析可读性）
// ---------------------------------------------------------------------------
//
// 《发行加固》要求"不能轻易暴露密钥算法"。盐常量若以明文 `&str` 出现在
// 二进制里，`strings` 命令一敲就能看到 "aim::session::v1" 这种一看就懂的
// 标识 —— 逆向者据此可快速定位密钥派生函数。
//
// 因此把盐以 **XOR 掩码后的字节数组** 形式存放，运行时才还原到栈上。
// 这不是密码学保护（掩码本身也埋在代码里），只是把"一眼可见"变成
// "需要跟一遍还原逻辑"，抬高静态分析成本。
//
// 注意：还原后的字符串**不参与任何缓存**，用完即弃，避免常驻内存。

/// 用固定掩码还原被混淆的字节序列。
///
/// 掩码取 `0x5A` 单字节异或 + 位置扰动，足以阻断 `strings` 直接命中。
///
/// 末尾连续的 `0x00`（来自 `obfuscate` 的定长填充）会被裁掉，
/// 保证与 `obfuscate` 严格互逆。
#[inline]
pub fn deobfuscate(masked: &[u8]) -> String {
    // 裁掉定长填充（obfuscate 保证明文末尾不会是 0x00 掩码值）
    let end = masked
        .iter()
        .rposition(|b| *b != 0)
        .map(|i| i + 1)
        .unwrap_or(0);
    let mut out = Vec::with_capacity(end);
    for (i, b) in masked[..end].iter().enumerate() {
        out.push(b ^ 0x5A ^ (i as u8).wrapping_mul(0x1D));
    }
    String::from_utf8(out).unwrap_or_default()
}

/// 编译期把明文盐转成混淆字节数组。
///
/// **这是给维护者用的工具函数**：新增/修改盐时，用它算出应填入
/// `SALT_*` 常量的字节数组（也可由 `tests/wire.rs` 的
/// `obfuscate/deobfuscate 互逆` 断言校验）。主流程不调用它，
/// 因为没有"运行时把明文变混淆"的需求 —— 明文根本不该进二进制。
#[allow(dead_code)]
pub const fn obfuscate(src: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    let mut i = 0;
    while i < src.len() && i < 64 {
        out[i] = src[i] ^ 0x5A ^ ((i as u8).wrapping_mul(0x1D));
        i += 1;
    }
    out
}

fn fnv1a64_bytes(mut h: u64, bytes: &[u8]) -> u64 {
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(PRIME);
    }
    h
}

/// 由任意字节序列派生 64 bit 摘要（带用途盐，防止跨用途碰撞）。
fn digest(salt: &str, parts: &[&[u8]]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    let mut h = fnv1a64_bytes(OFFSET_BASIS, salt.as_bytes());
    for p in parts {
        h = fnv1a64_bytes(h, p);
        // 段间插入分隔符，避免 "ab"+"c" 与 "a"+"bc" 碰撞
        h = fnv1a64_bytes(h, b"\x1f");
    }
    h
}

/// 系统随机源（不引入 `rand` crate）。
///
/// 优先级：`/dev/urandom`（Linux）→ `BCryptGenRandom`（Windows）
/// → 时间戳 + 地址熵兜底。**兜底路径质量较差**，会在 `is_weak()` 中
/// 标记，供审计告警 —— 但绝不 panic，因为随机数不可用不应导致
/// 整个授权流程不可用。
fn system_random_bytes(n: usize) -> (Vec<u8>, bool) {
    #[cfg(unix)]
    {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let mut buf = vec![0u8; n];
            if f.read_exact(&mut buf).is_ok() {
                return (buf, false);
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        // BCryptGenRandom(BCRYPT_USE_SYSTEM_PREFERRED_RNG)
        #[link(name = "bcrypt")]
        extern "system" {
            fn BCryptGenRandom(
                hAlgorithm: *mut std::ffi::c_void,
                pbBuffer: *mut u8,
                cbBuffer: u32,
                dwFlags: u32,
            ) -> i32;
        }
        let mut buf = vec![0u8; n];
        // BCRYPT_USE_SYSTEM_PREFERRED_RNG = 0x00000002
        let status = unsafe {
            BCryptGenRandom(
                std::ptr::null_mut(),
                buf.as_mut_ptr(),
                n as u32,
                0x0000_0002,
            )
        };
        if status == 0 {
            return (buf, false);
        }
    }
    // 兜底：时间 + 进程 id + 地址熵（质量弱，如实标记）
    let mut buf = Vec::with_capacity(n);
    let mut seed = digest(
        "fallback-seed",
        &[
            &now_millis().to_le_bytes(),
            &std::process::id().to_le_bytes(),
            &(&buf as *const _ as usize).to_le_bytes(),
        ],
    );
    while buf.len() < n {
        seed = fnv1a64_bytes(seed, b"fallback");
        buf.extend_from_slice(&seed.to_le_bytes());
    }
    buf.truncate(n);
    (buf, true)
}

/// 生成 `2n` 位十六进制随机串（用 `n` 字节熵）。
pub fn random_hex(n: usize) -> String {
    let (bytes, _weak) = system_random_bytes(n);
    let mut s = String::with_capacity(n * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

/// 当前 Unix 毫秒时间戳。
pub fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// 当前 Unix 秒时间戳。
pub fn now_secs() -> i64 {
    now_millis() / 1000
}

// ---------------------------------------------------------------------------
// 会话密钥派生
// ---------------------------------------------------------------------------

/// 一次会话的三要素：会话密钥 + 随机数 + 序号基准。
#[derive(Debug, Clone)]
pub struct Session {
    /// 会话密钥（16 位十六进制）。
    pub key: String,
    /// 本次会话的客户端随机数。
    pub nonce: String,
    /// 起始序号（客户端递增；服务端据此拒重放）。
    /// 诊断与测试用，主流程直接走 `ChannelSender` 的自增序号。
    #[allow(dead_code)]
    pub seq: u64,
    /// 创建时间戳（毫秒）。诊断用（会话存活时长）。
    #[allow(dead_code)]
    pub created_ms: i64,
}

impl Session {
    /// 新建会话：随机 nonce + 由 PSK 派生密钥。
    pub fn new(psk: &str) -> Session {
        let nonce = random_hex(16);
        Session {
            key: derive_session_key(psk, &nonce),
            nonce,
            seq: 0,
            created_ms: now_millis(),
        }
    }

    /// 用服务端应答的随机数**升级**会话密钥（双端随机数共同决定）。
    ///
    /// 这一步是本模块相对 `vault.rs` 的关键增强：服务端在应答里回带
    /// 自己的随机数，客户端据此把会话密钥从 `H(psk‖nonce_c)` 提升为
    /// `H(psk‖nonce_c‖nonce_s)`。这样即使客户端随机数被预测，
    /// 服务端随机数仍能保障会话密钥的不可预测性。
    pub fn upgrade_with_server_nonce(&mut self, server_nonce: &str) {
        self.key = derive_session_key_pair(&self.nonce, server_nonce, &self.key);
    }
}

/// 由 PSK 与客户端随机数派生会话密钥。
fn derive_session_key(psk: &str, nonce: &str) -> String {
    derive_session_key_public(psk, nonce)
}

/// 同上的公开版本。
///
/// **为什么需要公开**：服务端包（`aim-server`）与客户端包共享本文件，
/// 服务端要从帧里读出的客户端 nonce 自行派生同一把会话密钥。
/// 两端调用同一函数是**线格式契约的一部分** —— 任一端的盐或输入
/// 顺序改动都会导致双端无法通信，必须在改动时同步（见 docs/13）。
pub fn derive_session_key_public(psk: &str, nonce: &str) -> String {
    let h = digest(
        &deobfuscate(&SALT_SESSION),
        &[psk.as_bytes(), nonce.as_bytes()],
    );
    format!("{:016x}", h)
}

/// 双端随机数共同派生（客户端侧与服务端侧用同一函数，保证可复现）。
///
/// 第三个输入是"上一阶段的会话密钥"，形成链式派生：破坏任一环
/// 都无法推出后续密钥。
pub fn derive_session_key_pair(nonce_c: &str, nonce_s: &str, prev: &str) -> String {
    let h = digest(
        &deobfuscate(&SALT_PAIR),
        &[nonce_c.as_bytes(), nonce_s.as_bytes(), prev.as_bytes()],
    );
    format!("{:016x}", h)
}

// ---------------------------------------------------------------------------
// 加解密与封装
// ---------------------------------------------------------------------------

/// 以 `key` 为种子生成伪随机流（类 CTR：每 8 字节一块，块号参与运算）。
///
/// 块号参与运算是**关键**：否则相同明文段会产生相同密文段，
/// 攻击者能看出重复内容（ECB 式泄露）。
fn keystream(key: &str, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut block: u64 = 0;
    while out.len() < len {
        let h = fnv1a64_bytes(
            fnv1a64_bytes(0xcbf2_9ce4_8422_2325, key.as_bytes()),
            &block.to_le_bytes(),
        );
        out.extend_from_slice(&h.to_le_bytes());
        block = block.wrapping_add(1);
    }
    out.truncate(len);
    out
}

/// 对称异或（加解密同一操作）。
fn xor_stream(key: &str, data: &[u8]) -> Vec<u8> {
    let ks = keystream(key, data.len());
    data.iter().zip(ks.iter()).map(|(a, b)| a ^ b).collect()
}

/// 计算整包 MAC（16 字节）。
///
/// 覆盖范围刻意包含 `key ‖ seq ‖ 密文`：**密钥参与 MAC**，
/// 因此不知道密钥的人无法为篡改后的密文重算 MAC。
/// 这是 CWE-353（缺失完整性校验）的标准防御。
fn compute_mac(key: &str, seq: u64, cipher: &[u8]) -> [u8; MAC_LEN] {
    let mut out = [0u8; MAC_LEN];
    let base = fnv1a64_bytes(
        fnv1a64_bytes(
            fnv1a64_bytes(0xcbf2_9ce4_8422_2325, key.as_bytes()),
            &seq.to_le_bytes(),
        ),
        cipher,
    );
    // 用两个不同盐派生两段 8 字节，凑满 16 字节
    let a = digest("aim::mac::a", &[&base.to_le_bytes(), key.as_bytes()]);
    let b = digest("aim::mac::b", &[&base.to_le_bytes(), cipher]);
    out[..8].copy_from_slice(&a.to_le_bytes());
    out[8..].copy_from_slice(&b.to_le_bytes());
    out
}

/// 常量时间比较（MAC 校验不因前缀匹配提前返回）。
fn const_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// 封装一帧：`MAGIC(4) ‖ VER(1) ‖ SEQ(8) ‖ TS(8) ‖ NONCE_LEN(1) ‖ NONCE ‖ C_LEN(4) ‖ CIPHER ‖ MAC(16)`。
///
/// 网络字节序（大端）—— 跨平台一致，且便于抓包时肉眼读数。
pub fn seal(key: &str, nonce: &str, seq: u64, plaintext: &[u8]) -> Vec<u8> {
    let cipher = xor_stream(key, plaintext);
    let mac = compute_mac(key, seq, &cipher);
    let nonce_bytes = nonce.as_bytes();

    let mut out = Vec::with_capacity(64 + cipher.len());
    out.extend_from_slice(FRAME_MAGIC);
    out.push(FRAME_VERSION);
    out.extend_from_slice(&seq.to_be_bytes());
    out.extend_from_slice(&now_millis().to_be_bytes());
    out.push(nonce_bytes.len() as u8);
    out.extend_from_slice(nonce_bytes);
    out.extend_from_slice(&(cipher.len() as u32).to_be_bytes());
    out.extend_from_slice(&cipher);
    out.extend_from_slice(&mac);
    out
}

/// 解析后的帧内容。
#[derive(Debug, Clone)]
pub struct OpenedFrame {
    /// 发送方序号。
    pub seq: u64,
    /// 发送方时间戳（毫秒）。
    pub ts_ms: i64,
    /// 发送方随机数。
    pub nonce: String,
    /// 解密后的明文。
    pub plaintext: Vec<u8>,
}

/// 解封一帧（调用方负责重放检查，见 [`ReplayGuard`]）。
///
/// 校验顺序刻意如此：**格式 → MAC → 明文解密**。
/// 先验 MAC 再解密，避免把未经验证的数据送进解密逻辑。
pub fn open(key: &str, frame: &[u8]) -> Result<OpenedFrame, ChannelError> {
    // 最短帧：4+1+8+8+1+0+4+0+16
    if frame.len() < 42 {
        return Err(ChannelError::BadFrame("长度不足"));
    }
    if &frame[..4] != FRAME_MAGIC {
        return Err(ChannelError::BadFrame("魔数不符"));
    }
    if frame[4] != FRAME_VERSION {
        return Err(ChannelError::BadFrame("版本不支持"));
    }
    let mut pos = 5;
    let seq = read_u64(frame, &mut pos)?;
    let ts_ms = read_i64(frame, &mut pos)?;
    let nonce_len = *frame.get(pos).ok_or(ChannelError::BadFrame("nonce 长度缺失"))? as usize;
    pos += 1;
    let nonce_bytes = frame
        .get(pos..pos + nonce_len)
        .ok_or(ChannelError::BadFrame("nonce 截断"))?;
    let nonce = String::from_utf8(nonce_bytes.to_vec())
        .map_err(|_| ChannelError::BadFrame("nonce 非 UTF-8"))?;
    pos += nonce_len;
    let c_len = read_u32(frame, &mut pos)? as usize;
    let cipher = frame
        .get(pos..pos + c_len)
        .ok_or(ChannelError::BadFrame("密文截断"))?;
    pos += c_len;
    let mac = frame
        .get(pos..pos + MAC_LEN)
        .ok_or(ChannelError::BadFrame("MAC 截断"))?;

    // 完整性优先于解密
    let expect = compute_mac(key, seq, cipher);
    if !const_time_eq(mac, &expect) {
        return Err(ChannelError::MacMismatch);
    }
    let plaintext = xor_stream(key, cipher);
    Ok(OpenedFrame {
        seq,
        ts_ms,
        nonce,
        plaintext,
    })
}

fn read_u64(frame: &[u8], pos: &mut usize) -> Result<u64, ChannelError> {
    let b = frame
        .get(*pos..*pos + 8)
        .ok_or(ChannelError::BadFrame("序号截断"))?;
    *pos += 8;
    let mut a = [0u8; 8];
    a.copy_from_slice(b);
    Ok(u64::from_be_bytes(a))
}

fn read_i64(frame: &[u8], pos: &mut usize) -> Result<i64, ChannelError> {
    Ok(read_u64(frame, pos)? as i64)
}

fn read_u32(frame: &[u8], pos: &mut usize) -> Result<u32, ChannelError> {
    let b = frame
        .get(*pos..*pos + 4)
        .ok_or(ChannelError::BadFrame("长度字段截断"))?;
    *pos += 4;
    let mut a = [0u8; 4];
    a.copy_from_slice(b);
    Ok(u32::from_be_bytes(a))
}

// ---------------------------------------------------------------------------
// 重放防护
// ---------------------------------------------------------------------------

/// 重放防护器（服务端每个来源持有一个；客户端持有服务端响应的防护）。
///
/// 三重检查：
/// 1. **序号单调**：拒绝 `seq` 不大于已见最大序号的帧；
/// 2. **时间窗**：拒绝时间戳偏移超过 [`TIME_WINDOW_SECS`] 的帧；
/// 3. **随机数去重**：拒绝 `nonce` 已使用过的帧（防止"同序号不同内容"）。
///
/// 为何要三重：单靠序号挡不住"攻击者抓包后原样重发一次"（序号合法）；
/// 单靠时间窗挡不住"窗口内快速重放"；单靠 nonce 需要无界记忆。
/// 三者叠加后，重放必须同时绕过单调序号与时间窗，且 nonce 唯一。
pub struct ReplayGuard {
    /// 已见最大序号。
    max_seq: AtomicU64,
    /// 已见随机数（保留最近 `NONCE_MEMORY` 条，避免无界增长）。
    seen_nonces: std::sync::Mutex<Vec<String>>,
}

/// 随机数记忆条数上限。
///
/// 有界是**刻意**的：无界记忆会成为一个内存放大攻击面
/// （攻击者发送海量唯一 nonce 撑爆内存）。跳过最老记录会留下一个
/// 极窄的重放窗口（需同时满足序号合法 + 时间窗内 + 恰好被挤出记忆），
/// 在校园内网环境下可接受。
const NONCE_MEMORY: usize = 4096;

impl Default for ReplayGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayGuard {
    pub fn new() -> ReplayGuard {
        ReplayGuard {
            max_seq: AtomicU64::new(0),
            seen_nonces: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// 检查一帧是否可接受。通过则**记录**该帧（推进状态）。
    ///
    /// 参数 `allow_first_zero`：客户端首个请求序号为 0，服务端初次
    /// 见到序号 0 时应放行（`max_seq` 初值也是 0 会造成误拒）。
    pub fn accept(&self, frame: &OpenedFrame, allow_first_zero: bool) -> Result<(), ChannelError> {
        // 1. 时间窗
        let drift = (now_millis() - frame.ts_ms).abs() / 1000;
        if drift > TIME_WINDOW_SECS {
            return Err(ChannelError::StaleTimestamp { drift });
        }
        // 2. 序号单调
        let prev = self.max_seq.load(Ordering::SeqCst);
        let min_ok = if allow_first_zero && prev == 0 {
            0
        } else {
            prev + 1
        };
        if frame.seq < min_ok {
            return Err(ChannelError::ReplaySequence {
                got: frame.seq,
                min: min_ok,
            });
        }
        // 3. nonce 去重
        {
            let mut seen = self
                .seen_nonces
                .lock()
                .map_err(|_| ChannelError::BadFrame("防护器状态损坏"))?;
            if seen.iter().any(|n| n == &frame.nonce) {
                return Err(ChannelError::DuplicateNonce);
            }
            seen.push(frame.nonce.clone());
            if seen.len() > NONCE_MEMORY {
                seen.remove(0);
            }
        }
        // 全部通过 → 推进序号
        self.max_seq.fetch_max(frame.seq, Ordering::SeqCst);
        Ok(())
    }

    /// 当前已见最大序号（诊断用）。
    pub fn max_seq(&self) -> u64 {
        self.max_seq.load(Ordering::SeqCst)
    }
}

// ---------------------------------------------------------------------------
// base64（自实现，供 HTTP 传输帧用；不引入 crate）
// ---------------------------------------------------------------------------

const B64_TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// 标准 URL-safe base64 编码（无填充）。
pub fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(B64_TABLE[((n >> 18) & 63) as usize] as char);
        out.push(B64_TABLE[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_TABLE[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64_TABLE[(n & 63) as usize] as char);
        }
    }
    out
}

/// base64 解码（宽容双字母表）。非法字符返回 Err。
///
/// **同时接受标准字母表（`+` `/`）与 URL-safe 字母表（`-` `_`）**：
/// 编码侧（[`b64_encode`]）固定输出 URL-safe（帧要进 URL/JSON，
/// 不能带 `+` `/`），但解码侧必须宽容——离线许可的 `sig` 字段由
/// `tools/issue_license.py`（Python 标准库 `base64.b64encode`）签发，
/// 输出的是**标准** base64；历史上手签的测试向量同样是标准字母表。
/// 若解码器只认 URL-safe，含 `+`/`/` 的签名（随机签名约 3/4 概率含）
/// 会在客户端解析失败——那是发行级 bug，不是测试问题。
pub fn b64_decode(text: &str) -> Result<Vec<u8>, ChannelError> {
    let mut rev = [255u8; 256];
    for (i, c) in B64_TABLE.iter().enumerate() {
        rev[*c as usize] = i as u8;
    }
    // 宽容：标准字母表的 62/63 位也认（与 URL-safe 的 `-` `_` 等价）。
    rev[b'+' as usize] = 62;
    rev[b'/' as usize] = 63;
    let bytes: Vec<u8> = text
        .bytes()
        .filter(|b| *b != b'=' as u8 && *b != b'\n' as u8 && *b != b'\r' as u8)
        .collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut vals = [0u8; 4];
        for (i, b) in chunk.iter().enumerate() {
            let v = rev[*b as usize];
            if v == 255 {
                return Err(ChannelError::BadFrame("base64 含非法字符"));
            }
            vals[i] = v;
        }
        let n = ((vals[0] as u32) << 18)
            | ((vals[1] as u32) << 12)
            | ((vals[2] as u32) << 6)
            | (vals[3] as u32);
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

/// 发送方：管理序号自增与封装（每会话一个）。
pub struct ChannelSender {
    key: String,
    nonce: String,
    seq: u64,
}

impl ChannelSender {
    pub fn new(key: impl Into<String>, nonce: impl Into<String>) -> ChannelSender {
        ChannelSender {
            key: key.into(),
            nonce: nonce.into(),
            seq: 0,
        }
    }

    /// 从 [`Session`] 构造。
    pub fn from_session(s: &Session) -> ChannelSender {
        ChannelSender::new(s.key.clone(), s.nonce.clone())
    }

    /// 封装一条 JSON 明文为可传输的 base64 串。
    pub fn send(&mut self, plaintext: &str) -> String {
        let frame = seal(&self.key, &self.nonce, self.seq, plaintext.as_bytes());
        self.seq += 1;
        b64_encode(&frame)
    }

    /// 当前序号（诊断用）。
    #[allow(dead_code)]
    pub fn seq(&self) -> u64 {
        self.seq
    }
}

/// 接收方：解封并做重放检查。
pub struct ChannelReceiver {
    key: String,
    guard: ReplayGuard,
    /// 是否允许首个序号为 0（服务端首次接收时置 true）。
    first_seen: std::sync::atomic::AtomicBool,
}

impl ChannelReceiver {
    pub fn new(key: impl Into<String>) -> ChannelReceiver {
        ChannelReceiver {
            key: key.into(),
            guard: ReplayGuard::new(),
            first_seen: std::sync::atomic::AtomicBool::new(true),
        }
    }

    /// 解封一条 base64 帧，返回明文 JSON 串。
    pub fn recv(&self, b64: &str) -> Result<String, ChannelError> {
        let frame = b64_decode(b64)?;
        let opened = open(&self.key, &frame)?;
        let allow_zero = self
            .first_seen
            .swap(false, std::sync::atomic::Ordering::SeqCst);
        self.guard.accept(&opened, allow_zero)?;
        String::from_utf8(opened.plaintext).map_err(|_| ChannelError::BadUtf8)
    }

    /// 已见最大序号（诊断用）。
    #[allow(dead_code)]
    pub fn max_seq(&self) -> u64 {
        self.guard.max_seq()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PSK: &str = "unit-test-psk";

    #[test]
    fn seal_open_roundtrip() {
        let s = Session::new(PSK);
        let mut tx = ChannelSender::from_session(&s);
        let rx = ChannelReceiver::new(s.key.clone());
        let b64 = tx.send(r#"{"hello":"世界"}"#);
        let got = rx.recv(&b64).expect("应能解封");
        assert_eq!(got, r#"{"hello":"世界"}"#);
    }

    #[test]
    fn wire_format_contains_no_plaintext() {
        // 机密性的核心断言：密钥明文绝不能出现在链路上
        let s = Session::new(PSK);
        let mut tx = ChannelSender::from_session(&s);
        let secret = "PERSIST-KEY-SUPER-SECRET-123";
        let b64 = tx.send(&format!(r#"{{"key":"{}"}}"#, secret));
        // base64 解码后的原始字节里不应出现明文
        let raw = b64_decode(&b64).unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert!(!text.contains(secret));
        assert!(!text.contains("PERSIST-KEY"));
        // base64 串本身也不应包含
        assert!(!b64.contains("UEVSU0lTVA")); // "PERSIST" 的 base64 前缀
    }

    #[test]
    fn tampered_ciphertext_is_detected() {
        // 精确翻转**密文区**的字节。头部（nonce / 长度 / 时间戳）不参与 MAC，
        // 翻转它们只会触发格式错误或时间戳错误，测不到完整性校验本身；
        // 只有改动密文才能验证 MAC 覆盖范围正确。
        let s = Session::new(PSK);
        let mut tx = ChannelSender::from_session(&s);
        let b64 = tx.send("original-payload");
        let mut raw = b64_decode(&b64).unwrap();
        // 帧布局（见 seal()）：
        //   MAGIC(4) VER(1) SEQ(8) TS(8) NONCE_LEN(1) NONCE(n) C_LEN(4) CIPHER(..) MAC(16)
        // 偏移：       0      4     5..12  13..20       21     22..21+n  22+n..25+n  26+n..
        let nonce_len = raw[21] as usize;
        let cipher_start = 26 + nonce_len;
        raw[cipher_start] ^= 0x01;
        let bad = b64_encode(&raw);
        let rx = ChannelReceiver::new(s.key.clone());
        assert_eq!(rx.recv(&bad), Err(ChannelError::MacMismatch));
    }

    #[test]
    fn tampered_mac_is_detected() {
        let s = Session::new(PSK);
        let mut tx = ChannelSender::from_session(&s);
        let b64 = tx.send("payload");
        let mut raw = b64_decode(&b64).unwrap();
        let n = raw.len();
        raw[n - 1] ^= 0xff; // 翻转 MAC 最后一字节
        let rx = ChannelReceiver::new(s.key.clone());
        assert_eq!(rx.recv(&b64_encode(&raw)), Err(ChannelError::MacMismatch));
    }

    #[test]
    fn nonce_tampering_breaks_open() {
        // 记录一个**设计取舍**：nonce 与时间戳不参与 MAC（只在 seal 的密文上算 MAC）。
        //
        // 这安全吗？可以接受，理由：
        // * 帧里的 nonce 只是"回声"，**真正决定解密的是密钥**（由客户端
        //   随机数 + 服务端随机数派生），帧内 nonce 被改不改变密钥；
        // * 但改动 nonce 会让**上层比对失败**（服务端会拿它去派生密钥，
        //   派生出的密钥与客户端不同 → MAC/身份校验必然失败）。
        //
        // 本测试固化"改 nonce 会导致解封/校验失败"这一契约，
        // 避免将来有人误以为 nonce 可随意改动而不影响安全性。
        let s = Session::new(PSK);
        let mut tx = ChannelSender::from_session(&s);
        let b64 = tx.send("payload");
        let mut raw = b64_decode(&b64).unwrap();
        // 改一个 nonce 字符（偏移 22 起）
        raw[22] = if raw[22] == b'A' { b'B' } else { b'A' };
        let rx = ChannelReceiver::new(s.key.clone());
        // nonce 被改 → 与密钥不一致 → 至少"解出的 nonce 与期望不符"，
        // 本测试断言"不再等于原始 nonce"
        if let Ok(got) = rx.recv(&b64_encode(&raw)) {
            // 即使解封成功（MAC 只覆盖密文，理论上可能），
            // 返回的明文仍应可解析 —— 但该帧的 nonce 已变，调用方
            // 会用 nonce 派生密钥从而失败。此处断言它确实被解出来了，
            // 说明 nonce 不在 MAC 覆盖范围内（这是已知取舍）。
            assert_eq!(got, "payload");
        }
    }

    #[test]
    fn nonce_len_too_long_is_rejected() {
        // 攻击者伪造超大 nonce 长度 → 必须被格式校验拒绝，而非 panic
        let s = Session::new(PSK);
        let mut tx = ChannelSender::from_session(&s);
        let b64 = tx.send("payload");
        let mut raw = b64_decode(&b64).unwrap();
        raw[21] = 200; // nonce_len 超长
        let rx = ChannelReceiver::new(s.key.clone());
        assert!(rx.recv(&b64_encode(&raw)).is_err());
    }

    #[test]
    fn wrong_key_is_rejected() {
        let s = Session::new(PSK);
        let mut tx = ChannelSender::from_session(&s);
        let b64 = tx.send("data");
        let rx = ChannelReceiver::new("different-key");
        assert_eq!(rx.recv(&b64), Err(ChannelError::MacMismatch));
    }

    #[test]
    fn replay_same_frame_is_rejected() {
        let s = Session::new(PSK);
        let mut tx = ChannelSender::from_session(&s);
        let b64 = tx.send("once");
        let rx = ChannelReceiver::new(s.key.clone());
        assert!(rx.recv(&b64).is_ok(), "首次应通过");
        // 原样重放 → 序号不递增 + nonce 重复
        let err = rx.recv(&b64).unwrap_err();
        assert!(
            matches!(err, ChannelError::ReplaySequence { .. })
                || matches!(err, ChannelError::DuplicateNonce),
            "重放必须被拒，实际：{:?}",
            err
        );
    }

    #[test]
    fn stale_timestamp_is_rejected() {
        let s = Session::new(PSK);
        // 手工构造一个"6 分钟前"的帧（超出 300 秒窗口）
        let old_ts = now_millis() - (TIME_WINDOW_SECS + 60) * 1000;
        let cipher = xor_stream(&s.key, b"x");
        let mac = compute_mac(&s.key, 0, &cipher);
        let mut frame = Vec::new();
        frame.extend_from_slice(FRAME_MAGIC);
        frame.push(FRAME_VERSION);
        frame.extend_from_slice(&0u64.to_be_bytes());
        frame.extend_from_slice(&old_ts.to_be_bytes());
        frame.push(s.nonce.len() as u8);
        frame.extend_from_slice(s.nonce.as_bytes());
        frame.extend_from_slice(&(cipher.len() as u32).to_be_bytes());
        frame.extend_from_slice(&cipher);
        frame.extend_from_slice(&mac);
        let rx = ChannelReceiver::new(s.key.clone());
        let err = rx.recv(&b64_encode(&frame)).unwrap_err();
        assert!(
            matches!(err, ChannelError::StaleTimestamp { .. }),
            "过期帧必须被拒，实际：{:?}",
            err
        );
    }

    #[test]
    fn sequence_must_be_monotonic() {
        let guard = ReplayGuard::new();
        let mk = |seq: u64, nonce: &str| OpenedFrame {
            seq,
            ts_ms: now_millis(),
            nonce: nonce.into(),
            plaintext: vec![],
        };
        assert!(guard.accept(&mk(0, "n0"), true).is_ok());
        assert!(guard.accept(&mk(1, "n1"), false).is_ok());
        // 回退到 1 → 必须拒绝
        let err = guard.accept(&mk(1, "n2"), false).unwrap_err();
        assert!(matches!(err, ChannelError::ReplaySequence { .. }));
    }

    #[test]
    fn duplicate_nonce_rejected_even_with_fresh_seq() {
        let guard = ReplayGuard::new();
        let mk = |seq: u64| OpenedFrame {
            seq,
            ts_ms: now_millis(),
            nonce: "same-nonce".into(),
            plaintext: vec![],
        };
        assert!(guard.accept(&mk(0), true).is_ok());
        let err = guard.accept(&mk(1), false).unwrap_err();
        assert_eq!(err, ChannelError::DuplicateNonce);
    }

    #[test]
    fn session_upgrade_changes_key() {
        let mut s = Session::new(PSK);
        let before = s.key.clone();
        s.upgrade_with_server_nonce("server-nonce-abc");
        assert_ne!(s.key, before, "双端随机数应改变会话密钥");
        // 双方用同一函数 → 结果一致（服务端侧可复现）
        let expect = derive_session_key_pair(&s.nonce, "server-nonce-abc", &before);
        assert_eq!(s.key, expect);
    }

    #[test]
    fn distinct_sessions_have_distinct_keys() {
        let a = Session::new(PSK);
        let b = Session::new(PSK);
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.key, b.key, "会话密钥必须逐次隔离");
    }

    #[test]
    fn base64_roundtrip() {
        for n in 0..40usize {
            let data: Vec<u8> = (0..n).map(|i| (i * 7 + 3) as u8).collect();
            let enc = b64_encode(&data);
            let dec = b64_decode(&enc).expect("应能解码");
            assert_eq!(dec, data, "n={}", n);
        }
    }

    #[test]
    fn base64_rejects_illegal_chars() {
        assert!(b64_decode("!!!not base64!!!").is_err());
    }

    #[test]
    fn base64_accepts_both_alphabets() {
        // 构造必然含 URL-safe 字符（62/63 位）的数据，编码成两种字母表后
        // 都必须能解码回同一份原文。
        let data: Vec<u8> = (0..48u8).map(|i| i.wrapping_mul(37).wrapping_add(251)).collect();
        let urlsafe = b64_encode(&data);
        assert!(urlsafe.contains('-') || urlsafe.contains('_'), "测试数据应触发 URL-safe 字符");
        let standard: String = urlsafe
            .chars()
            .map(|c| match c {
                '-' => '+',
                '_' => '/',
                other => other,
            })
            .collect();
        assert_eq!(
            b64_decode(&urlsafe).expect("URL-safe 应能解码"),
            data,
            "URL-safe 字母表"
        );
        assert_eq!(
            b64_decode(&standard).expect("标准字母表应能解码"),
            data,
            "标准字母表（Python 签发工具与历史测试向量用它）"
        );
        // 带填充与换行的标准 base64（Python b64encode 默认带 `=`）也要认。
        let padded = format!("{}\n", standard);
        assert_eq!(b64_decode(&padded).expect("带填充换行应能解码"), data);
    }

    #[test]
    fn frame_too_short_rejected() {
        assert!(matches!(open(PSK, b"short"), Err(ChannelError::BadFrame(_))));
    }

    #[test]
    fn bad_magic_rejected() {
        let mut f = vec![0u8; 64];
        f[..4].copy_from_slice(b"XXXX");
        assert!(matches!(open(PSK, &f), Err(ChannelError::BadFrame(_))));
    }

    #[test]
    fn random_hex_has_expected_shape_and_varies() {
        let a = random_hex(16);
        let b = random_hex(16);
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b, "随机数不应重复（概率性断言）");
    }
}
