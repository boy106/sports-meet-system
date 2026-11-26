//! 授权客户端与管理器（v1.8.0 新增）。
//!
//! # 职责
//!
//! 本模块是**客户端侧**授权总入口，串起这几件事：
//!
//! ```text
//!   ① 采集机器指纹（hwid）                      → 本机唯一标识
//!   ② 与服务端建立加密信道（channel）            → 安全传输
//!   ③ 激活 / 校验 / 续期 / 停用（HTTP + 加密帧） → 拿授权
//!   ④ 本地加密缓存 + 离线降级判定                → 断网也能用
//!   ⑤ 48 位密钥验签 + 使用配额计量（v1.9.0）     → 纯离线激活码
//!   ⑥ 完整性自校验 + 反调试（v1.9.0 手段 2/3）   → 改二进制即失败
//! ```
//!
//! # 判定权在服务端 / 发行方（防白嫖的根基）
//!
//! 对**服务端密钥**：客户端不做任何密钥真伪判断。它只做两件事：把指纹与
//! 密钥送到服务端；把服务端给的**签名授权票据**存起来。票据的有效性由
//! 服务端私钥签名保证，客户端只用内置公钥验签 —— 因此即使把客户端完全
//! 反编译，攻击者也只能得到"一个公钥"，**无法自行签发有效票据**。
//!
//! 对**48 位激活密钥**（v1.9.0）：验签在客户端完成（AEAD，密钥由二进制
//! 内置主密钥 + 机器指纹派生）。这是 48 位字符容量装不下 Ed25519 签名
//! 的工程折中，边界是"提取内置主密钥需要完整逆向 + 绕过完整性自校验"，
//! 详见 `keyfmt` 模块顶部的诚实声明。要"数学不可伪造"请用 `asym` 的
//! 非对称许可文件（本模块中优先级更高的 ⓪ 号路径）。
//!
//! # 离线降级（严格对应需求）
//!
//! ```text
//!   try 联网校验
//!     ├─ 成功 → 用服务端结果（权威），刷新本地缓存
//!     └─ 失败（超时/拒绝连接/DNS 失败）
//!          └─ 读本地授权物（按优先级）
//!               ├─ 非对称许可文件（验签通过 + 指纹绑定 + 未过期）→ 放行 ✅
//!               ├─ 48 位密钥（验签通过 + 未超配额）             → 放行 ✅
//!               ├─ 缓存的「持久密钥」票据在有效期内              → 放行 ✅
//!               ├─ 缓存的「临时密钥」票据在有效期内              → 放行 ✅
//!               └─ 无授权物 / 已过期 / 配额用尽 / 二进制被改     → 拒绝 ❌
//! ```
//!
//! 这正是需求中"不能联网则转离线模式，查看以前是否使用过持久性密钥，
//! 若时效期还在则允许使用"的逐条落地。

use std::fmt::Write as _;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::core::aim::channel as ch;
use crate::core::aim::hwid;
use crate::core::aim::{asym, integrity, keyfmt, obf, trial, usage};
use crate::core::json::Json;
use crate::{log_debug, log_error, log_info, log_warn};

/// 本地授权缓存文件名。
pub const CACHE_FILE: &str = ".license";

/// 48 位激活密钥文件名（用户粘贴的密钥原文，供重启后直接载入）。
///
/// 存原文而非解析结果：密钥本身已自带验签，存原文可以让
/// 「换一个构建/升级版本后重新验签」自然发生（存解析结果反而
/// 需要防篡改）。文件内容不敏感 —— 它本来就该是用户自己能看的东西。
pub const KEY_FILE: &str = "license.key";

/// 授权缓存格式版本。
pub const CACHE_VERSION: u8 = 1;

/// 门禁"贵重复核"节流间隔（秒）：配额/许可验签/试用/完整性按此频率查。
///
/// 取 15 秒的理由：业务请求频率远高于此（页面轮询约 5 秒一次），
/// 节流后真实成本降到 1/3 以下；而 15 秒的失效延迟对"天数/小时级"
/// 的配额完全无感。日期时效不走节流（每次必查，纯整数比较）。
const RECHECK_INTERVAL_SECS: i64 = 15;

/// 网络超时（连接 + 读写）。
///
/// 取 3 秒：校园内网到授权服务通常 <50ms，3 秒足以覆盖偶发抖动；
/// 又足够短，**联网失败时老师不会等太久**（离线降级必须"快"，
/// 否则用户体验比直接报错还差）。
const NET_TIMEOUT: Duration = Duration::from_secs(3);

/// 请求体大小上限。
const MAX_RESP: usize = 256 * 1024;

/// 授权类型。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenseKind {
    /// 持久性密钥：运营预生成，绑定机器指纹，有效期长（月/年）。
    Persistent,
    /// 临时性密钥：按需签发，短时效（小时/天），通常限次数。
    Temporary,
    /// 无授权（未激活 / 已过期 / 已吊销）。
    None,
}

impl LicenseKind {
    pub fn as_str(self) -> &'static str {
        match self {
            LicenseKind::Persistent => "persistent",
            LicenseKind::Temporary => "temporary",
            LicenseKind::None => "none",
        }
    }

    pub fn parse(s: &str) -> LicenseKind {
        match s {
            "persistent" => LicenseKind::Persistent,
            "temporary" => LicenseKind::Temporary,
            _ => LicenseKind::None,
        }
    }

    /// 中文展示名（界面/日志用）。
    pub fn label(self) -> &'static str {
        match self {
            LicenseKind::Persistent => "持久性授权",
            LicenseKind::Temporary => "临时性授权",
            LicenseKind::None => "未授权",
        }
    }
}

/// 授权状态（对外唯一真相）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthState {
    /// 已授权（在线校验通过或离线缓存有效）。
    Granted,
    /// 未授权。
    Denied,
    /// 授权服务不可达，且本地无可用缓存。
    OfflineNoCache,
    /// 未配置授权服务地址（未启用授权模式）。
    NotConfigured,
}

impl AuthState {
    pub fn as_str(&self) -> &'static str {
        match self {
            AuthState::Granted => "granted",
            AuthState::Denied => "denied",
            AuthState::OfflineNoCache => "offline_no_cache",
            AuthState::NotConfigured => "not_configured",
        }
    }

    /// 是否放行使用。
    pub fn is_granted(&self) -> bool {
        matches!(self, AuthState::Granted)
    }
}

/// 授权判定结果（含解释信息，供界面与审计使用）。
#[derive(Debug, Clone)]
pub struct AuthDecision {
    pub state: AuthState,
    /// 是否处于离线模式（用了本地缓存）。
    pub offline: bool,
    /// 授权类型。
    pub kind: LicenseKind,
    /// 到期时间（Unix 秒；0 表示无）。
    pub expire_at: i64,
    /// 剩余天数（-1 表示无期限/无授权）。
    pub days_left: i64,
    /// 面向用户的说明。
    pub message: String,
    /// 机器指纹前 8 位（展示用）。
    pub hwid_short: String,
}

impl AuthDecision {
    fn new(state: AuthState, message: impl Into<String>) -> AuthDecision {
        AuthDecision {
            state,
            offline: false,
            kind: LicenseKind::None,
            expire_at: 0,
            days_left: -1,
            message: message.into(),
            hwid_short: String::new(),
        }
    }
}

/// 本地缓存中的一条授权记录。
#[derive(Debug, Clone)]
pub struct CachedLicense {
    /// 授权类型（持久/临时）。
    pub kind: LicenseKind,
    /// 机器指纹（用于校验"缓存是否属于本机"）。
    pub hwid: String,
    /// 服务端签发的票据（客户端无法伪造）。
    pub ticket: String,
    /// 到期时间（Unix 秒）。
    pub expire_at: i64,
    /// 服务端签发的原始响应（含备注、次数等）。
    pub payload: Json,
    /// 最近一次成功在线校验时间（Unix 秒）。
    pub verified_at: i64,
}

impl CachedLicense {
    /// 是否在有效期内（以本机时钟判定）。
    fn is_fresh(&self, now: i64) -> bool {
        self.expire_at > now
    }

    /// 转 JSON（落盘用）。
    fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("kind", Json::s(self.kind.as_str()));
        o.set("hwid", Json::s(self.hwid.clone()));
        o.set("ticket", Json::s(self.ticket.clone()));
        o.set("expire_at", Json::Int(self.expire_at));
        o.set("verified_at", Json::Int(self.verified_at));
        o.set("payload", self.payload.clone());
        o
    }

    /// 从 JSON 还原。字段缺失或类型不符时返回 None（缓存损坏）。
    fn from_json(j: &Json) -> Option<CachedLicense> {
        Some(CachedLicense {
            kind: LicenseKind::parse(j.get_str("kind").unwrap_or("none")),
            hwid: j.get_str("hwid").unwrap_or("").to_string(),
            ticket: j.get_str("ticket").unwrap_or("").to_string(),
            expire_at: j.get_i64("expire_at").unwrap_or(0),
            payload: j.get("payload").cloned().unwrap_or_else(Json::obj),
            verified_at: j.get_i64("verified_at").unwrap_or(0),
        })
    }
}

/// 本地授权缓存：整体加密封装后落盘（`data/.license`）。
///
/// 为什么"整体加密"而不是只存明文 JSON：
/// 授权票据虽经服务端签名**不可伪造**，但明文落盘会让攻击者容易
/// 分析票据结构（例如看出 `expire_at` 字段并尝试手工改大）。
/// 虽然改了签名会失效，但"让攻击面变模糊"本身就有价值 ——
/// 这与 `vault.rs` 的定位一致：**提高门槛**。
#[derive(Debug, Clone)]
pub struct LicenseCache {
    /// 已缓存的授权（可能同时有持久与临时各一条）。
    pub entries: Vec<CachedLicense>,
}

impl Default for LicenseCache {
    fn default() -> Self {
        LicenseCache {
            entries: Vec::new(),
        }
    }
}

impl LicenseCache {
    /// 从数据目录读取缓存。文件不存在/损坏/解密失败均返回空缓存
    /// （**不报错**：缓存损坏不应阻止程序启动，只是需要重新激活）。
    ///
    /// `hwid` 参与缓存密钥派生 —— 传错指纹等于拿错钥匙，必然解不开。
    pub fn load(data_dir: &Path, hwid: &str) -> LicenseCache {
        let path = data_dir.join(CACHE_FILE);
        let raw = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => return LicenseCache::default(),
        };
        let text = match decrypt_cache(hwid, &raw) {
            Some(t) => t,
            None => {
                log_warn!("aim", "本地授权缓存解密失败（可能被篡改、指纹不符或密钥不符），已忽略");
                return LicenseCache::default();
            }
        };
        let j = match Json::parse(&text) {
            Ok(j) => j,
            Err(e) => {
                log_warn!("aim", "本地授权缓存 JSON 解析失败：{}，已忽略", e);
                return LicenseCache::default();
            }
        };
        if j.get_i64("version").unwrap_or(0) != CACHE_VERSION as i64 {
            log_info!("aim", "本地授权缓存版本不符，按空缓存处理");
            return LicenseCache::default();
        }
        let mut entries = Vec::new();
        if let Some(arr) = j.get("entries").and_then(|v| v.as_arr()) {
            for e in arr {
                if let Some(c) = CachedLicense::from_json(e) {
                    entries.push(c);
                }
            }
        }
        LicenseCache { entries }
    }

    /// 原子写入缓存（临时文件 → fsync → rename）。
    ///
    /// 原子性很重要：若写一半断电，留下半个文件会导致下次启动
    /// "缓存解析失败 → 需重新激活"。用 rename 保证"要么旧要么新"。
    pub fn save(&self, data_dir: &Path, hwid: &str) -> Result<(), String> {
        let mut j = Json::obj();
        j.set("version", Json::Int(CACHE_VERSION as i64));
        j.set("saved_at", Json::Int(ch::now_secs()));
        j.set(
            "entries",
            Json::arr(self.entries.iter().map(|e| e.to_json())),
        );
        let text = j.to_string_pretty();
        let sealed = encrypt_cache(hwid, text.as_bytes());
        let path = data_dir.join(CACHE_FILE);
        std::fs::create_dir_all(data_dir).map_err(|e| format!("创建数据目录失败：{}", e))?;
        let tmp = data_dir.join(format!("{}.tmp", CACHE_FILE));
        {
            let mut f = std::fs::File::create(&tmp).map_err(|e| format!("写缓存失败：{}", e))?;
            f.write_all(&sealed).map_err(|e| format!("写缓存失败：{}", e))?;
            f.flush().map_err(|e| format!("刷缓存失败：{}", e))?;
            // fsync：确保 rename 前数据真正落盘（否则断电可能得到空文件）
            let _ = f.sync_all();
        }
        std::fs::rename(&tmp, &path).map_err(|e| format!("替换缓存失败：{}", e))?;
        Ok(())
    }

    /// 取本机某类型的最新一条有效缓存。
    fn find_valid(&self, hwid: &str, kind: LicenseKind, now: i64) -> Option<&CachedLicense> {
        self.entries
            .iter()
            .filter(|e| e.kind == kind && e.hwid == hwid && e.is_fresh(now))
            .max_by_key(|e| e.expire_at)
    }

    /// 写入或更新一条记录（同类型+同指纹覆盖）。
    fn upsert(&mut self, entry: CachedLicense) {
        if let Some(pos) = self
            .entries
            .iter()
            .position(|e| e.kind == entry.kind && e.hwid == entry.hwid)
        {
            self.entries[pos] = entry;
        } else {
            self.entries.push(entry);
        }
    }

    /// 移除某类型的记录（被服务端吊销时调用）。
    fn remove(&mut self, hwid: &str, kind: LicenseKind) {
        self.entries
            .retain(|e| !(e.kind == kind && e.hwid == hwid));
    }
}

// ---------------------------------------------------------------------------
// 缓存文件加解密（复用 channel 的流密码思想，用固定用途密钥）
// ---------------------------------------------------------------------------

/// 缓存加密用途密钥（与 PSK 派生，避免直接用 PSK 加密文件）。
///
/// 明文为 `"sports-meet::aim::cache::v1.8.0"`，以 XOR 混淆存放。
const CACHE_SALT_MASKED: [u8; 31] = [
    0x29, 0x37, 0x0f, 0x7f, 0x5a, 0xb8, 0xd9, 0xfc, 0xd7, 0x3a, 0x0c, 0x5f, 0x3c, 0x42, 0xa5,
    0x84, 0xb0, 0x8d, 0x33, 0x1c, 0x7d, 0x53, 0x41, 0xfb, 0xd8, 0xf9, 0x99, 0x7b, 0x4e, 0x3d,
    0x0c,
];

/// 派生缓存文件密钥。
///
/// **必须把机器指纹作为输入**（v1.8.1 修复的真实漏洞）：
///
/// 旧版只用「盐 ‖ PSK」派生，于是缓存文件用**与机器无关**的密钥加密。
/// 而 PSK 是明文写在 `config.json` 里的，攻击者因此可以：
///   ① 用同一算法解出缓存明文 → ② 改掉 JSON 里的 `hwid` 字段 →
///   ③ 用同一算法重新加密 → ④ 换一台机器白嫖。
/// 文档里"缓存与机器指纹绑定、拷贝无效"当时并没有兑现。
///
/// 修复后 `hwid` 参与密钥派生：换机器 → 密钥不同 → **连解密都失败**，
/// 而不是"解密成功但 hwid 不匹配"。前者才是真的绑死。
fn cache_key(hwid: &str) -> String {
    let salt = ch::deobfuscate(&CACHE_SALT_MASKED);
    // FNV-1a 四段混合：用途盐 ‖ **主密钥** ‖ hwid。
    //
    // v1.9.1 加固（第三轮）：这里原来混的是 `DEFAULT_PSK` —— 那是**明文
    // 常量**，`strings` 就能从二进制里读出来。攻击者据此可以在不改二进制
    // 的前提下离线伪造 `license.cache`（`--hwid` 会直接打印本机指纹），
    // 这是比"改 is_granted"更省力的绕过路径（实测确认：缓存条目只按
    // hwid + expire_at 判定，`ticket` 字段本地**从不验签**）。
    //
    // 改混**主密钥**后，纯字符串提取不再够用：主密钥以掩码形式存放，
    // 必须逆向 `MASTER_MASKED ^ UNMASK` 才能得到，与"自己伪造 48 位密钥"
    // 同等成本 —— 两条路的门槛被拉平，都不再是"读几个字符串"就能完成的。
    //
    // 代价：升级后旧 `license.cache` 全部解不开（密钥变了），需重新激活一次。
    let master = crate::core::aim::keyfmt::master_secret();
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in salt.bytes().chain(master.iter().copied()) {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    for b in hwid.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let mut s = String::new();
    let _ = write!(s, "{:016x}", h);
    s
}

/// 缓存文件魔数。
const CACHE_MAGIC: &[u8; 4] = b"SMAL";

/// 加密缓存：`MAGIC(4) ‖ VER(1) ‖ 密文 ‖ MAC(16)`。
///
/// `hwid` 参与密钥派生（见 [`cache_key`]），因此**换机器即无法解密**。
fn encrypt_cache(hwid: &str, plain: &[u8]) -> Vec<u8> {
    let key = cache_key(hwid);
    let cipher = ch::seal(&key, "cache", 0, plain);
    let mut out = Vec::with_capacity(cipher.len() + 5);
    out.extend_from_slice(CACHE_MAGIC);
    out.push(CACHE_VERSION);
    out.extend_from_slice(&cipher);
    out
}

/// 解密缓存。魔数不符 / MAC 失败 / **指纹不符**均返回 None。
fn decrypt_cache(hwid: &str, raw: &[u8]) -> Option<String> {
    if raw.len() < 5 || &raw[..4] != CACHE_MAGIC {
        return None;
    }
    if raw[4] != CACHE_VERSION {
        return None;
    }
    let key = cache_key(hwid);
    let opened = ch::open(&key, &raw[5..]).ok()?;
    String::from_utf8(opened.plaintext).ok()
}

// ---------------------------------------------------------------------------
// HTTP 传输（自实现，走加密帧）
// ---------------------------------------------------------------------------

/// 授权服务回应。
struct ServerReply {
    status: u16,
    body: String,
}

/// 向授权服务发送一个加密请求。
///
/// 请求体是**加密帧的 base64**，因此链路上不存在明文密钥。
/// 使用 `POST` + `application/octet-stream`，避免被中间设备当作文本日志记录。
fn post_encrypted(
    host: &str,
    port: u16,
    path: &str,
    frame_b64: &str,
) -> Result<ServerReply, String> {
    let addr = format!("{}:{}", host, port);
    let sock = addr
        .to_socket_addrs()
        .map_err(|e| format!("解析授权服务地址失败：{}", e))?
        .next()
        .ok_or_else(|| "授权服务地址无法解析".to_string())?;
    let mut stream =
        TcpStream::connect_timeout(&sock, NET_TIMEOUT).map_err(|e| format!("连接授权服务失败：{}", e))?;
    stream
        .set_read_timeout(Some(NET_TIMEOUT))
        .map_err(|e| e.to_string())?;
    stream
        .set_write_timeout(Some(NET_TIMEOUT))
        .map_err(|e| e.to_string())?;

    let req = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{}",
        path,
        addr,
        frame_b64.len(),
        frame_b64
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|e| format!("发送授权请求失败：{}", e))?;
    stream.flush().ok();

    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > MAX_RESP {
                    return Err("授权服务响应过大".into());
                }
            }
            Err(e) => return Err(format!("读取授权响应失败：{}", e)),
        }
    }
    let text = String::from_utf8_lossy(&buf).to_string();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| "授权服务响应格式非法".to_string())?;
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| "授权服务响应缺少状态码".to_string())?;
    Ok(ServerReply {
        status,
        body: body.to_string(),
    })
}

/// 授权服务配置。
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// 服务端主机（IP 或域名）。
    pub host: String,
    /// 服务端端口。
    pub port: u16,
    /// 预共享密钥（须与服务端一致）。
    pub psk: String,
    /// 是否启用授权。为 false 时全部判定为 NotConfigured（向后兼容）。
    pub enabled: bool,
}

impl Default for AuthConfig {
    fn default() -> Self {
        AuthConfig {
            host: String::new(),
            port: 8766,
            psk: ch::DEFAULT_PSK.to_string(),
            enabled: false,
        }
    }
}

impl AuthConfig {
    /// 从 JSON 配置节构造。
    ///
    /// v1.9.1 加固：配置缺失/为空时不再回退到内置默认 PSK——
    /// 旧版 `unwrap_or(DEFAULT_PSK)` 意味着"装上就能对上服务端默认口令"，
    /// 发布包即携带共享秘密。未配置 PSK 时由 `AuthManager::new` 降级为停用。
    pub fn from_json(j: &Json) -> AuthConfig {
        let host = j.get_str("host").unwrap_or("").trim().to_string();
        AuthConfig {
            enabled: j.get_bool("enabled").unwrap_or(false) && !host.is_empty(),
            host,
            port: j.get_i64("port").unwrap_or(8766).max(1).min(65535) as u16,
            psk: j.get_str("psk").unwrap_or("").trim().to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// 授权管理器
// ---------------------------------------------------------------------------

/// 客户端授权管理器（唯一对外入口）。
pub struct AuthManager {
    config: AuthConfig,
    data_dir: PathBuf,
    /// 本机机器指纹（启动时采集一次并缓存）。
    hwid: String,
    /// 机器信息（用于诊断展示）。
    info: hwid::HwidInfo,
    /// 本地缓存。
    cache: LicenseCache,
    /// 最近一次判定结果（供诊断接口读取，不重复跑网络）。
    last: AuthDecision,
    /// 试用管理器（内置试用密钥 + 分散冗余记录）。
    trial: trial::TrialManager,
    /// 最近一次反调试扫描结果。
    threat: obf::ScanReport,
    /// 离线许可（非对称签名，v1.9.0 手段 1）。`None` 表示未放置/解析失败。
    offline_license: Option<asym::LicenseFile>,
    /// 48 位激活密钥（v1.9.0）。`None` 表示未激活/验签失败。
    active_key: Option<keyfmt::KeyLicense>,
    /// 使用配额计量器（使用次数 / 累计时长，v1.9.0）。
    usage: usage::UsageTracker,
    /// 上一次"贵重复核"的时间（Unix 秒；见 `recheck_gate`）。
    last_recheck: i64,
    /// 上一次完整性前置检查的时间（Unix 秒；v1.9.1）。
    last_integrity: i64,
    /// 完整性前置检查的**结论**（v1.9.1）。
    ///
    /// 必须缓存结论而不是"节流期直接放行"：实测第一次请求被拦住，
    /// 15 秒节流窗口内的后续请求却 200 —— 因为节流只跳过了检查，
    /// 没有复用"不通过"这个结论。缓存结论才是对的。
    integrity_ok: bool,
}

impl AuthManager {
    /// 构造管理器（采集指纹 + 载入缓存，**不发网络请求**）。
    pub fn new(mut config: AuthConfig, data_dir: &Path) -> AuthManager {
        // v1.9.1 加固：空 PSK 或仍为历史内置默认值的配置一律降级为停用，
        // 防止"默认口令出厂即有效"。AuthConfig::default 的占位值仅供单测，
        // 不应进入真实判定路径。
        if config.enabled && (config.psk.is_empty() || config.psk == ch::DEFAULT_PSK) {
            log_warn!(
                "aim",
                "license_server.psk 未配置或仍为默认值，已停用服务端授权通道（请生成随机 PSK 后重试）"
            );
            config.enabled = false;
        }
        let info = hwid::collect();
        let hwid = info.fingerprint();
        // 缓存密钥由 hwid 派生，故必须先算指纹再读缓存
        let cache = LicenseCache::load(data_dir, &hwid);
        if info.degraded {
            log_warn!(
                "aim",
                "机器指纹已降级（稳定硬件特征不足两项）：{}",
                info.warnings.join("；")
            );
        }
        let mut last = AuthDecision::new(AuthState::NotConfigured, "未配置授权服务");
        last.hwid_short = info.short_id();
        // 试用管理器与反调试扫描在构造期初始化（不发网络、不改文件）。
        let trial = trial::TrialManager::new(&hwid, data_dir, trial::TrialPolicy::default());
        let threat = obf::scan();
        if threat.level.should_block() {
            log_warn!("aim", "环境检测：{}", threat.summary());
        } else if !threat.signals.is_empty() {
            log_debug!("aim", "环境检测：{}", threat.summary());
        }
        // v1.9.0：使用配额计量器（主密钥缺失时整体停用，返回不限量）。
        let master = if keyfmt::master_secret_configured() {
            Some(keyfmt::master_secret())
        } else {
            None
        };
        let usage = usage::UsageTracker::new(&hwid, data_dir, master.as_ref());
        // v1.9.0：载入 48 位激活密钥（仅解析验签，不记次数 —— 记账在 decide()）。
        let active_key = Self::load_key_file(data_dir, &hwid);
        if let Some(lic) = &active_key {
            log_info!(
                "aim",
                "已载入 48 位激活密钥：{}（编号 {:06x}）",
                lic.kind.label(),
                lic.key_id
            );
        }
        AuthManager {
            config,
            data_dir: data_dir.to_path_buf(),
            hwid,
            info,
            cache,
            last,
            trial,
            threat,
            offline_license: Self::load_offline_license(data_dir),
            active_key,
            usage,
            last_recheck: 0,
            last_integrity: 0,
            // 初始为"未验证"：第一次请求必然触发一次真实检查
            integrity_ok: false,
        }
    }

    /// 从 `data/license.key` 载入 48 位密钥并验签。
    ///
    /// 文件不存在 → `None`（正常状态，不刷日志）；
    /// 存在但验签失败 → `None` + 一条告警（用户会看到激活失败原因）。
    fn load_key_file(data_dir: &Path, hwid: &str) -> Option<keyfmt::KeyLicense> {
        let path = data_dir.join(KEY_FILE);
        let text = std::fs::read_to_string(&path).ok()?;
        match keyfmt::open_key(text.trim(), hwid, ch::now_secs()) {
            Ok(lic) => Some(lic),
            Err(e) => {
                log_warn!("aim", "48 位激活密钥无效（{}）：{}", path.display(), e);
                None
            }
        }
    }

    /// 从 `data/license.lic` 载入离线许可（不校验，仅解析）。
    ///
    /// 解析失败**不报错**（返回 None）—— 用户没放许可文件是正常状态，
    /// 不该在启动时刷一堆日志。真正的失败原因在验签阶段给出。
    fn load_offline_license(data_dir: &Path) -> Option<asym::LicenseFile> {
        let path = data_dir.join("license.lic");
        let text = std::fs::read_to_string(&path).ok()?;
        match asym::LicenseFile::parse(&text) {
            Ok(lf) => Some(lf),
            Err(e) => {
                log_warn!("aim", "离线许可文件解析失败（{}）：{}", path.display(), e);
                None
            }
        }
    }

    /// 重新载入离线许可（用户放入新许可后无需重启）。
    pub fn reload_offline_license(&mut self) -> bool {
        self.offline_license = Self::load_offline_license(&self.data_dir);
        self.offline_license.is_some()
    }

    /// 当前离线许可是否有效（验签 + 指纹绑定 + 未过期）。
    pub fn offline_license_status(&self) -> (bool, String) {
        match &self.offline_license {
            None => (false, "未放置离线许可文件".to_string()),
            Some(lf) => {
                if !asym::issuer_key_configured() {
                    return (false, "本构建未配置签发公钥（无法校验离线许可）".to_string());
                }
                lf.validate(&asym::ISSUER_PUBLIC_KEY, &self.hwid, ch::now_secs())
            }
        }
    }

    // ───────────────────────────────────────────────────────────────
    // v1.9.0：48 位混合字符密钥（便携激活码）
    // ───────────────────────────────────────────────────────────────

    /// 用一枚 48 位密钥激活（**完全离线**，不需要授权服务）。
    ///
    /// 流程：反调试闸门 → 完整性自校验 → 验签 + 指纹绑定 + 时效
    /// → 配额检查 → 落盘 → 记账（本次激活计 1 次使用）。
    ///
    /// 与 `activate_trial` 共用同一道反调试闸门：只在**高度可疑**
    /// （多路强信号同时命中）时拒绝，避免误杀真实用户。
    pub fn activate_key(&mut self, key_text: &str) -> AuthDecision {
        let threat = obf::scan();
        self.threat = threat.clone();
        // v1.9.2：永久免费后，"反复白嫖限时试用"这个动机不存在了，
        // 反调试闸门留着只会误伤（老师挂着录屏/输入法/安全软件都可能被
        // 判为可疑）。限时模式下仍然保留该闸门。
        if !self.trial.is_perpetual() && threat.level.should_block() {
            log_warn!("aim", "拒绝激活密钥：{}", threat.summary());
            let mut d = AuthDecision::new(
                AuthState::Denied,
                "检测到调试/逆向环境，已拒绝激活".to_string(),
            );
            d.hwid_short = self.info.short_id();
            self.last = d.clone();
            return d;
        }

        // 完整性自校验（手段 2）：二进制被改过 → 拒绝激活。
        // 只在这里查一次：激活是"授权体系的入口"，入口被污染时
        // 后面所有判定都不可信。
        let ir = integrity::verify_self();
        if ir.is_fatal() {
            log_error!("aim", "拒绝激活密钥：{}", ir.summary());
            let mut d = AuthDecision::new(
                AuthState::Denied,
                format!("程序完整性校验失败（{}），已拒绝激活", ir.summary()),
            );
            d.hwid_short = self.info.short_id();
            self.last = d.clone();
            return d;
        }

        let text = key_text.trim();
        if text.is_empty() {
            let mut d = AuthDecision::new(AuthState::Denied, "密钥不能为空");
            d.hwid_short = self.info.short_id();
            self.last = d.clone();
            return d;
        }

        let now = ch::now_secs();
        let lic = match keyfmt::open_key(text, &self.hwid, now) {
            Ok(l) => l,
            Err(e) => {
                log_info!("aim", "密钥激活失败：{}", e);
                let mut d = AuthDecision::new(AuthState::Denied, e);
                d.hwid_short = self.info.short_id();
                self.last = d.clone();
                return d;
            }
        };

        // 配额检查（check 内部会 tick 累计时长）
        if let Some(deny) = self.key_quota_denial(&lic, now) {
            self.active_key = Some(lic); // 保留展示：让界面能显示"已用尽"
            self.last = deny.clone();
            return deny;
        }

        // 落盘密钥原文（重启后直接载入，无需再激活）
        let path = self.data_dir.join(KEY_FILE);
        if let Err(e) = std::fs::create_dir_all(&self.data_dir)
            .and_then(|_| std::fs::write(&path, format!("{}\n", text)))
        {
            log_error!("aim", "密钥写入失败：{}（不影响本次使用）", e);
        }

        // 记账：激活本身计 1 次使用
        let st = self.usage.record_launch(now);
        self.active_key = Some(lic.clone());
        let mut d = AuthDecision::new(
            AuthState::Granted,
            format!("密钥激活成功：{}", lic.describe()),
        );
        d.offline = true; // 密钥激活完全离线
        d.kind = if lic.kind.is_short_lived() {
            LicenseKind::Temporary
        } else {
            LicenseKind::Persistent
        };
        if !lic.perpetual() {
            d.expire_at = (lic.valid_until_day as i64) * 86400 + 86399;
            d.days_left = ((lic.valid_until_day as i64) - keyfmt::today_day(now) as i64).max(0);
        }
        d.hwid_short = self.info.short_id();
        log_info!(
            "aim",
            "48 位密钥激活成功：{}（第 {} 次使用）",
            lic.kind.label(),
            st.launches
        );
        self.last = d.clone();
        d
    }

    /// 停用 48 位密钥（删密钥文件 + 清计量；不影响其他授权路径）。
    pub fn deactivate_key(&mut self) -> AuthDecision {
        let path = self.data_dir.join(KEY_FILE);
        let _ = std::fs::remove_file(&path);
        self.usage.clear_all();
        self.active_key = None;
        let mut d = AuthDecision::new(AuthState::Denied, "已停用 48 位激活密钥（计量已清除）");
        d.hwid_short = self.info.short_id();
        self.last = d.clone();
        d
    }

    /// 当前激活的密钥（只读）。
    pub fn key_license(&self) -> Option<&keyfmt::KeyLicense> {
        self.active_key.as_ref()
    }

    /// 配额是否超限（超限时返回一条 Denied 决策）。
    fn key_quota_denial(&self, lic: &keyfmt::KeyLicense, now: i64) -> Option<AuthDecision> {
        match self.usage.check(lic, now) {
            usage::QuotaVerdict::Ok { .. } => None,
            usage::QuotaVerdict::LaunchesExhausted { used, limit } => {
                let mut d = AuthDecision::new(
                    AuthState::Denied,
                    format!(
                        "密钥使用次数已用尽（{} / {} 次）：请联系管理员续购或更换密钥",
                        used, limit
                    ),
                );
                d.hwid_short = self.info.short_id();
                Some(d)
            }
            usage::QuotaVerdict::SecondsExhausted { used, limit } => {
                let mut d = AuthDecision::new(
                    AuthState::Denied,
                    format!(
                        "密钥使用时长已用尽（{} / {} 秒）：请联系管理员续购或更换密钥",
                        used, limit
                    ),
                );
                d.hwid_short = self.info.short_id();
                Some(d)
            }
        }
    }

    /// 密钥状态字段（脱敏；供 `/api/aim/status` 与诊断页）。
    pub fn key_fields(&self) -> Option<Json> {
        let lic = self.active_key.as_ref()?;
        let mut o = Json::obj();
        o.set("kind", Json::s(lic.kind.as_str()));
        o.set("kind_label", Json::s(lic.kind.label()));
        o.set("perpetual", Json::Bool(lic.perpetual()));
        o.set("key_id", Json::Int(lic.key_id as i64));
        if let Some((y, m, d)) = lic.until_ymd() {
            o.set("valid_until", Json::s(format!("{:04}-{:02}-{:02}", y, m, d)));
        }
        // 功能位 → 人类可读名（不含位运算细节）
        let names: Vec<Json> = feature_names(lic.feature_flags)
            .iter()
            .map(|s| Json::s(s.to_string()))
            .collect();
        o.set("features", Json::arr(names));
        // 用量快照（计量停用时给 0，由 UI 显示"未计量"）
        let snap = self.usage.usage_snapshot(ch::now_secs());
        o.set("launches_used", Json::Int(snap.launches as i64));
        o.set("seconds_used", Json::Int(snap.seconds as i64));
        if lic.usage_count_limit > 0 {
            o.set(
                "launches_limit",
                Json::Int(lic.usage_count_limit as i64),
            );
        }
        if lic.usage_seconds_limit > 0 {
            o.set(
                "seconds_limit",
                Json::Int(lic.usage_seconds_limit as i64),
            );
        }
        Some(o)
    }

    /// 当前放行来源允许的功能位图。
    ///
    /// 密钥路径 → 密钥自带的功能限制；其他路径（试用 / 在线票据 /
    /// 非对称许可文件）→ 全功能。未授权时返回全功能**无实际影响**：
    /// 门禁会先整体拦截（`granted=false`），功能位根本走不到。
    pub fn features(&self) -> u16 {
        match &self.active_key {
            Some(lic) if self.last.state.is_granted() => lic.feature_flags,
            _ => keyfmt::FEAT_ALL,
        }
    }

    /// 某功能是否允许（api 层按位查询）。
    pub fn feature_allowed(&self, flag: u16) -> bool {
        self.features() & flag != 0
    }

    /// 机器指纹（完整 16 位；供内部与测试使用，状态接口只给前 8 位）。
    #[allow(dead_code)]
    pub fn hwid(&self) -> &str {
        &self.hwid
    }

    /// 机器信息（诊断用）。
    pub fn hwid_info(&self) -> &hwid::HwidInfo {
        &self.info
    }

    /// 授权是否已启用。
    pub fn configured(&self) -> bool {
        self.config.enabled
    }

    /// 最近一次判定结果。
    pub fn last_decision(&self) -> &AuthDecision {
        &self.last
    }

    /// 最近一次反调试扫描结果（诊断用）。
    pub fn threat(&self) -> &obf::ScanReport {
        &self.threat
    }

    /// 重新执行一次反调试扫描并刷新缓存结果。
    pub fn rescan_threat(&mut self) -> &obf::ScanReport {
        self.threat = obf::scan();
        &self.threat
    }

    /// 当前试用状态（只读）。
    pub fn trial_status(&self) -> trial::TrialState {
        self.trial.status()
    }

    /// 输入的密钥是否是内置试用密钥。
    pub fn is_trial_key(&self, key: &str) -> bool {
        self.trial.is_trial_key(key)
    }

    /// 用内置试用密钥启用 30 分钟试用。
    ///
    /// 与普通 `activate_*` 的区别：试用**完全离线**，不需要服务端，
    /// 靠本地分散冗余记录保证"一次性"。
    ///
    /// # 安全闸（分级响应）
    ///
    /// 若反调试扫描判定为 `High`（多路强信号同时命中），**拒绝启用** ——
    /// 这是"发现内存里有逆向工具就停止"的落点。注意仅 `High` 才拒，
    /// 避免误杀开着杀毒/还原卡的真实用户（详见 [`obf`] 模块说明）。
    pub fn activate_trial(&mut self) -> AuthDecision {
        // 闸门：仅在高度可疑时拒绝
        let threat = obf::scan();
        self.threat = threat.clone();
        // v1.9.2：永久免费后，"反复白嫖限时试用"这个动机不存在了，
        // 反调试闸门留着只会误伤（老师挂着录屏/输入法/安全软件都可能被
        // 判为可疑）。限时模式下仍然保留该闸门。
        if !self.trial.is_perpetual() && threat.level.should_block() {
            log_warn!("aim", "拒绝启用试用：{}", threat.summary());
            let mut d = AuthDecision::new(
                AuthState::Denied,
                "检测到调试/逆向环境，已拒绝启用试用授权".to_string(),
            );
            d.hwid_short = self.info.short_id();
            self.last = d.clone();
            return d;
        }

        match self.trial.activate_trial() {
            Ok(state) => {
                let granted = state.is_granted();
                let mut d = AuthDecision::new(
                    if granted {
                        AuthState::Granted
                    } else {
                        AuthState::Denied
                    },
                    state.message(),
                );
                d.offline = true;
                d.kind = LicenseKind::Temporary;
                if let trial::TrialState::Active(secs) = state {
                    // v1.9.2：永久模式下 secs 是哨兵值，不能拿来算到期时间
                    // —— 否则 `now + 100 年` 会溢出并显示成负数/1970 年。
                    // 永久即 `expire_at = 0`（与"无到期"的既有约定一致）。
                    d.expire_at = if self.trial.is_perpetual() {
                        0
                    } else {
                        ch::now_secs() + secs
                    };
                }
                d.hwid_short = self.info.short_id();
                self.last = d.clone();
                d
            }
            Err(e) => {
                let mut d = AuthDecision::new(AuthState::Denied, e);
                d.hwid_short = self.info.short_id();
                self.last = d.clone();
                d
            }
        }
    }

    /// 结束试用并标记为已消耗（到期/主动结束）。
    pub fn end_trial(&mut self) {
        self.trial.mark_consumed();
    }

    /// 用持久性密钥激活（联网）。
    ///
    /// 成功则把服务端签发的票据写入本地缓存，返回判定结果。
    pub fn activate_persistent(&mut self, key: &str, note: &str) -> AuthDecision {
        self.activate(key, LicenseKind::Persistent, note)
    }

    /// 用临时性密钥激活（联网）。
    pub fn activate_temporary(&mut self, key: &str, note: &str) -> AuthDecision {
        self.activate(key, LicenseKind::Temporary, note)
    }

    /// 激活通用流程。
    fn activate(&mut self, key: &str, kind: LicenseKind, note: &str) -> AuthDecision {
        if !self.config.enabled {
            let mut d = AuthDecision::new(AuthState::NotConfigured, "未配置授权服务地址");
            d.hwid_short = self.info.short_id();
            self.last = d.clone();
            return d;
        }
        let key = key.trim();
        if key.is_empty() {
            let mut d = AuthDecision::new(AuthState::Denied, "密钥不能为空");
            d.hwid_short = self.info.short_id();
            self.last = d.clone();
            return d;
        }

        // 构造激活请求（明文 JSON → 加密帧）
        let mut req = Json::obj();
        req.set("action", Json::s("activate"));
        req.set("hwid", Json::s(self.hwid.clone()));
        req.set("key", Json::s(key));
        req.set("kind", Json::s(kind.as_str()));
        req.set("note", Json::s(note));

        match self.exchange(&req) {
            Ok(resp) => self.apply_server_reply(resp, kind),
            Err(e) => {
                // 联网失败 → 立刻降级到离线判定（不做重试等待，用户体验优先）
                log_warn!("aim", "激活时无法连接授权服务（{}），转离线判定", e);
                let mut d = self.offline_decision();
                d.message = format!("无法连接授权服务（{}）；{}", e, d.message);
                self.last = d.clone();
                d
            }
        }
    }

    /// 在线校验 / 续期。无参数，用本地缓存里的票据向服务端确认仍有效。
    pub fn verify_online(&mut self) -> AuthDecision {
        if !self.config.enabled {
            let mut d = AuthDecision::new(AuthState::NotConfigured, "未配置授权服务");
            d.hwid_short = self.info.short_id();
            self.last = d.clone();
            return d;
        }
        let mut req = Json::obj();
        req.set("action", Json::s("verify"));
        req.set("hwid", Json::s(self.hwid.clone()));
        let ticket = self
            .cache
            .entries
            .iter()
            .find(|e| e.hwid == self.hwid)
            .map(|e| e.ticket.clone())
            .unwrap_or_default();
        req.set("ticket", Json::s(ticket));

        match self.exchange(&req) {
            Ok(resp) => {
                let kind = LicenseKind::parse(resp.get_str("kind").unwrap_or("none"));
                self.apply_server_reply(resp, kind)
            }
            Err(e) => {
                log_warn!("aim", "在线校验失败（{}），转离线判定", e);
                let mut d = self.offline_decision();
                d.message = format!("无法连接授权服务（{}）；{}", e, d.message);
                self.last = d.clone();
                d
            }
        }
    }

    /// 判定当前是否可用（**启动时调用一次**）。
    ///
    /// 流程：有票据则先在线校验；联网失败或校验不可用则走离线判定。
    /// 无票据时直接给离线判定（提示需要激活）。
    ///
    /// v1.9.0 变更：未配置服务端时**不再直接返回 NotConfigured**，
    /// 而是走离线判定 —— 48 位密钥 / 非对称许可文件都是纯离线路径，
    /// 与服务端是否配置无关。三者皆无时才提示需要激活。
    pub fn decide(&mut self) -> AuthDecision {
        if !self.config.enabled {
            let d = self.offline_decision();
            self.last = d.clone();
            return d;
        }
        let has_ticket = self.cache.entries.iter().any(|e| e.hwid == self.hwid);
        let d = if has_ticket {
            self.verify_online()
        } else {
            self.offline_decision()
        };
        d
    }

    /// 门禁复核：`last` 说放行时，再确认"**现在**仍然该放行"。
    ///
    /// 为什么存在：`last` 是启动时/激活时算出的**快照**。一份 3 天有效的
    /// 密钥在第 4 天、一个 30 分钟试用在第 31 分钟、一个 100 次的配额在
    /// 第 101 次启动时，若不再复核，长跑的服务器会凭过期快照一直放行 ——
    /// "有效时间 / 使用时间 / 使用次数"全部落空。http.rs 的授权门禁在
    /// 每个业务请求拦截判定前都会过这里。
    ///
    /// 成本控制（否则每个请求都读盘验签，界面会卡）：
    /// * **每次必查（免费）**：48 位密钥的日期时效（纯整数比较）；
    /// * **15 秒节流**：配额（要读写计量文件）、离线许可（Ed25519 验签）、
    ///   试用（读分散冗余记录）、完整性自校验（读整个二进制）。
    ///   改动系统时钟绕不过"计量文件在磁盘上"（tick 有单次累加上限）。
    ///
    /// 通过时**不刷新** `last`（放行结论不变，避免无谓的状态churn）；
    /// 仅在"转为拒绝"时写入 `last`，让诊断页/状态接口如实反映。
    pub fn recheck_gate(&mut self) -> bool {
        if !self.last.state.is_granted() {
            return false;
        }
        let now = ch::now_secs();

        // ⓪-1 完整性前置（v1.9.1）：**无条件执行，不以"有没有授权物"为前提**。
        //
        // 为什么必须提到最前面：破解最省力的一步是把 `is_granted()` 改成
        // 恒真 —— 此时 `any_grant_alive()` 里的完整性分支根本不会跑
        // （那里以 `has_material` 为前提）。实测：只改那一行 + 删掉盖章
        // 缓存（让自校验退回"只算不判"的基线模式），业务接口即可 200。
        //
        // 这里同时否掉两种情况：
        //   * 已盖章但校验不过（改过二进制）；
        //   * **基线模式**（发行构建里不存在盖不了的合法情形，删缓存重编译
        //     是典型破解手法；debug 构建保留开发豁免）。
        // 15 秒节流：verify_self 要读整个二进制，不能每个请求都做。
        if now - self.last_integrity >= RECHECK_INTERVAL_SECS {
            self.last_integrity = now;
            let rep = integrity::verify_self();
            let baseline_untrusted = !crate::core::aim::OPEN_SOURCE && !cfg!(debug_assertions) && rep.baseline;
            self.integrity_ok = !(rep.is_fatal() || baseline_untrusted);
            if !self.integrity_ok {
                log_warn!("aim", "完整性前置检查未通过（{}），拒绝放行", rep.summary());
            }
        }
        if !self.integrity_ok {
            let mut d = AuthDecision::new(
                AuthState::Denied,
                "程序完整性校验未通过：文件被改动或未按发行流程构建，授权不可信".to_string(),
            );
            d.hwid_short = self.info.short_id();
            self.last = d;
            return false;
        }

        // ⓪ 48 位密钥日期：纯比较，每次请求都查（这是最常见的失效形态）
        if let Some(lic) = self.active_key.clone() {
            let today = keyfmt::today_day(now);
            let from_ok = lic.valid_from_day == 0 || today >= lic.valid_from_day;
            let until_ok = lic.perpetual() || today <= lic.valid_until_day;
            if !from_ok || !until_ok {
                let msg = if !until_ok {
                    let (y, m, d) = keyfmt::day_to_ymd(lic.valid_until_day);
                    format!("48 位密钥已过期（有效期至 {:04}-{:02}-{:02}）", y, m, d)
                } else {
                    let (y, m, d) = keyfmt::day_to_ymd(lic.valid_from_day);
                    format!("48 位密钥尚未生效（生效日期 {:04}-{:02}-{:02}）", y, m, d)
                };
                log_warn!("aim", "运行期复核：{}", msg);
                let mut d = AuthDecision::new(AuthState::Denied, msg);
                d.hwid_short = self.info.short_id();
                self.last = d;
                return false;
            }
        }

        // ① 贵重复核：15 秒节流。任一来源仍然有效即放行（与
        //    `offline_decision` 同序，但**全部只读**，不记使用次数）。
        if now - self.last_recheck >= RECHECK_INTERVAL_SECS {
            self.last_recheck = now;
            if !self.any_grant_alive(now) {
                log_warn!("aim", "运行期复核：授权已失效（配额/时效/完整性）");
                let mut d = AuthDecision::new(
                    AuthState::Denied,
                    "授权已在运行期失效：请重新激活或联系管理员".to_string(),
                );
                d.hwid_short = self.info.short_id();
                self.last = d;
                return false;
            }
        }
        true
    }

    /// 只读地判断"当前是否仍有任一有效授权来源"（不写任何文件）。
    ///
    /// 与 `offline_decision` 的区别：那个方法会**记一次使用**（有副作用，
    /// 只能启动/激活时跑）；这个只读，可以按门禁频率调用。
    fn any_grant_alive(&self, now: i64) -> bool {
        let has_material = self.active_key.is_some()
            || self.offline_license.is_some()
            || self.cache.entries.iter().any(|e| e.hwid == self.hwid)
            || self.trial.status().is_granted();
        if has_material {
            // 完整性自校验：二进制被改过 → 授权结论不可信
            if integrity::verify_self().is_fatal() {
                return false;
            }
        }
        // 离线非对称许可（最强离线形态）
        if let Some(lf) = &self.offline_license {
            if asym::issuer_key_configured()
                && lf.validate(&asym::ISSUER_PUBLIC_KEY, &self.hwid, now).0
            {
                return true;
            }
        }
        // 48 位密钥：日期 + 配额（check 内部会 tick 累计使用时长 ——
        // 这正是"使用时间"配额的驱动点，节流保证频率）
        if let Some(lic) = &self.active_key {
            if keyfmt::master_secret_configured() {
                let today = keyfmt::today_day(now);
                let date_ok = (lic.valid_from_day == 0 || today >= lic.valid_from_day)
                    && (lic.perpetual() || today <= lic.valid_until_day);
                if date_ok && matches!(self.usage.check(lic, now), usage::QuotaVerdict::Ok { .. }) {
                    return true;
                }
            }
        }
        // 在线票据（本地缓存，无需网络）
        if self
            .cache
            .find_valid(&self.hwid, LicenseKind::Persistent, now)
            .is_some()
            || self
                .cache
                .find_valid(&self.hwid, LicenseKind::Temporary, now)
                .is_some()
        {
            return true;
        }
        // 试用（本地分散记录）
        self.trial.status().is_granted()
    }

    /// 停用（清除本地缓存）。
    pub fn deactivate(&mut self) -> AuthDecision {        self.cache.remove(&self.hwid, LicenseKind::Persistent);
        self.cache.remove(&self.hwid, LicenseKind::Temporary);
        let _ = self.cache.save(&self.data_dir, &self.hwid);
        let mut d = AuthDecision::new(AuthState::Denied, "已停用本地授权（缓存已清除）");
        d.hwid_short = self.info.short_id();
        self.last = d.clone();
        d
    }

    /// 离线判定：读本地授权物，按「非对称许可文件 → 48 位密钥 →
    /// 持久在线票据 → 临时在线票据」的顺序检查。
    ///
    /// **这是需求的核心落点**：不能联网时，查以前用过的持久性密钥，
    /// 时效期还在就允许使用。
    ///
    /// v1.9.0：签名改为 `&mut self` —— 密钥路径放行时要**记一次使用**
    /// （使用次数配额在本机计量，见 `usage` 模块）。
    fn offline_decision(&mut self) -> AuthDecision {
        let now = ch::now_secs();
        let mut d = AuthDecision::new(AuthState::Denied, "本地无可用授权");
        d.offline = true;
        d.hwid_short = self.info.short_id();

        // ⓪-0 完整性自校验（手段 2）：仅在"存在授权物"时执行
        //      （无授权实例本来就会被拦，不必白白读整个二进制）。
        //      二进制被改过 → 一切授权结论都不可信 → 直接拒绝。
        let has_material = self.active_key.is_some()
            || self.offline_license.is_some()
            || self.cache.entries.iter().any(|e| e.hwid == self.hwid);
        if has_material {
            let ir = integrity::verify_self();
            if ir.is_fatal() {
                log_error!("aim", "授权判定中断：{}", ir.summary());
                d.state = AuthState::Denied;
                d.message = format!("程序完整性校验失败（{}）：拒绝使用", ir.summary());
                return d;
            }
        }

        // ⓪ 最高优先级：离线非对称许可（v1.9.0 手段 1）。
        //    它绑定本机指纹、由发行方私钥签名，客户端只验不签 ——
        //    因此无需联网、无法自行伪造，是本项目最强的离线授权形态。
        //    **放在最前**：离线许可一旦有效即放行，不看在线票据。
        if let Some(lf) = &self.offline_license {
            if asym::issuer_key_configured() {
                let (ok, reason) = lf.validate(&asym::ISSUER_PUBLIC_KEY, &self.hwid, now);
                if ok {
                    d.state = AuthState::Granted;
                    d.kind = if lf.kind == "temporary" {
                        LicenseKind::Temporary
                    } else {
                        LicenseKind::Persistent
                    };
                    d.expire_at = lf.exp;
                    d.days_left = if lf.exp == 0 {
                        -1
                    } else {
                        (lf.exp - now) / 86400
                    };
                    d.message = if lf.exp == 0 {
                        "离线许可有效（无期限）".to_string()
                    } else {
                        format!("离线许可有效（剩余 {} 天）", d.days_left)
                    };
                    return d;
                } else {
                    // 有文件但无效 —— 如实记录，继续走其他路径（不直接拒）
                    log_warn!("aim", "离线许可无效：{}", reason);
                }
            }
        }

        // ⓪-2 次优先级：48 位混合字符密钥（v1.9.0）。
        //     验签 + 指纹绑定已在载入时做过；这里复核时效与配额，
        //     放行时记一次使用（次数配额在本机计量）。
        if let Some(lic) = self.active_key.clone() {
            if !keyfmt::master_secret_configured() {
                log_warn!("aim", "本构建未配置密钥主密钥，48 位密钥无法生效");
            } else {
                let today = keyfmt::today_day(now);
                let date_ok = (lic.valid_from_day == 0 || today >= lic.valid_from_day)
                    && (lic.valid_until_day == keyfmt::DAY_PERPETUAL
                        || today <= lic.valid_until_day);
                if !date_ok {
                    // 密钥已过期/未生效 → 明确拒绝（不静默落到"从未激活"，
                    // 那会让用户以为没激活过而反复输同一枚密钥）
                    d.state = AuthState::Denied;
                    d.message = if lic.valid_until_day != keyfmt::DAY_PERPETUAL
                        && today > lic.valid_until_day
                    {
                        let (y, m, dd) = keyfmt::day_to_ymd(lic.valid_until_day);
                        format!("48 位密钥已过期（有效期至 {:04}-{:02}-{:02}）", y, m, dd)
                    } else {
                        let (y, m, dd) = keyfmt::day_to_ymd(lic.valid_from_day);
                        format!("48 位密钥尚未生效（生效日期 {:04}-{:02}-{:02}）", y, m, dd)
                    };
                    log_warn!("aim", "{}", d.message);
                    return d;
                }
                if let Some(deny) = self.key_quota_denial(&lic, now) {
                    return deny;
                }
                let st = self.usage.record_launch(now);
                d.state = AuthState::Granted;
                d.kind = if lic.kind.is_short_lived() {
                    LicenseKind::Temporary
                } else {
                    LicenseKind::Persistent
                };
                if !lic.perpetual() {
                    d.expire_at = (lic.valid_until_day as i64) * 86400 + 86399;
                    d.days_left =
                        ((lic.valid_until_day as i64) - today as i64).max(0);
                }
                d.message = format!(
                    "48 位密钥有效：{}（第 {} 次使用）",
                    lic.describe(),
                    st.launches
                );
                log_info!("aim", "密钥放行：{}（第 {} 次使用）", lic.kind.label(), st.launches);
                return d;
            }
        }

        // ① 优先看持久性密钥（需求原文：查看以前是否使用过持久性密钥）
        if let Some(c) = self.cache.find_valid(&self.hwid, LicenseKind::Persistent, now) {
            d.state = AuthState::Granted;
            d.kind = LicenseKind::Persistent;
            d.expire_at = c.expire_at;
            d.days_left = (c.expire_at - now) / 86400;
            d.message = format!(
                "离线模式：持久性授权仍在有效期内（剩余 {} 天）",
                d.days_left
            );
            return d;
        }
        // ② 再看临时性密钥
        if let Some(c) = self.cache.find_valid(&self.hwid, LicenseKind::Temporary, now) {
            d.state = AuthState::Granted;
            d.kind = LicenseKind::Temporary;
            d.expire_at = c.expire_at;
            d.days_left = (c.expire_at - now) / 86400;
            let hours = ((c.expire_at - now) % 86400) / 3600;
            d.message = format!(
                "离线模式：临时性授权仍在有效期内（剩余 {} 天 {} 小时）",
                d.days_left, hours
            );
            return d;
        }
        // ③ 有记录但已过期 → 如实告知（不假装可用）
        let expired = self
            .cache
            .entries
            .iter()
            .filter(|e| e.hwid == self.hwid)
            .max_by_key(|e| e.expire_at);
        if let Some(e) = expired {
            d.state = AuthState::OfflineNoCache;
            d.kind = e.kind;
            d.expire_at = e.expire_at;
            d.message = format!(
                "离线模式：本地{}已过期（{}），需联网重新校验",
                e.kind.label(),
                fmt_time(e.expire_at)
            );
            return d;
        }
        // ④ 永久免费模式（v1.9.2）：没有任何授权物也直接放行。
        //
        // 放在最后而不是最前，是为了让已有的密钥/许可/票据优先命中 ——
        // 用户手上有正式授权时，界面就该显示正式授权，而不是"试用版"。
        // 也正因为放在这里，它继承了上面所有完整性前置检查。
        if let trial::TrialState::Active(_) = self.trial.status() {
            if self.trial.is_perpetual() {
                d.state = AuthState::Granted;
                d.kind = LicenseKind::Temporary;
                d.expire_at = 0;
                d.days_left = -1;
                d.message = "免费使用（无到期限制）".into();
                return d;
            }
        }

        d.state = AuthState::OfflineNoCache;
        d.message = "离线模式：本机从未激活过，需联网激活".into();
        d
    }

    /// 处理服务端应答（统一入口）。
    fn apply_server_reply(&mut self, resp: Json, fallback_kind: LicenseKind) -> AuthDecision {
        let now = ch::now_secs();
        let ok = resp.get_bool("ok").unwrap_or(false);
        let granted = resp.get_bool("granted").unwrap_or(ok);
        let mut d = AuthDecision::new(AuthState::Denied, "");
        d.hwid_short = self.info.short_id();

        if !granted {
            // 服务端明确拒绝（密钥错误 / 已吊销 / 机器不匹配）
            let reason = resp
                .get_str("reason")
                .unwrap_or("服务端拒绝了本次授权请求")
                .to_string();
            d.state = AuthState::Denied;
            d.kind = LicenseKind::None;
            d.message = reason;
            // 若服务端说"已吊销"，清掉本地缓存，防止离线继续用
            if resp.get_bool("revoked").unwrap_or(false) {
                self.cache.remove(&self.hwid, LicenseKind::Persistent);
                self.cache.remove(&self.hwid, LicenseKind::Temporary);
                let _ = self.cache.save(&self.data_dir, &self.hwid);
                d.message = format!("{}（本地缓存已清除）", d.message);
            }
            self.last = d.clone();
            return d;
        }

        let kind = {
            let k = LicenseKind::parse(resp.get_str("kind").unwrap_or(fallback_kind.as_str()));
            if k == LicenseKind::None {
                fallback_kind
            } else {
                k
            }
        };
        let expire_at = resp.get_i64("expire_at").unwrap_or(0);
        let ticket = resp.get_str("ticket").unwrap_or("").to_string();

        if ticket.is_empty() {
            d.state = AuthState::Denied;
            d.message = "服务端未返回授权票据（协议异常）".into();
            self.last = d.clone();
            return d;
        }

        // 写入缓存（离线时可复用）
        let entry = CachedLicense {
            kind,
            hwid: self.hwid.clone(),
            ticket,
            expire_at,
            payload: resp.clone(),
            verified_at: now,
        };
        self.cache.upsert(entry);
        if let Err(e) = self.cache.save(&self.data_dir, &self.hwid) {
            log_error!("aim", "授权缓存写入失败：{}（不影响本次使用）", e);
        } else {
            log_info!(
                "aim",
                "授权已更新：{}，到期 {}",
                kind.label(),
                fmt_time(expire_at)
            );
        }

        d.state = AuthState::Granted;
        d.kind = kind;
        d.expire_at = expire_at;
        d.days_left = if expire_at > 0 {
            (expire_at - now) / 86400
        } else {
            -1
        };
        d.message = format!(
            "{}校验通过（{}，到期 {}）",
            kind.label(),
            resp.get_str("server").unwrap_or("授权服务"),
            fmt_time(expire_at)
        );
        self.last = d.clone();
        d
    }

    /// 与服务端完成一次加密往返。
    fn exchange(&self, req: &Json) -> Result<Json, String> {
        // ① 建立会话（随机 nonce + 派生会话密钥）
        let mut session = ch::Session::new(&self.config.psk);
        let mut tx = ch::ChannelSender::from_session(&session);
        let frame = tx.send(&req.to_string());

        // ② 发送
        let reply = post_encrypted(&self.config.host, self.config.port, "/v1/aim", &frame)?;

        // ③ 解析应答：服务端回带自己的 nonce，用它升级会话密钥
        let body_text = reply.body.trim();
        let server_frame = Json::parse(body_text).map_err(|e| format!("应答不是 JSON：{}", e))?;
        let server_nonce = server_frame
            .get_str("sn")
            .ok_or_else(|| "应答缺少服务端随机数".to_string())?
            .to_string();
        session.upgrade_with_server_nonce(&server_nonce);

        let rx = ch::ChannelReceiver::new(session.key.clone());
        let payload = server_frame
            .get_str("d")
            .ok_or_else(|| "应答缺少加密载荷".to_string())?;
        let plain = rx
            .recv(payload)
            .map_err(|e| format!("应答解密失败：{}", e))?;
        log_debug!("aim", "授权往返完成（HTTP {}）", reply.status);
        Json::parse(&plain).map_err(|e| format!("应答载荷不是 JSON：{}", e))
    }
}

/// 功能位图 → 人类可读名（诊断页 / 状态接口用；顺序固定）。
fn feature_names(flags: u16) -> Vec<&'static str> {
    let mut v = Vec::new();
    if flags & keyfmt::FEAT_BASIC != 0 {
        v.push("基础积分");
    }
    if flags & keyfmt::FEAT_EXPORT != 0 {
        v.push("数据导出");
    }
    if flags & keyfmt::FEAT_SMART != 0 {
        v.push("智能解析");
    }
    if flags & keyfmt::FEAT_SCHEDULE != 0 {
        v.push("赛程编排");
    }
    if flags & keyfmt::FEAT_PRINT != 0 {
        v.push("打印证书");
    }
    if flags & keyfmt::FEAT_MULTI != 0 {
        v.push("批量操作");
    }
    v
}

/// 把 Unix 秒格式化为 `YYYY-MM-DD HH:MM`（本地时区近似：UTC+8）。
///
/// 自实现而不引 `chrono`：项目坚持最小依赖，且这里只需展示。
fn fmt_time(secs: i64) -> String {
    if secs <= 0 {
        return "无期限".into();
    }
    // 以 UTC 计算日期（避免引入时区库），仅用于展示
    let days = secs / 86400;
    let rem = secs % 86400;
    let (h, m) = (rem / 3600, (rem % 3600) / 60);
    let (y, mo, d) = civil_from_days(days);
    format!("{:04}-{:02}-{:02} {:02}:{:02} UTC", y, mo, d, h, m)
}

/// 由 Unix 天数换算公历年月日（Howard Hinnant 的 civil_from_days 算法）。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 关掉 v1.9.2 的永久免费模式，恢复"限时演示版"语义。
    ///
    /// 用来测试**"没有授权就应当拒绝"**这类用例 —— 它们的语义前提是
    /// "授权是稀缺的"。永久免费是产品定位选择，不是这些用例要验证的东西，
    /// 所以必须显式关掉，否则测不到原来的路径。
    fn disable_perpetual(mgr: &mut AuthManager) {
        let cur = mgr.trial.policy().clone();
        mgr.trial = trial::TrialManager::new(
            &mgr.hwid,
            &mgr.data_dir,
            trial::TrialPolicy {
                enabled: cur.enabled,
                perpetual: false,
                require_online_confirm: cur.require_online_confirm,
            },
        );
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sm-aim-test-{}-{}-{}",
            tag,
            std::process::id(),
            ch::now_millis()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn load_key_file_rejects_garbage() {
        let dir = tmp_dir("key-garbage");
        std::fs::write(dir.join(KEY_FILE), "这不是一枚密钥\n").unwrap();
        let loaded = AuthManager::load_key_file(&dir, "hwid-x");
        assert!(loaded.is_none(), "垃圾内容不得被当成密钥载入");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn license_kind_roundtrip() {
        for k in [
            LicenseKind::Persistent,
            LicenseKind::Temporary,
            LicenseKind::None,
        ] {
            assert_eq!(LicenseKind::parse(k.as_str()), k);
        }
    }

    #[test]
    fn cache_encrypt_decrypt_roundtrip() {
        const HW: &str = "cache-hwid-0001";
        let plain = br#"{"version":1,"entries":[]}"#;
        let enc = encrypt_cache(HW, plain);
        assert_eq!(&enc[..4], CACHE_MAGIC);
        // 明文不得出现在密文中
        let text = String::from_utf8_lossy(&enc);
        assert!(!text.contains("entries"));
        let dec = decrypt_cache(HW, &enc).expect("应能解密");
        assert_eq!(dec.as_bytes(), plain);
    }

    #[test]
    fn tampered_cache_returns_none() {
        const HW: &str = "cache-hwid-0001";
        let mut enc = encrypt_cache(HW, b"hello");
        let n = enc.len();
        enc[n / 2] ^= 0xff;
        assert!(decrypt_cache(HW, &enc).is_none(), "篡改的缓存必须被拒");
    }

    /// **v1.8.1 修复的漏洞回归测试**。
    ///
    /// 旧版缓存密钥不含机器指纹 → 拿到别的机器的缓存文件后，
    /// 只要知道 PSK 就能解密、改 hwid 字段、重新加密，换机器白嫖。
    ///
    /// 现在 `hwid` 参与密钥派生：换机器**连解密都过不了**。
    #[test]
    fn cache_is_bound_to_machine_fingerprint() {
        const HW_A: &str = "machine-A-0123456789abcdef";
        const HW_B: &str = "machine-B-fedcba9876543210";

        let enc = encrypt_cache(HW_A, br#"{"entries":[{"ticket":"X"}]}"#);
        // 同机器能解开
        assert!(decrypt_cache(HW_A, &enc).is_some(), "同机应能解密");
        // **换机器必须解不开**（而不是"解开但 hwid 不匹配"）
        assert!(
            decrypt_cache(HW_B, &enc).is_none(),
            "缓存必须绑定机器指纹：换机器应连解密都失败"
        );
        // 密钥本身也应不同
        assert_ne!(cache_key(HW_A), cache_key(HW_B));
        assert_eq!(cache_key(HW_A), cache_key(HW_A), "派生必须确定");
    }

    /// v1.9.1 加固回归：**仅凭二进制里能读到的公开字符串**伪造的缓存必须无效。
    ///
    /// 这个用例刻意扮演攻击者：它只用 `--hwid` 打印的指纹、`strings` 能读到的
    /// 盐与旧版 `DEFAULT_PSK`，按旧算法重算缓存密钥并封一份"365 天有效"的
    /// 票据。加固前这样写出来的 `.license` 会被直接接受（ticket 本地不验签）。
    ///
    /// 若将来有人把 `cache_key` 的密钥材料改回公开常量，这条会立刻变红。
    #[test]
    fn forged_cache_from_public_strings_is_rejected() {
        let dir = tmp_dir("forge");
        let hwid = hwid::collect().fingerprint();
        let now = ch::now_secs();
        let body = format!(
            r#"{{"version":{},"saved_at":{},"entries":[{{"kind":"persistent","hwid":"{}","ticket":"FAKE","expire_at":{},"verified_at":{},"payload":{{}}}}]}}"#,
            CACHE_VERSION,
            now,
            hwid,
            now + 86400 * 365,
            now
        );
        // 攻击者视角：公开盐 + 旧版公开 PSK 明文
        let salt = ch::deobfuscate(&CACHE_SALT_MASKED);
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in salt.as_bytes().iter().chain(ch::DEFAULT_PSK.as_bytes()) {
            h ^= *b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        for b in hwid.as_bytes() {
            h ^= *b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        let old_key = format!("{:016x}", h);
        let cipher = ch::seal(&old_key, "cache", 0, body.as_bytes());
        let mut raw = CACHE_MAGIC.to_vec();
        raw.push(CACHE_VERSION);
        raw.extend_from_slice(&cipher);
        std::fs::write(dir.join(CACHE_FILE), &raw).unwrap();

        // 用旧材料封的缓存必须解不开 → 解析出空缓存 → 不授予任何授权
        assert!(
            decrypt_cache(&hwid, &raw).is_none(),
            "公开字符串派生的密钥不应还能解开缓存（否则等于留了离线伪造通道）"
        );
        let cache = LicenseCache::load(&dir, &hwid);
        assert!(
            cache.find_valid(&hwid, LicenseKind::Persistent, now).is_none(),
            "伪造的持久票据不得被判定为有效"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn cache_save_load_roundtrip() {
        let dir = tmp_dir("cache");
        let mut cache = LicenseCache::default();
        cache.upsert(CachedLicense {
            kind: LicenseKind::Persistent,
            hwid: "abc123".into(),
            ticket: "ticket-data".into(),
            expire_at: ch::now_secs() + 86400 * 30,
            payload: Json::obj(),
            verified_at: ch::now_secs(),
        });
        const HW: &str = "cache-hwid-0001";
        cache.save(&dir, HW).expect("保存应成功");

        // 落盘文件里不应出现明文票据
        let raw = std::fs::read(dir.join(CACHE_FILE)).unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert!(!text.contains("ticket-data"), "票据不应明文落盘");

        let loaded = LicenseCache::load(&dir, HW);
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].ticket, "ticket-data");
        assert_eq!(loaded.entries[0].kind, LicenseKind::Persistent);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_cache_loads_empty_without_panic() {
        let dir = tmp_dir("corrupt");
        std::fs::write(dir.join(CACHE_FILE), b"garbage-not-a-cache").unwrap();
        let loaded = LicenseCache::load(&dir, "any-hwid");
        assert!(loaded.entries.is_empty(), "损坏缓存应安全降级为空");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn offline_uses_valid_persistent_key() {
        // 需求核心：离线时持久密钥在有效期内 → 放行
        let dir = tmp_dir("offline-persistent");
        let mut mgr = AuthManager::new(AuthConfig::default(), &dir);
        let now = ch::now_secs();
        mgr.cache = LicenseCache::default();
        mgr.cache.upsert(CachedLicense {
            kind: LicenseKind::Persistent,
            hwid: mgr.hwid.clone(),
            ticket: "tk".into(),
            expire_at: now + 86400 * 100,
            payload: Json::obj(),
            verified_at: now,
        });
        let d = mgr.offline_decision();
        assert_eq!(d.state, AuthState::Granted);
        assert_eq!(d.kind, LicenseKind::Persistent);
        assert!(d.offline);
        assert!(d.days_left > 90);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn offline_rejects_expired_persistent_key() {
        let dir = tmp_dir("offline-expired");
        let mut mgr = AuthManager::new(AuthConfig::default(), &dir);
        mgr.cache = LicenseCache::default();
        mgr.cache.upsert(CachedLicense {
            kind: LicenseKind::Persistent,
            hwid: mgr.hwid.clone(),
            ticket: "tk".into(),
            expire_at: ch::now_secs() - 10,
            payload: Json::obj(),
            verified_at: ch::now_secs() - 100,
        });
        let d = mgr.offline_decision();
        assert_eq!(d.state, AuthState::OfflineNoCache);
        assert!(!d.state.is_granted());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn offline_prefers_persistent_over_temporary() {
        let dir = tmp_dir("offline-priority");
        let mut mgr = AuthManager::new(AuthConfig::default(), &dir);
        let now = ch::now_secs();
        mgr.cache = LicenseCache::default();
        mgr.cache.upsert(CachedLicense {
            kind: LicenseKind::Temporary,
            hwid: mgr.hwid.clone(),
            ticket: "tmp".into(),
            expire_at: now + 3600,
            payload: Json::obj(),
            verified_at: now,
        });
        mgr.cache.upsert(CachedLicense {
            kind: LicenseKind::Persistent,
            hwid: mgr.hwid.clone(),
            ticket: "per".into(),
            expire_at: now + 86400 * 50,
            payload: Json::obj(),
            verified_at: now,
        });
        let d = mgr.offline_decision();
        assert_eq!(d.kind, LicenseKind::Persistent, "持久授权应优先");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn offline_uses_temporary_when_no_persistent() {
        let dir = tmp_dir("offline-temp");
        let mut mgr = AuthManager::new(AuthConfig::default(), &dir);
        mgr.cache = LicenseCache::default();
        mgr.cache.upsert(CachedLicense {
            kind: LicenseKind::Temporary,
            hwid: mgr.hwid.clone(),
            ticket: "tmp".into(),
            expire_at: ch::now_secs() + 7200,
            payload: Json::obj(),
            verified_at: ch::now_secs(),
        });
        let d = mgr.offline_decision();
        assert_eq!(d.state, AuthState::Granted);
        assert_eq!(d.kind, LicenseKind::Temporary);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn offline_ignores_cache_from_other_machine() {
        // 把别人的缓存文件拷过来不应生效（指纹不匹配）
        let dir = tmp_dir("offline-otherhw");
        let mut mgr = AuthManager::new(AuthConfig::default(), &dir);
        disable_perpetual(&mut mgr); // 本用例验"无有效授权即拒绝"
        mgr.cache = LicenseCache::default();
        mgr.cache.upsert(CachedLicense {
            kind: LicenseKind::Persistent,
            hwid: "OTHER-MACHINE-FINGERPRINT".into(),
            ticket: "tk".into(),
            expire_at: ch::now_secs() + 86400 * 100,
            payload: Json::obj(),
            verified_at: ch::now_secs(),
        });
        let d = mgr.offline_decision();
        assert_eq!(d.state, AuthState::OfflineNoCache, "异机缓存必须无效");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn not_configured_when_disabled() {
        // v1.9.0 起语义变更：未配置服务端时 decide() 不再直接返回
        // NotConfigured，而是走离线判定（48 位密钥 / 许可文件都是纯离线
        // 路径，与服务端无关）。无任何本地授权物 → Denied。
        let dir = tmp_dir("notcfg");
        let mut mgr = AuthManager::new(AuthConfig::default(), &dir);
        disable_perpetual(&mut mgr); // 本用例验"无任何授权物即拒绝"
        let d = mgr.decide();
        assert!(!d.state.is_granted());
        assert!(d.offline, "离线判定应标记 offline");
        std::fs::remove_dir_all(&dir).ok();
    }

    // ---- v1.9.0：48 位激活密钥 ----

    fn fake_key_lic(until_day: u32) -> keyfmt::KeyLicense {
        keyfmt::KeyLicense {
            kind: keyfmt::KeyKind::Pro,
            valid_from_day: 0,
            valid_until_day: until_day,
            usage_seconds_limit: 0,
            usage_count_limit: 0,
            feature_flags: keyfmt::FEAT_ALL,
            key_id: 7,
        }
    }

    #[test]
    fn activate_key_empty_rejected() {
        let dir = tmp_dir("key-empty");
        let mut mgr = AuthManager::new(AuthConfig::default(), &dir);
        let d = mgr.activate_key("   ");
        assert_eq!(d.state, AuthState::Denied);
        assert!(d.message.contains("密钥不能为空"), "{}", d.message);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn activate_key_without_master_secret_denied() {
        // 开发构建没有 keys/aim.secret → 激活必须被明确拒绝
        // （而不是"看起来成功"）。发行构建由 build.sh 保证注入。
        if keyfmt::master_secret_configured() {
            return; // 构建机上有主密钥时跳过本用例
        }
        let dir = tmp_dir("key-nosecret");
        let mut mgr = AuthManager::new(AuthConfig::default(), &dir);
        // 用测试密钥签发的真密钥（格式合法）
        let text = keyfmt::issue_key(
            &[0x11; 32],
            &mgr.hwid,
            &keyfmt::KeyParams {
                kind: keyfmt::KeyKind::Pro,
                valid_from_day: 0,
                valid_until_day: keyfmt::DAY_PERPETUAL,
                usage_seconds_limit: 0,
                usage_count_limit: 0,
                feature_flags: keyfmt::FEAT_ALL,
                key_id: 1,
            },
        );
        let d = mgr.activate_key(&text);
        assert_eq!(d.state, AuthState::Denied);
        assert!(d.message.contains("主密钥"), "{}", d.message);
        // 拒绝后不得落盘密钥文件
        assert!(!dir.join(KEY_FILE).exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn recheck_gate_denies_when_not_granted() {
        let dir = tmp_dir("gate-deny");
        let mut mgr = AuthManager::new(AuthConfig::default(), &dir);
        mgr.last = AuthDecision::new(AuthState::Denied, "未授权");
        assert!(!mgr.recheck_gate());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn recheck_gate_catches_runtime_expiry() {
        // 启动时放行、运行期间密钥过期 → 门禁必须现在拒绝
        let dir = tmp_dir("gate-expire");
        let mut mgr = AuthManager::new(AuthConfig::default(), &dir);
        let yesterday = keyfmt::today_day(ch::now_secs()).saturating_sub(1);
        mgr.active_key = Some(fake_key_lic(yesterday));
        mgr.last = AuthDecision::new(AuthState::Granted, "测试放行");
        assert!(!mgr.recheck_gate(), "过期密钥必须在门禁被拦下");
        assert!(!mgr.last.state.is_granted());
        assert!(mgr.last.message.contains("已过期"), "{}", mgr.last.message);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn recheck_gate_passes_with_valid_dates() {
        // 日期有效时，免费检查必须放行（贵重复核 15 秒内不会跑）
        let dir = tmp_dir("gate-ok");
        let mut mgr = AuthManager::new(AuthConfig::default(), &dir);
        let tomorrow = keyfmt::today_day(ch::now_secs()) + 1;
        mgr.active_key = Some(fake_key_lic(tomorrow));
        mgr.last = AuthDecision::new(AuthState::Granted, "测试放行");
        mgr.last_recheck = ch::now_secs(); // 假装刚复核过 → 跳过贵查询
        assert!(mgr.recheck_gate());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn deactivate_key_removes_file() {
        let dir = tmp_dir("key-deact");
        let mut mgr = AuthManager::new(AuthConfig::default(), &dir);
        std::fs::write(dir.join(KEY_FILE), "whatever\n").unwrap();
        let d = mgr.deactivate_key();
        assert_eq!(d.state, AuthState::Denied);
        assert!(!dir.join(KEY_FILE).exists(), "停用应删除密钥文件");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn key_fields_reports_quota_and_features() {
        let dir = tmp_dir("key-fields");
        let mut mgr = AuthManager::new(AuthConfig::default(), &dir);
        assert!(mgr.key_fields().is_none(), "未激活时无密钥字段");
        mgr.active_key = Some(keyfmt::KeyLicense {
            kind: keyfmt::KeyKind::Standard,
            valid_from_day: 0,
            valid_until_day: keyfmt::DAY_PERPETUAL,
            usage_seconds_limit: 3600,
            usage_count_limit: 10,
            feature_flags: keyfmt::FEAT_BASIC | keyfmt::FEAT_EXPORT,
            key_id: 99,
        });
        let f = mgr.key_fields().expect("已激活应有字段");
        let s = f.to_string();
        assert!(s.contains("标准版"), "{}", s);
        assert!(s.contains("导出"), "{}", s);
        assert!(s.contains("\"launches_limit\":10"), "{}", s);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn activate_without_server_falls_back_to_offline() {
        // 指向一个必然连不上的地址 → 应降级而非 panic
        let dir = tmp_dir("noserver");
        let cfg = AuthConfig {
            host: "127.0.0.1".into(),
            port: 1, // 保留端口，必拒
            // v1.9.1：默认 PSK 会被 AuthManager 判为"未配置"而停用通道，
            // 这里必须给一个非默认值才能真正走到网络失败路径。
            psk: "test-only-psk".into(),
            enabled: true,
        };
        let mut mgr = AuthManager::new(cfg, &dir);
        disable_perpetual(&mut mgr); // 激活失败应降级为"未授权"，不是"永久免费"
        let d = mgr.activate_persistent("SOME-KEY", "test");
        // 无缓存 → 离线判定为"无可用授权"，但**不 panic**
        assert!(!d.state.is_granted());
        assert!(d.offline);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn corrupt_ticket_clears_cache_is_deterministic() {
        let dir = tmp_dir("revoke");
        let mut mgr = AuthManager::new(AuthConfig::default(), &dir);
        mgr.cache.upsert(CachedLicense {
            kind: LicenseKind::Persistent,
            hwid: mgr.hwid.clone(),
            ticket: "tk".into(),
            expire_at: ch::now_secs() + 9999,
            payload: Json::obj(),
            verified_at: ch::now_secs(),
        });
        // 模拟服务端说 revoked
        let mut resp = Json::obj();
        resp.set("ok", Json::Bool(true));
        resp.set("granted", Json::Bool(false));
        resp.set("revoked", Json::Bool(true));
        resp.set("reason", Json::s("该密钥已被吊销"));
        let d = mgr.apply_server_reply(resp, LicenseKind::Persistent);
        assert_eq!(d.state, AuthState::Denied);
        assert!(mgr.cache.entries.iter().all(|e| e.hwid != mgr.hwid));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn granted_reply_writes_cache() {
        let dir = tmp_dir("granted");
        let mut mgr = AuthManager::new(AuthConfig::default(), &dir);
        let exp = ch::now_secs() + 86400 * 365;
        let mut resp = Json::obj();
        resp.set("ok", Json::Bool(true));
        resp.set("granted", Json::Bool(true));
        resp.set("kind", Json::s("persistent"));
        resp.set("ticket", Json::s("server-signed-ticket"));
        resp.set("expire_at", Json::Int(exp));
        resp.set("server", Json::s("test-server"));
        let d = mgr.apply_server_reply(resp, LicenseKind::Persistent);
        assert_eq!(d.state, AuthState::Granted);
        assert_eq!(d.kind, LicenseKind::Persistent);
        assert!(d.days_left >= 364);
        // 缓存已落盘且可被离线复用
        let reloaded = LicenseCache::load(&dir, mgr.hwid());
        assert_eq!(reloaded.entries.len(), 1);
        assert_eq!(reloaded.entries[0].ticket, "server-signed-ticket");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn empty_key_is_denied_without_network() {
        let dir = tmp_dir("emptykey");
        let cfg = AuthConfig {
            host: "127.0.0.1".into(),
            port: 1,
            psk: "test-only-psk".into(),
            enabled: true,
        };
        let mut mgr = AuthManager::new(cfg, &dir);
        let d = mgr.activate_persistent("   ", "x");
        assert_eq!(d.state, AuthState::Denied);
        assert!(!d.offline, "空密钥应在本地直接拒绝，不走网络");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn civil_from_days_matches_known_dates() {
        // 1970-01-01
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2000-01-01 = 10957 天
        assert_eq!(civil_from_days(10957), (2000, 1, 1));
        // 2026-01-01 = 20454 天
        assert_eq!(civil_from_days(20454), (2026, 1, 1));
    }

    #[test]
    fn auth_config_from_json() {
        let mut j = Json::obj();
        j.set("host", Json::s("10.0.0.5"));
        j.set("port", Json::Int(9000));
        j.set("psk", Json::s("my-psk"));
        j.set("enabled", Json::Bool(true));
        let c = AuthConfig::from_json(&j);
        assert_eq!(c.host, "10.0.0.5");
        assert_eq!(c.port, 9000);
        assert_eq!(c.psk, "my-psk");
        assert!(c.enabled);

        // 无 host → 即使 enabled=true 也不启用（避免空地址反复重试）
        let mut j2 = Json::obj();
        j2.set("enabled", Json::Bool(true));
        assert!(!AuthConfig::from_json(&j2).enabled);
    }
    // ───────────────────────────────────────────────────────────────
    // 离线非对称许可（v1.9.0 手段 1）端到端测试
    // ───────────────────────────────────────────────────────────────
    //
    // 测试用的密钥对由 `tools/issue_license.py keygen` 生成，
    // 是**公开的测试密钥**（非生产密钥），仅用于验证验签链路。

    /// 测试用签发公钥（hex）。
    const TEST_ISSUER_PK_HEX: &str =
        "10428f6aba20f74eb992c7c892d774b729b8f0b1e0d61dff72a621d93a676a86";

    fn test_pk() -> [u8; 32] {
        let v = hex_bytes(TEST_ISSUER_PK_HEX);
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        a
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// 有效许可应通过验签。
    #[test]
    fn offline_license_valid() {
        // 由测试私钥签出：hwid=test-hwid-aa, exp=4102444800(2100年), kind=persistent
        let sig_b64 = "lrAaV8UcZWHALB1d/jCWuBe3/Wva8yIjgoChbwAoUgsVYFqDw32YyzHbcE69ciqYyAcYx5hUxvvRG5eQVmwQCg==";
        let lic = format!(
            r#"{{"v":1,"hwid":"test-hwid-aa","exp":4102444800,"kind":"persistent","mask":0,"sig":"{}"}}"#,
            sig_b64
        );
        let lf = asym::LicenseFile::parse(&lic).expect("应能解析");
        let (ok, reason) = lf.validate(&test_pk(), "test-hwid-aa", 1_700_000_000);
        assert!(ok, "有效许可应通过：{}", reason);
    }

    /// 换一台机器（hwid 不同）→ 必须失败（绑定指纹）。
    #[test]
    fn offline_license_hwid_mismatch() {
        let sig_b64 = "lrAaV8UcZWHALB1d/jCWuBe3/Wva8yIjgoChbwAoUgsVYFqDw32YyzHbcE69ciqYyAcYx5hUxvvRG5eQVmwQCg==";
        let lic = format!(
            r#"{{"v":1,"hwid":"test-hwid-aa","exp":4102444800,"kind":"persistent","mask":0,"sig":"{}"}}"#,
            sig_b64
        );
        let lf = asym::LicenseFile::parse(&lic).unwrap();
        let (ok, reason) = lf.validate(&test_pk(), "other-machine", 1_700_000_000);
        assert!(!ok, "换机必须失败");
        assert!(reason.contains("指纹"), "失败原因应提示指纹不匹配：{}", reason);
    }

    /// 篡改 hwid 后签名失配 → 必须失败。
    #[test]
    fn offline_license_tampered_hwid_rejected() {
        let sig_b64 = "lrAaV8UcZWHALB1d/jCWuBe3/Wva8yIjgoChbwAoUgsVYFqDw32YyzHbcE69ciqYyAcYx5hUxvvRG5eQVmwQCg==";
        // 把 hwid 改成 bb（签名是对 aa 签的）
        let lic = format!(
            r#"{{"v":1,"hwid":"test-hwid-bb","exp":4102444800,"kind":"persistent","mask":0,"sig":"{}"}}"#,
            sig_b64
        );
        let lf = asym::LicenseFile::parse(&lic).unwrap();
        // 用 bb 作为本机指纹（绕过指纹检查，直接考验签名）
        let (ok, _) = lf.validate(&test_pk(), "test-hwid-bb", 1_700_000_000);
        assert!(!ok, "篡改 hwid 后签名必须失配");
    }

    /// 用错误公钥验签 → 必须失败（防伪）。
    #[test]
    fn offline_license_wrong_key_rejected() {
        let sig_b64 = "lrAaV8UcZWHALB1d/jCWuBe3/Wva8yIjgoChbwAoUgsVYFqDw32YyzHbcE69ciqYyAcYx5hUxvvRG5eQVmwQCg==";
        let lic = format!(
            r#"{{"v":1,"hwid":"test-hwid-aa","exp":4102444800,"kind":"persistent","mask":0,"sig":"{}"}}"#,
            sig_b64
        );
        let lf = asym::LicenseFile::parse(&lic).unwrap();
        let mut wrong = test_pk();
        wrong[0] ^= 0xff;
        let (ok, _) = lf.validate(&wrong, "test-hwid-aa", 1_700_000_000);
        assert!(!ok, "错误公钥必须验签失败");
    }

    /// 过期许可 → 失败。
    #[test]
    fn offline_license_expired_rejected() {
        // 此许可 exp=4102444800；用"未来"的 now 让它过期
        let sig_b64 = "lrAaV8UcZWHALB1d/jCWuBe3/Wva8yIjgoChbwAoUgsVYFqDw32YyzHbcE69ciqYyAcYx5hUxvvRG5eQVmwQCg==";
        let lic = format!(
            r#"{{"v":1,"hwid":"test-hwid-aa","exp":4102444800,"kind":"persistent","mask":0,"sig":"{}"}}"#,
            sig_b64
        );
        let lf = asym::LicenseFile::parse(&lic).unwrap();
        let (ok, reason) = lf.validate(&test_pk(), "test-hwid-aa", 4_102_444_801);
        assert!(!ok, "过期必须失败");
        assert!(reason.contains("过期"), "原因应提示过期：{}", reason);
    }

    /// 永久许可（exp=0）→ 任何时刻都有效。
    #[test]
    fn offline_license_perpetual() {
        let sig_b64 = "HIzFhFCrpw/2S/O2Jgsz2n3zxy66Pcg3T9OC+oSrdEf+vXrXH/QQEP2NAjsXbyjbGbJUxGg4VLIuZMO7XG6VBQ==";
        let lic = format!(
            r#"{{"v":1,"hwid":"test-hwid-bb","exp":0,"kind":"persistent","mask":0,"sig":"{}"}}"#,
            sig_b64
        );
        let lf = asym::LicenseFile::parse(&lic).unwrap();
        let (ok, reason) = lf.validate(&test_pk(), "test-hwid-bb", 9_999_999_999);
        assert!(ok, "永久许可应始终有效：{}", reason);
    }

    /// 放入 data/license.lic 后，AuthManager 能识别（离线放行路径）。
    #[test]
    fn offline_license_loaded_from_disk() {
        let dir = tmp_dir("offline-lic");
        // 用测试公钥对应的私钥签的许可写盘（hwid 需与真实机器匹配才能放行，
        // 这里只验证"能载入"，不验证放行）
        let sig_b64 = "lrAaV8UcZWHALB1d/jCWuBe3/Wva8yIjgoChbwAoUgsVYFqDw32YyzHbcE69ciqYyAcYx5hUxvvRG5eQVmwQCg==";
        let lic = format!(
            r#"{{"v":1,"hwid":"test-hwid-aa","exp":4102444800,"kind":"persistent","mask":0,"sig":"{}"}}"#,
            sig_b64
        );
        std::fs::write(dir.join("license.lic"), lic).unwrap();
        let loaded = AuthManager::load_offline_license(&dir);
        assert!(loaded.is_some(), "应能从 data/license.lic 载入");
        let lf = loaded.unwrap();
        assert_eq!(lf.hwid, "test-hwid-aa");
        assert_eq!(lf.exp, 4102444800);
        // 文件不存在时返回 None
        let empty = tmp_dir("offline-lic-empty");
        assert!(AuthManager::load_offline_license(&empty).is_none());
    }

}
