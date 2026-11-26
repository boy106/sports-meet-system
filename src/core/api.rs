//! 核心 API（核心模块）：领域逻辑 + HTTP 路由注册。
//!
//! 「一个核心、多个扩展」中的核心层——扩展通过 `CoreContext`（即 Core）
//! 调用这里的全部公开方法，实现自己的业务联动。

use crate::core::ext::{CoreEvent, EventKind, Extension};
use crate::core::http::{Request, Response};
use crate::core::json::Json;
// 日志宏由 core::log 以 #[macro_export] 导出到 crate 根，故显式引入使用。
use crate::core::model::{Event, Registration, Result as DomainResult, Settings, Student};
use crate::core::scoring;
use crate::core::sync::LockExt;
use crate::core::store::{
    self, event_from_json, event_to_json, export_all_json, reg_to_json,
    result_to_json, student_from_json, student_to_json, Data, Store, UndoEntry,
};
use crate::{log_debug, log_error, log_info, log_warn};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

// v1.4：统一错误类型已抽取到 core/error.rs（文档 02/09 曾声称存在该文件，
// 现在名副其实）。此处 re-export 保持既有 `crate::core::api::ApiErr` 引用路径兼容。
pub use crate::core::error::ApiErr;
// v1.6.0：错误码用 `crate::core::error::ErrCode` 全路径引用，不额外 use ——
// 本文件对它的直接引用很少，全路径更能表明"这是跨模块的错误码契约"。

/// 撤销栈硬上限（v1.2）：防止异常情况下内存无限增长。
/// 实际保留条数由 `Core::undo_keep` 控制，此值仅作兜底。
const MAX_UNDO_STACK: usize = 64;

/// 签名令牌默认有效期（v1.5）：12 小时。
///
/// 运动会通常是"早上八点开到下午五点"，12 小时足以覆盖一整天而不必
/// 中途重输口令；又足够短，即使令牌泄露也不至于长期有效。
const TOKEN_TTL_SECS: i64 = 12 * 3600;

pub struct Core {
    pub store: Store,
    pub web_dir: PathBuf,
    pub extensions: Mutex<Vec<Arc<dyn Extension>>>,
    /// 撤销栈保留步数（v1.2：默认 10，v1.1 为 1）。
    pub undo_keep: usize,
    pub backup_keep: usize,
    /// 管理员口令（v1.4）：`--password` 或配置文件设置。为 Some 时，
    /// 写操作（POST/DELETE）必须携带有效凭证；读操作保持开放。
    /// None 时行为与 v1.3 完全一致（免鉴权）。
    pub password: Option<String>,
    /// 令牌签名密钥（v1.5）：**进程启动时随机生成，不落盘**。
    ///
    /// 收益：重启后旧令牌自动全部失效（无需维护吊销列表），
    /// 且即使审计文件泄露也推不出密钥。
    pub token_secret: String,
    /// 扩展健康状态（v1.2）：扩展名 -> 统计。
    pub ext_health: Mutex<std::collections::HashMap<String, ExtHealth>>,
    /// 密钥与开发者模式（v1.5.1）。
    ///
    /// 用 `Option<Box<...>>` 而非直接内嵌，原因有二：
    /// * `license` 是「安全横切关注点」，不属于任何单个业务模块，
    ///   但 `Core` 是所有路由的公共上下文，放这里最自然；
    /// * 装箱后 `Core` 的体积不受 `License` 影响，且单元测试可以
    ///   构造"无密钥"的 `Core`，无需伪造密钥。
    pub license: Option<Box<crate::core::license::License>>,
    /// v1.8.0：服务端授权管理器（机器指纹 + 加密信道 + 离线降级）。
    ///
    /// **与 `license` 的分工**：`license` 管"开发者模式"（调试便利），
    /// 本字段管"正式授权准入"（防白嫖）。两者互不影响。
    ///
    /// 用 `Mutex` 而非直接内嵌：授权管理器需要 `&mut` 才能刷新缓存与
    /// 状态，而 `Core` 被 `Arc` 共享（handler 只拿得到 `&Core`）。
    /// 用 `Option` 包裹使单元测试可构造"未启用授权"的 Core，
    /// 语义与 `license` 字段保持一致。
    pub aim: Option<Mutex<crate::core::aim::AuthManager>>,
    /// v1.8.0：无有效授权时是否拒绝启动（"启动门禁"）。
    ///
    /// `true`（默认）：授权校验不通过 → 不做任何业务，只提供授权接口；
    /// `false`（宽容）：仅提示，不拦截（便于现场排障与内部试用）。
    pub aim_enforce: bool,
    /// 数据文件是否加密落盘（v1.5.1，`--encrypt-data`）。
    ///
    /// 默认 `false`：v1.5 的数据目录是明文 JSON，直接打开就能改。
    /// 打开后 `store` 层落盘走 `vault::write_auto`，并清理同名明文，
    /// 避免"以为加密了、明文还躺在旁边"的假安全感。
    pub encrypt_data: bool,
    /// v1.6.0：接口可观测统计。
    ///
    /// 由 `http` 层在分发后写入（请求数/耗时/限流拒绝数），
    /// 由 `api` 层的 `/api/dev/status` 读出展示给诊断页。
    ///
    /// 为什么放在 `Core` 而不是 `Router`：诊断接口是**核心路由**，
    /// handler 只拿得到 `&Core`，拿不到 `Router`。放在 Core 上，
    /// 依赖方向保持 `http → api` 单向，不需要把 Router 引进来。
    pub http_stats: Mutex<HttpStats>,
}

/// 接口运行统计（v1.6.0）。
///
/// 设计原则：**只记聚合量，不记明细**。
/// 存"每个路径的平均耗时"会带来无界内存增长（路径可含 id），
/// 而诊断页真正需要的是"整体健康度"——总次数、失败率、限流次数、
/// 最慢的一次。**不记录任何请求内容**，避免把业务数据写进统计里。
#[derive(Debug, Default)]
pub struct HttpStats {
    /// 已处理请求总数（含被限流的）
    pub total: u64,
    /// 2xx/3xx 计数
    pub ok_count: u64,
    /// 4xx 计数（客户端错）
    pub client_err: u64,
    /// 5xx 计数（服务端错）
    pub server_err: u64,
    /// 被限流拒绝的次数
    pub limited: u64,
    /// 累计耗时（毫秒，用于算平均）
    pub total_ms: f64,
    /// 最慢一次耗时（毫秒）与其路径
    pub slowest_ms: f64,
    pub slowest_path: String,
    /// v1.6.0：限流器快照（由 http 层每请求同步一次）
    /// 限流放行次数
    pub rate_allowed: u64,
    /// 限流拒绝次数
    pub rate_rejected: u64,
    /// 当前活跃来源数（不同 IP / loopback 聚合）
    pub rate_sources: usize,
}

impl HttpStats {
    /// 记录一次请求。`status` 为最终 HTTP 状态码。
    pub fn record(&mut self, path: &str, status: u16, cost_ms: f64) {
        self.total += 1;
        self.total_ms += cost_ms;
        if status >= 500 {
            self.server_err += 1;
        } else if status >= 400 {
            self.client_err += 1;
        } else {
            self.ok_count += 1;
        }
        if status == 429 {
            self.limited += 1;
        }
        if cost_ms > self.slowest_ms {
            self.slowest_ms = cost_ms;
            self.slowest_path = path.to_string();
        }
    }

    /// 平均耗时（毫秒）；无请求时为 0。
    pub fn avg_ms(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.total_ms / self.total as f64
        }
    }

    /// 失败率（4xx+5xx 占比），0.0 ~ 1.0。
    pub fn error_rate(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.client_err + self.server_err) as f64 / self.total as f64
        }
    }
}

/// 扩展运行时健康统计（v1.2 新增）。
#[derive(Debug, Clone, Default)]
pub struct ExtHealth {
    /// 是否初始化成功
    pub initialized: bool,
    /// 初始化失败原因
    pub init_error: Option<String>,
    /// 注册的路由条数
    pub route_count: usize,
    /// 累计接收事件数
    pub event_count: u64,
    /// 累计事件处理异常数（panic 捕获）
    pub event_errors: u64,
    /// 最近一次事件时间
    pub last_event_time: Option<String>,
}

impl Core {
    pub fn new(data_dir: &std::path::Path, web_dir: &std::path::Path) -> Core {
        // v1.5.1：无密钥的默认路径 —— 按明文载入。
        // 这样所有既有单测（构造 Core 后立刻读写数据）语义不变。
        // 需要加密的场景由 `activate_vault` 重新载入（见其文档）。
        let mut store = Store::load(data_dir);
        // 先探测磁盘上是否存在密文，供 `load_from_disk` 选对日志级别：
        // "只有个密文躺着、没带密钥"属于预期情形（INFO），
        // 不该用 ERROR 吓人；真正的密钥错误才该报 ERROR。
        let plain = data_dir.join(crate::core::store::DATA_FILE_NAME);
        store.vault_detected = crate::core::vault::enc_path(&plain).exists() && !plain.exists();
        store.load_from_disk(data_dir);
        Core {
            store,
            web_dir: web_dir.to_path_buf(),
            extensions: Mutex::new(Vec::new()),
            undo_keep: 10,
            backup_keep: 10,
            password: None,
            token_secret: random_secret(),
            ext_health: Mutex::new(std::collections::HashMap::new()),
            license: None,
            aim: None,
            aim_enforce: false, // 开源版：默认不强制授权门禁
            encrypt_data: false,
            http_stats: Mutex::new(HttpStats::default()),
        }
    }

    /// v1.5.1：装配密钥并完成数据载入（**加密场景专用**）。
    ///
    /// `Core::new` 已按明文载入一次；若本实例要加密，则在此**重新载入**：
    /// 先用密钥武装 Store，再读盘（这时读的可能是 `.smev` 密文）。
    ///
    /// 顺序不可颠倒 —— 先武装再读盘。反过来会因"还没密钥就去解密"
    /// 而读成空库，且**不会有任何报错**，是典型的静默数据丢失。
    ///
    /// 未启用加密时本方法只做一次幂等检查，不重复读盘。
    pub fn activate_vault(&mut self, data_dir: &std::path::Path) {
        // 自动探测：数据目录里若存在密文而当前未武装保险库，则按"需要解密"处理。
        // 这样用户**无需重复记着带 --encrypt-data**（忘记它 = 数据看起来凭空消失）。
        let plain = data_dir.join(crate::core::store::DATA_FILE_NAME);
        let enc = crate::core::vault::enc_path(&plain);
        if !self.encrypt_data {
            // 只有当"密文在、明文不在"时才自动接管；否则维持原状，
            // 避免把用户手动放回的旧明文文件也误当成密文处理。
            if enc.exists() && !plain.exists() {
                self.encrypt_data = true;
                self.store.vault_detected = true;
                log_info!("api", "检测到密文数据文件，自动进入加密读取模式");
            } else {
                return;
            }
        }
        let seed = self
            .license
            .as_ref()
            .and_then(|l| l.stream_seed())
            .map(|s| s.to_string());
        if !self.store.enable_vault(true, seed) {
            // 无密钥 → Store 拒绝启用，保持明文，如实回写状态
            self.encrypt_data = false;
            return;
        }
        self.store.load_from_disk(data_dir);
        log_info!("api", "数据保险库已启用：落盘为 .smev 密文");
    }

    // ------------------------------------------------------------------
    // 鉴权与审计（v1.5）
    // ------------------------------------------------------------------

    /// 签发一个签名令牌。无口令时返回 Err（调用方应先检查）。
    ///
    /// 令牌结构（三段，`.` 分隔，无 base64 依赖，便于 curl 手工调试）：
    ///
    /// ```text
    ///   <expire_unix>.<nonce>.<sig>
    ///   sig = H(secret ‖ expire ‖ nonce)
    /// ```
    ///
    /// * `expire_unix` —— 到期时间戳（秒），校验时先看它；
    /// * `nonce`       —— 随机串，使同一秒内多次签发也不重样，
    ///   避免"相同令牌可预测"；
    /// * `sig`         —— 用进程内随机密钥签名，客户端无法伪造。
    ///
    /// # 与"直接传口令"的差别（为什么值得多这一步）
    ///
    /// v1.4 的做法是前端把口令存进 localStorage，每次请求都明文回传。
    /// 局域网里任何能抓包的人（同 WiFi 的笔记本、教室的交换机镜像口）
    /// 都能直接拿到口令，之后永远通行。改成令牌后：抓包者拿到的是
    /// **12 小时后自动失效**的凭证，且不含口令本身，危害面显著收窄。
    ///
    /// # 诚实的局限（不隐瞒）
    ///
    /// 本方案仍基于 FNV-1a 而非标准 HMAC-SHA256，**不是密码学意义上的
    /// 安全 MAC**。它挡的是"抓包重放"和"随手改 URL 冒充管理员"，
    /// 挡不了有密码学能力、能本地离线跑碰撞的对手。若部署环境升级为
    /// 公网或跨网段，应替换为 `hmac` + `sha2`（见 docs/03 与 docs/07）。
    pub fn issue_token(&self, seconds: Option<i64>) -> Result<Json, ApiErr> {
        if self.password.is_none() {
            return Err(ApiErr::with_status(
                "当前未启用管理口令，无需令牌。可通过 --password 或配置文件开启",
                400,
            ));
        }
        let ttl = seconds.unwrap_or(TOKEN_TTL_SECS).clamp(60, 7 * 24 * 3600);
        let expire = unix_now() + ttl;
        let nonce = random_secret();
        let nonce = &nonce[..16.min(nonce.len())];
        let sig = token_sig(&self.token_secret, expire, nonce);
        let token = format!("{}.{}.{}", expire, nonce, sig);
        let mut o = Json::obj();
        o.set("ok", Json::Bool(true));
        o.set("token", Json::s(token));
        o.set("ttl", Json::Int(ttl));
        o.set("expires_at", Json::s(unix_to_string(expire)));
        o.set(
            "notice",
            Json::s("请将令牌放入 Authorization: Bearer <token>；服务重启后需重新获取"),
        );
        Ok(o)
    }

    /// 校验一个 Bearer 凭证：先试令牌，再回退比较原始口令。
    ///
    /// 回退分支保证 v1.4 的脚本/客户端**无感升级**（向后兼容）。
    pub fn is_authorized(&self, given: &str) -> bool {
        let expect = match &self.password {
            Some(p) => p,
            None => return true, // 未设口令：一律放行
        };
        if given.is_empty() {
            return false;
        }
        if crate::core::http::Router::const_time_eq(given, expect) {
            return true;
        }
        self.verify_token(given).is_some()
    }

    /// 校验令牌，返回到期时间戳（秒）。失败返回 None。
    pub fn verify_token(&self, token: &str) -> Option<i64> {
        let mut parts = token.split('.');
        let expire_s = parts.next()?;
        let nonce = parts.next()?;
        let sig = parts.next()?;
        if parts.next().is_some() {
            return None; // 多段 → 非法
        }
        let expire: i64 = expire_s.parse().ok()?;
        if expire <= unix_now() {
            return None; // 已过期
        }
        let expect = token_sig(&self.token_secret, expire, nonce);
        if !crate::core::http::Router::const_time_eq(sig, &expect) {
            return None;
        }
        Some(expire)
    }

    /// 审计链校验报告（v1.5）。
    pub fn audit_verify_json(&self) -> Json {
        crate::core::audit::verify().to_json()
    }

    /// 审计面板数据：最近记录 + 链头 + 目录（v1.5）。
    pub fn audit_panel_json(&self, limit: usize) -> Json {
        let mut j = crate::core::audit::recent(limit);
        j.set(
            "dir",
            Json::s(
                crate::core::audit::dir_path()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "（审计未初始化）".into()),
            ),
        );
        // 顺手附上总条数与一致性结论，前端一次请求即可画出完整面板
        j.set("verify", crate::core::audit::verify().to_json());
        j.set(
            "genesis",
            Json::s(crate::core::audit::GENESIS.to_string()),
        );
        j
    }

    // ------------------------------------------------------------------
    // 扩展管理
    // ------------------------------------------------------------------

    pub fn register_extension(self: &Arc<Self>, ext: Arc<dyn Extension>) {
        let name = ext.name().to_string();

        // --- v1.2 校验 1：扩展名合法性 ---
        if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            log_error!("ext", "扩展注册被拒绝：名称非法「{}」（仅允许字母/数字/下划线/连字符）", name);
            return;
        }

        // --- v1.2 校验 2：扩展名唯一性 ---
        {
            let hs = match self.ext_health.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            if hs.contains_key(&name) {
                log_error!("ext", "扩展注册被拒绝：名称「{}」已被占用", name);
                return;
            }
        }

        // --- v1.2 校验 3：路由前缀必须为 /api/ext/<name>/ ---
        let expected_prefix = format!("/api/ext/{}/", name);
        let routes = ext.routes();
        for r in &routes {
            let ok_prefix = r.path.starts_with(&expected_prefix)
                || r.path == format!("/api/ext/{}", name);
            if !ok_prefix {
                log_error!(
                    "ext",
                    "扩展「{}」路由被拒绝：{} {} 未使用规定前缀 {}",
                    name,
                    r.method,
                    r.path,
                    expected_prefix
                );
                return;
            }
        }

        let route_count = routes.len();

        // 初始化健康记录
        {
            let mut hs = match self.ext_health.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            hs.insert(
                name.clone(),
                ExtHealth {
                    initialized: false,
                    init_error: None,
                    route_count,
                    event_count: 0,
                    event_errors: 0,
                    last_event_time: None,
                },
            );
        }

        if let Ok(mut exts) = self.extensions.lock() {
            exts.push(ext);
        }
        log_info!("ext", "扩展已注册：{}（{} 条路由）", name, route_count);
    }

    /// 启动扩展（on_init）。失败仅记录到健康状态与控制台，不阻断核心。
    pub fn init_extensions(self: &Arc<Self>) {
        let exts = self.extensions.lock_recover().clone();
        for ext in exts {
            let name = ext.name().to_string();
            match ext.on_init(self) {
                Ok(()) => {
                    if let Ok(mut hs) = self.ext_health.lock() {
                        if let Some(h) = hs.get_mut(&name) {
                            h.initialized = true;
                        }
                    }
                    log_info!("ext", "扩展初始化成功：{}", name);
                }
                Err(e) => {
                    if let Ok(mut hs) = self.ext_health.lock() {
                        if let Some(h) = hs.get_mut(&name) {
                            h.initialized = false;
                            h.init_error = Some(e.clone());
                        }
                    }
                    log_error!("ext", "扩展「{}」初始化失败：{}", name, e);
                }
            }
        }
    }

    /// 发布事件到全部扩展。
    /// 数据目录（供扩展存放自己的状态文件）。
    pub fn data_dir(&self) -> std::path::PathBuf {
        self.store
            .db_path
            .parent()
            .unwrap_or(std::path::Path::new("data"))
            .to_path_buf()
    }

    /// 发布一条信息性事件（如核心启动）。
    pub fn publish_info(&self, info: &str) {
        let mut p = Json::obj();
        p.set("info", Json::s(info));
        self.publish(EventKind::CoreStarted, p);
    }

    pub fn publish(&self, kind: EventKind, payload: Json) {
        let ev = CoreEvent {
            kind,
            payload,
            time: store::now_string(),
        };
        let exts = self.extensions.lock_recover().clone();
        log_debug!("event", "发布事件 {}", kind.as_str());
        for ext in exts {
            let name = ext.name().to_string();
            // v1.2 扩展隔离：单个扩展的处理异常不得影响核心与其他扩展。
            // catch_unwind 需要 UnwindSafe，而 &CoreEvent 含 Json（含 BTreeMap）
            // 满足要求，故用 AssertUnwindSafe 包裹引用即可。
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                ext.on_event(self, &ev);
            }));
            let mut hs = match self.ext_health.lock() {
                Ok(g) => g,
                Err(_) => continue,
            };
            if let Some(h) = hs.get_mut(&name) {
                h.event_count += 1;
                h.last_event_time = Some(ev.time.clone());
                if result.is_err() {
                    h.event_errors += 1;
                }
            }
            drop(hs);
            if result.is_err() {
                log_error!(
                    "ext",
                    "扩展「{}」处理事件 {} 时发生 panic，已隔离（核心继续运行）",
                    name,
                    kind.as_str()
                );
            }
        }
    }

    // ------------------------------------------------------------------
    // 数据访问（加锁 + 落盘）
    // ------------------------------------------------------------------

    /// 只读访问。
    pub fn read<R>(&self, f: impl FnOnce(&Data) -> R) -> R {
        let d = self.store.data.lock_recover();
        f(&d)
    }

    /// 修改访问：f 返回 Ok 后自动落盘；Err 则不落盘。
    ///
    /// v1.2：落盘前按 `undo_keep` 裁剪撤销栈，保证持久化的栈长度符合配置。
    pub fn write<R>(
        &self,
        f: impl FnOnce(&mut Data) -> Result<R, ApiErr>,
    ) -> Result<R, ApiErr> {
        let mut d = self.store.data.lock_recover();
        let r = f(&mut d)?;
        Self::trim_undo_stack(&mut d, self.undo_keep);
        self.store.save(&d)?;
        Ok(r)
    }

    /// 记录撤销（v1.2：压入多步栈，超出上限时丢弃最旧条目）。
    ///
    /// 栈顶（`undo_stack.last()`）为最近一次可撤销操作。
    fn push_undo(d: &mut Data, action: &str, payload: Json) {
        d.undo_stack.push(UndoEntry {
            time: store::now_string(),
            action: action.to_string(),
            payload,
        });
        // 上限保护：由 Core::undo_keep 决定，但此处无法访问 Core 实例，
        // 故使用模块级常量上限（合理上界），实际裁剪在 write 包装中完成。
        if d.undo_stack.len() > MAX_UNDO_STACK {
            let excess = d.undo_stack.len() - MAX_UNDO_STACK;
            d.undo_stack.drain(0..excess);
        }
    }

    /// 按 Core 配置的 undo_keep 裁剪栈（在 write 落盘前调用）。
    fn trim_undo_stack(d: &mut Data, keep: usize) {
        if keep == 0 {
            d.undo_stack.clear();
            return;
        }
        if d.undo_stack.len() > keep {
            let excess = d.undo_stack.len() - keep;
            d.undo_stack.drain(0..excess);
        }
    }

    // ------------------------------------------------------------------
    // 统计 / 元信息
    // ------------------------------------------------------------------

    pub fn stats_json(&self) -> Json {
        self.read(|d| {
            let computed = d.results.iter().filter(|r| r.points.is_some()).count();
            let records = d.results.iter().filter(|r| r.broke_record).count();
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("events", Json::Int(d.events.len() as i64));
            o.set("students", Json::Int(d.students.len() as i64));
            o.set("registrations", Json::Int(d.registrations.len() as i64));
            o.set("results", Json::Int(d.results.len() as i64));
            o.set("computed", Json::Int(computed as i64));
            o.set("records", Json::Int(records as i64));
            o
        })
    }

    pub fn meta_json(&self) -> Json {
        self.read(|d| {
            let st = &d.settings;
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            // v1.5.1：暴露版本与安全态摘要，供诊断页签展示。
            // 只放"版本号"这类非敏感信息；口令、密钥一律不出现。
            o.set(
                "version",
                Json::s(env!("CARGO_PKG_VERSION").to_string()),
            );
            o.set("security", self.security_summary_json());
            o.set("grades", Json::arr(st.grades.iter().map(|g| Json::s(g.clone()))));
            o.set("class_count", Json::Int(st.class_count));
            o.set("categories", Json::arr([Json::s("径赛"), Json::s("田赛")]));
            o.set(
                "genders",
                Json::arr([Json::s("男子"), Json::s("女子"), Json::s("通用")]),
            );
            o.set("units", Json::arr([Json::s("时间"), Json::s("米"), Json::s("个")]));
            o.set("max_individual", Json::Int(st.max_individual));
            o.set("max_team", Json::Int(st.max_team));
            o.set(
                "points_table",
                Json::arr(st.points_table.iter().map(|p| Json::Num(*p))),
            );
            o.set("record_bonus", Json::Num(st.record_bonus));
            o.set("team_multiplier", Json::Num(st.team_multiplier));
            o
        })
    }

    /// 安全态摘要（v1.5.1）—— 供 `/api/meta` 与诊断页签使用。
    ///
    /// 刻意只放**布尔量与枚举标签**，不含密钥、口令、种子或任何可反推
    /// 凭据的信息。这些字段本来就是"使用者自己配置了什么"的如实反馈，
    /// 泄露它们不会削弱安全边界。
    pub fn security_summary_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("password_enabled", Json::Bool(self.password.is_some()));
        o.set("encrypt_data", Json::Bool(self.encrypt_data));
        // v1.5.1：区分"磁盘上存在密文"与"确实已武装保险库"。
        // 前者为真而后者为假，说明**缺少密钥**，诊断页可给出准确指引。
        o.set("vault_enabled", Json::Bool(self.store.vault_enabled));
        o.set("vault_detected", Json::Bool(self.store.vault_detected));
        let (has_key, unlocked) = match self.license.as_ref() {
            Some(l) => (l.key_ok(), l.mode().is_unlocked()),
            None => (false, false),
        };
        o.set("devkey_present", Json::Bool(has_key));
        o.set("dev_mode", Json::s(if unlocked { "unlocked" } else { "locked" }));
        o
    }

    // ------------------------------------------------------------------
    // 设置
    // ------------------------------------------------------------------

    pub fn get_settings(&self) -> Json {
        self.read(|d| {
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("settings", d.settings.to_json());
            o
        })
    }

    pub fn set_settings(&self, patch: &Json) -> Result<Json, ApiErr> {
        let payload = patch.clone();
        let st = self.write(|d| {
            d.settings = Self::validate_settings(&d.settings, patch)?;
            Ok(d.settings.clone())
        })?;
        log_info!("api", "设置已更新");
        crate::core::audit::record("admin", "settings.update", "更新计分与报名参数");
        self.publish(EventKind::SettingsChanged, payload);
        let mut o = Json::obj();
        o.set("ok", Json::Bool(true));
        o.set("settings", st.to_json());
        Ok(o)
    }

    fn validate_settings(cur: &Settings, patch: &Json) -> Result<Settings, ApiErr> {
        let mut s = cur.clone();
        if let Some(Json::Arr(arr)) = patch.get("grades") {
            let mut grades: Vec<String> = Vec::new();
            for v in arr {
                let g = v
                    .as_str()
                    .map(|x| x.trim().to_string())
                    .unwrap_or_default();
                if g.is_empty() {
                    return Err(ApiErr::new("年级列表必须为 1~10 个不重复的非空名称"));
                }
                if !grades.contains(&g) {
                    grades.push(g);
                }
            }
            if grades.is_empty() || grades.len() > 10 {
                return Err(ApiErr::new("年级列表必须为 1~10 个不重复的非空名称"));
            }
            s.grades = grades;
        }
        if let Some(v) = patch.get_i64("class_count") {
            if !(1..=60).contains(&v) {
                return Err(ApiErr::new("每个年级班级数须为 1~60"));
            }
            s.class_count = v;
        }
        if let Some(v) = patch.get_i64("max_individual") {
            if !(0..=10).contains(&v) {
                return Err(ApiErr::new("每人单项限额须为 0~10"));
            }
            s.max_individual = v;
        }
        if let Some(v) = patch.get_i64("max_team") {
            if !(0..=10).contains(&v) {
                return Err(ApiErr::new("每人集体项目限额须为 0~10"));
            }
            s.max_team = v;
        }
        if let Some(v) = patch.get_i64("max_per_class_per_event") {
            if !(0..=60).contains(&v) {
                return Err(ApiErr::new("每班每单项限报须为不小于 0 的整数"));
            }
            s.max_per_class_per_event = v;
        }
        if let Some(v) = patch.get("enforce_gender").and_then(|v| v.as_bool()) {
            s.enforce_gender = v;
        }
        if let Some(Json::Arr(arr)) = patch.get("points_table") {
            let mut pts: Vec<f64> = Vec::new();
            for v in arr {
                let p = v.as_f64().ok_or_else(|| ApiErr::new("积分表必须为数字列表"))?;
                if !(0.0..=1000.0).contains(&p) {
                    return Err(ApiErr::new("积分须为 0~1000 之间的数字"));
                }
                pts.push(p);
            }
            if pts.is_empty() || pts.len() > 30 {
                return Err(ApiErr::new("积分表须为 1~30 个数字"));
            }
            s.points_table = pts;
        }
        if let Some(v) = patch.get("record_bonus").and_then(|v| v.as_f64()) {
            if !(0.0..=100.0).contains(&v) {
                return Err(ApiErr::new("破纪录加分须为 0~100"));
            }
            s.record_bonus = v;
        }
        if let Some(v) = patch.get("team_multiplier").and_then(|v| v.as_f64()) {
            if !(1.0..=10.0).contains(&v) {
                return Err(ApiErr::new("集体项目倍数须为 1~10"));
            }
            s.team_multiplier = v;
        }
        Ok(s)
    }

    // ------------------------------------------------------------------
    // 项目
    // ------------------------------------------------------------------

    pub fn list_events(&self) -> Json {
        self.read(|d| {
            let mut arr = Vec::new();
            for ev in &d.events {
                let registered = d
                    .registrations
                    .iter()
                    .filter(|r| r.event_id == ev.id)
                    .count();
                let mut o = event_to_json(ev);
                o.set("is_track", Json::Bool(ev.is_track()));
                o.set(
                    "record_text",
                    ev.record
                        .map(|v| Json::s(scoring::format_score(v, &ev.unit)))
                        .unwrap_or(Json::Null),
                );
                o.set("registered", Json::Int(registered as i64));
                arr.push(o);
            }
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("events", Json::Arr(arr));
            o
        })
    }

    pub fn add_event(&self, body: &Json) -> Result<Json, ApiErr> {
        let (ev, payload) = self.write(|d| {
            let name = body.get_str("name").unwrap_or_default().trim().to_string();
            if name.is_empty() || name.chars().count() > 24 {
                return Err(ApiErr::new("项目名称必填，且不超过 24 字"));
            }
            /* v1.6.0：同名项目检测，返回 E_CONFLICT 而非泛泛的 400。
               理由：录入场景里"手滑重复添加同一个项目"非常常见，
               而此前会静默成功地建出两个同名项目，报表里两行一样、
               分不清哪个是哪个。现在明确拒绝，且错误码告知客户端
               "这是重复，不是格式错"——前端可以据此走"已存在，
               是否直接编辑那一个"的分支，而不是弹一个无用的报错。 */
            if d.events.iter().any(|e| e.name == name) {
                // 用语义化构造器（409 Conflict + E_CONFLICT）。
                // 不过 HTTP 状态码仍是 409 会让"同名"与真正的资源冲突混在一起，
                // 这里保留 409 —— 语义上确实就是冲突，且 409 语义清晰，
                // 客户端按 `error.code` 分流即可，不必依赖状态码。
                return Err(ApiErr::conflict(format!("项目「{}」已存在", name)));
            }
            let category = body.get_str("category").unwrap_or_default();
            if category != "径赛" && category != "田赛" {
                return Err(ApiErr::new("类别必须为「径赛」或「田赛」"));
            }
            let gender = body.get_str("gender").unwrap_or_default();
            if !["男子", "女子", "通用"].contains(&gender) {
                // v1.6.0：显式标注为校验错误码。虽然 `ApiErr::new` 默认就是
                // E_VALIDATION，但这里写明是为了**在阅读时一眼看出意图**，
                // 也避免将来有人把默认值改掉时这里被静默改变语义。
                return Err(ApiErr::new("性别分组不合法")
                    .with_code(crate::core::error::ErrCode::Validation));
            }
            let grade = body.get_str("grade").unwrap_or_default();
            let grade_ok = grade == "全部" || d.settings.grades.iter().any(|g| g == grade);
            if !grade_ok {
                return Err(ApiErr::new("适用年级不合法"));
            }
            let unit = body.get_str("unit").unwrap_or_default();
            if !["时间", "米", "个"].contains(&unit) {
                return Err(ApiErr::new("成绩单位不合法"));
            }
            let is_team = body.get("is_team").and_then(|v| v.as_bool()).unwrap_or(false);
            let record = match body.get("record") {
                Some(Json::Null) | None => None,
                Some(v) => {
                    let t = v.as_str().unwrap_or_default().trim().to_string();
                    if t.is_empty() {
                        None
                    } else {
                        match scoring::parse_score(&t, unit) {
                            Some(x) => Some(x),
                            None => {
                                return Err(ApiErr::new(format!(
                                    "校纪录格式不正确（{}）",
                                    scoring::unit_hint(unit)
                                )))
                            }
                        }
                    }
                }
            };
            let ev = Event {
                id: d.next_event_id,
                name: name.clone(),
                category: category.to_string(),
                gender: gender.to_string(),
                grade: grade.to_string(),
                is_team,
                unit: unit.to_string(),
                record,
            };
            d.next_event_id += 1;
            let pj = event_to_json(&ev);
            d.events.push(ev.clone());
            Ok((ev, pj))
        })?;
        let _ = payload;
        log_info!("api", "新建项目：{}（id={}）", ev.name, ev.id);
        crate::core::audit::record(
            "admin",
            "event.create",
            &format!("新建项目「{}」（id={}）", ev.name, ev.id),
        );
        self.publish(EventKind::EventCreated, event_to_json(&ev));
        let mut o = Json::obj();
        o.set("ok", Json::Bool(true));
        o.set("id", Json::Int(ev.id));
        Ok(o)
    }

    pub fn update_event(&self, id: i64, body: &Json) -> Result<Json, ApiErr> {
        let ev = self.write(|d| -> Result<Event, ApiErr> {
            let grade_names: Vec<String> = d.settings.grades.clone();
            let ev = d
                .events
                .iter_mut()
                .find(|e| e.id == id)
                .ok_or_else(|| ApiErr::with_status("项目不存在", 404))?;
            if let Some(v) = body.get("name") {
                let n = v.as_str().unwrap_or_default().trim().to_string();
                if n.is_empty() || n.chars().count() > 24 {
                    return Err(ApiErr::new("项目名称必填，且不超过 24 字"));
                }
                ev.name = n;
            }
            for (key, valid, field) in [
                ("category", vec!["径赛", "田赛"], 0),
                ("gender", vec!["男子", "女子", "通用"], 1),
                ("unit", vec!["时间", "米", "个"], 2),
            ] {
                if let Some(v) = body.get(key) {
                    let s = v.as_str().unwrap_or_default();
                    if !valid.contains(&s) {
                        return Err(ApiErr::new(format!("{} 不合法", key)));
                    }
                    match field {
                        0 => ev.category = s.into(),
                        1 => ev.gender = s.into(),
                        _ => ev.unit = s.into(),
                    }
                }
            }
            if let Some(v) = body.get("grade") {
                let g = v.as_str().unwrap_or_default();
                if g != "全部" && !grade_names.contains(&g.to_string()) {
                    return Err(ApiErr::new("适用年级不合法"));
                }
                ev.grade = g.into();
            }
            if let Some(v) = body.get("is_team").and_then(|v| v.as_bool()) {
                ev.is_team = v;
            }
            if let Some(v) = body.get("record") {
                ev.record = match v {
                    Json::Null => None,
                    v => {
                        let t = v.as_str().unwrap_or_default().trim().to_string();
                        if t.is_empty() {
                            None
                        } else {
                            match scoring::parse_score(&t, &ev.unit) {
                                Some(x) => Some(x),
                                None => {
                                    return Err(ApiErr::new(format!(
                                        "校纪录格式不正确（{}）",
                                        scoring::unit_hint(&ev.unit)
                                    )))
                                }
                            }
                        }
                    }
                };
            }
            Ok(ev.clone())
        })?;
        // 修改项目（如校纪录）后名次可能变化，重算该项目
        let _ = self.compute_event_inner(id);
        log_info!("api", "更新项目：{}（id={}）", ev.name, ev.id);
        crate::core::audit::record(
            "admin",
            "event.update",
            &format!("修改项目「{}」（id={}）", ev.name, ev.id),
        );
        self.publish(EventKind::EventUpdated, event_to_json(&ev));
        let mut o = Json::obj();
        o.set("ok", Json::Bool(true));
        Ok(o)
    }

    pub fn delete_preview_event(&self, id: i64) -> Result<Json, ApiErr> {
        self.read(|d| -> Result<Json, ApiErr> {
            let ev = d
                .events
                .iter()
                .find(|e| e.id == id)
                .ok_or_else(|| ApiErr::with_status("项目不存在", 404))?;
            let regs = d.registrations.iter().filter(|r| r.event_id == id).count();
            let results = d.results.iter().filter(|r| r.event_id == id).count();
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("name", Json::s(ev.name.clone()));
            o.set("registrations", Json::Int(regs as i64));
            o.set("results", Json::Int(results as i64));
            Ok(o)
        })
    }

    pub fn delete_event(&self, id: i64, confirmed: bool) -> Result<Json, ApiErr> {
        if !confirmed {
            let preview = self.delete_preview_event(id)?;
            return Err(ApiErr::with_status("需要确认", 428).with_data(preview));
        }
        let (name, _payload) = self.write(|d| -> Result<(String, Json), ApiErr> {
            let idx = d
                .events
                .iter()
                .position(|e| e.id == id)
                .ok_or_else(|| ApiErr::with_status("项目不存在", 404))?;
            let ev = d.events.remove(idx);
            let regs: Vec<Json> = d
                .registrations
                .iter()
                .filter(|r| r.event_id == id)
                .map(reg_to_json)
                .collect();
            let results: Vec<Json> = d
                .results
                .iter()
                .filter(|r| r.event_id == id)
                .map(result_to_json)
                .collect();
            d.registrations.retain(|r| r.event_id != id);
            d.results.retain(|r| r.event_id != id);
            let mut p = Json::obj();
            p.set("event", event_to_json(&ev));
            p.set("registrations", Json::Arr(regs));
            p.set("results", Json::Arr(results));
            Self::push_undo(d, "delete_event", p.clone());
            Ok((ev.name.clone(), p))
        })?;
        log_warn!("api", "删除项目：{}（id={}）", name, id);
        crate::core::audit::record(
            "admin",
            "event.delete",
            &format!("删除项目「{}」（id={}，连带成绩）", name, id),
        );
        self.publish(EventKind::EventDeleted, {
            let mut o = Json::obj();
            o.set("id", Json::Int(id));
            o.set("name", Json::s(name));
            o
        });
        let mut o = Json::obj();
        o.set("ok", Json::Bool(true));
        o.set("message", Json::s("项目已删除，可撤销"));
        Ok(o)
    }

    // ------------------------------------------------------------------
    // 学生
    // ------------------------------------------------------------------

    pub fn list_students(&self, grade: Option<&str>, class_no: Option<i64>) -> Json {
        self.read(|d| {
            let mut arr = Vec::new();
            for s in &d.students {
                if let Some(g) = grade {
                    if s.grade != g {
                        continue;
                    }
                }
                if let Some(c) = class_no {
                    if s.class_no != c {
                        continue;
                    }
                }
                let mut o = student_to_json(s);
                o.set("class_name", Json::s(s.class_name()));
                let regs: Vec<i64> = d
                    .registrations
                    .iter()
                    .filter(|r| r.student_id == s.id)
                    .map(|r| r.event_id)
                    .collect();
                o.set("events", Json::arr(regs.into_iter().map(Json::Int)));
                arr.push(o);
            }
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("students", Json::Arr(arr));
            o
        })
    }

    /// 新增单个或批量学生（去重：同年级同班同名）。
    pub fn add_students(&self, students: &[Student]) -> Result<Json, ApiErr> {
        if students.is_empty() {
            return Err(ApiErr::new("没有可添加的学生"));
        }
        let mut created = Vec::new();
        let mut skipped: Vec<(String, String)> = Vec::new();
        self.write(|d| {
            for s in students {
                let grade = s.grade.trim();
                let name = s.name.trim();
                if name.is_empty() || name.chars().count() > 20 {
                    skipped.push((s.name.clone(), "姓名不合法".into()));
                    continue;
                }
                if !d.settings.grades.contains(&grade.to_string()) {
                    skipped.push((s.name.clone(), "年级不存在".into()));
                    continue;
                }
                if s.class_no < 1 || s.class_no > d.settings.class_count {
                    skipped.push((s.name.clone(), "班级号超出范围".into()));
                    continue;
                }
                if !["男", "女", ""].contains(&s.gender.as_str()) {
                    skipped.push((s.name.clone(), "性别不合法".into()));
                    continue;
                }
                let dup = d.students.iter().any(|x| {
                    x.grade == grade && x.class_no == s.class_no && x.name == name
                });
                if dup {
                    // v1.6.0：重名属于**冲突**（数据已存在），不是参数格式错。
                    // 加前缀标记，序列化时映射为 E_CONFLICT，客户端可据此
                    // 区分"改一下再试"与"这人已经录过了，别再试"。
                    skipped.push((s.name.clone(), "\u{1}该班级已有同名学生".into()));
                    continue;
                }
                let stu = Student {
                    id: d.next_student_id,
                    grade: grade.to_string(),
                    class_no: s.class_no,
                    name: name.to_string(),
                    gender: s.gender.clone(),
                };
                d.next_student_id += 1;
                d.students.push(stu.clone());
                created.push(stu);
            }
            Ok(())
        })?;
        log_info!("api", "批量添加学生：{} 人", created.len());
        crate::core::audit::record(
            "admin",
            "student.batch_add",
            &format!("批量添加学生 {} 人", created.len()),
        );
        for s in &created {
            self.publish(EventKind::StudentCreated, student_to_json(s));
        }
        let mut o = Json::obj();
        o.set("ok", Json::Bool(true));
        o.set("added", Json::Int(created.len() as i64));
        o.set(
            "skipped",
            Json::arr(skipped.iter().map(|(n, r)| {
                let mut e = Json::obj();
                e.set("name", Json::s(n.clone()));
                // v1.6.0：\u{1} 前缀表示"冲突类跳过"，剥离后给出稳定错误码。
                // 用控制字符做内部分隔，避免与用户可见文案混淆
                // （姓名/理由里不可能出现 \u{1}）。
                if let Some(rest) = r.strip_prefix('\u{1}') {
                    e.set("reason", Json::s(rest));
                    e.set("code", Json::s("E_CONFLICT"));
                } else {
                    e.set("reason", Json::s(r.clone()));
                    e.set("code", Json::s("E_VALIDATION"));
                }
                e
            })),
        );
        Ok(o)
    }

    /// 报名表导入（v1.9.0：xlsx 经 `tools/baoming_import.py` 转成的 JSON）。
    ///
    /// 输入形状（脚本产出；除 `students` 外均可缺省）：
    /// ```text
    /// {
    ///   "ensure_grades": true,                    // 年级不在设置里时自动补上
    ///   "grades": ["奥创七"],                      // 需要确保存在的年级
    ///   "students":     [{"name","grade","class_no","gender"}],
    ///   "registrations":[{"name","grade","class_no","event","event_id","note"}]
    /// }
    /// ```
    /// 流程：按需补年级设置 → 批量加学生（已存在的记 E_CONFLICT 跳过）
    /// → 按 (年级, 班号, 姓名) 解析学生、按 `event_id`/名称解析项目
    /// → 逐条报名。全程复用既有校验（性别/额度/班级限额/年级限制），
    /// 任何一条不合格都进 `skipped` 报告，不会半途中断。
    pub fn import_baoming(&self, body: &Json) -> Result<Json, ApiErr> {
        // —— 1) 解析学生与报名条目 ——
        let mut students: Vec<Student> = Vec::new();
        if let Some(Json::Arr(arr)) = body.get("students") {
            for e in arr {
                students.push(Student {
                    id: 0,
                    grade: e.get_string("grade"),
                    class_no: e.get_i64("class_no").unwrap_or(0),
                    name: e.get_string("name"),
                    gender: e.get_string("gender"),
                });
            }
        }
        if students.is_empty() {
            return Err(ApiErr::new("没有可导入的学生（students 为空）"));
        }
        // 报名条目（内部表示，避免反复解 JSON）
        struct Entry {
            name: String,
            grade: String,
            class_no: i64,
            event: String,
            event_id: Option<i64>,
            note: String,
        }
        let mut entries: Vec<Entry> = Vec::new();
        if let Some(Json::Arr(arr)) = body.get("registrations") {
            for e in arr {
                entries.push(Entry {
                    name: e.get_string("name"),
                    grade: e.get_string("grade"),
                    class_no: e.get_i64("class_no").unwrap_or(0),
                    event: e.get_string("event"),
                    event_id: e.get_i64("event_id"),
                    note: e.get_string("note"),
                });
            }
        }

        // —— 2) 按需补年级设置（"奥创七7"这类学校自定义年级名）——
        let mut grades_added: Vec<String> = Vec::new();
        if body
            .get("ensure_grades")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            let mut need: Vec<String> = match body.get("grades") {
                Some(Json::Arr(arr)) => arr
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.trim().to_string()))
                    .filter(|s| !s.is_empty())
                    .collect(),
                _ => Vec::new(),
            };
            if need.is_empty() {
                // 没显式给列表 → 从学生里推导
                for s in &students {
                    if !s.grade.is_empty() && !need.contains(&s.grade) {
                        need.push(s.grade.clone());
                    }
                }
            }
            let cur = self.read(|d| d.settings.grades.clone());
            let mut merged = cur;
            for g in need {
                if !merged.contains(&g) {
                    if merged.len() >= 10 {
                        return Err(ApiErr::new(format!(
                            "年级数将达到 10 个上限，无法自动添加「{}」—— 请先在设置里整理年级列表",
                            g
                        )));
                    }
                    merged.push(g.clone());
                    grades_added.push(g);
                }
            }
            if !grades_added.is_empty() {
                let mut patch = Json::obj();
                patch.set("grades", Json::arr(merged.iter().map(|g| Json::s(g.clone()))));
                self.set_settings(&patch)?;
                crate::core::audit::record(
                    "admin",
                    "import.baoming.grades",
                    &format!("报名表导入自动添加年级：{}", grades_added.join("、")),
                );
            }
        }

        // —— 3) 加学生（已存在的走 E_CONFLICT 跳过，后面仍可报名）——
        let add_res = self.add_students(&students)?;
        let added = add_res.get_i64("added").unwrap_or(0);

        // —— 4) 解析学生与项目，逐条报名 ——
        let events = self.read(|d| d.events.clone());
        let students_now = self.read(|d| d.students.clone());
        let find_student = |e: &Entry| -> Option<i64> {
            students_now
                .iter()
                .find(|s| s.grade == e.grade && s.class_no == e.class_no && s.name == e.name)
                .map(|s| s.id)
        };
        let find_event = |e: &Entry| -> Option<i64> {
            if let Some(id) = e.event_id {
                if events.iter().any(|ev| ev.id == id) {
                    return Some(id);
                }
            }
            if e.event.is_empty() {
                return None;
            }
            if let Some(ev) = events.iter().find(|ev| ev.name == e.event) {
                return Some(ev.id);
            }
            // 归一化兜底：去空白、去「男子/女子/男/女」前缀、统一 × ——
            // 覆盖「100米」对「男子100米」这类常见写法
            let norm = |s: &str| -> String {
                s.chars()
                    .filter(|c| !c.is_whitespace())
                    .collect::<String>()
                    .trim_start_matches("男子")
                    .trim_start_matches("女子")
                    .trim_start_matches(['男', '女'])
                    .replace('×', "x")
                    .replace('X', "x")
            };
            let want = norm(&e.event);
            events
                .iter()
                .find(|ev| norm(&ev.name) == want)
                .map(|ev| ev.id)
        };

        let mut reg_added = 0i64;
        let mut reg_skipped: Vec<Json> = Vec::new();
        for e in &entries {
            let label = if e.grade.is_empty() {
                e.name.clone()
            } else {
                format!("{}（{}{}班）", e.name, e.grade, e.class_no)
            };
            let Some(sid) = find_student(e) else {
                reg_skipped.push(skip_entry(&label, "学生不在名单中（年级/班号/姓名对不上）"));
                continue;
            };
            let Some(eid) = find_event(e) else {
                reg_skipped.push(skip_entry(
                    &label,
                    &format!(
                        "项目不存在：{}",
                        if e.event.is_empty() {
                            "（未提供）"
                        } else {
                            e.event.as_str()
                        }
                    ),
                ));
                continue;
            };
            let res = self.register_many(eid, &[sid], &e.note, false)?;
            if res.get_i64("added").unwrap_or(0) > 0 {
                reg_added += 1;
            } else {
                let reason = res
                    .get("skipped")
                    .and_then(|v| v.as_arr())
                    .and_then(|a| a.first())
                    .and_then(|x| x.get_str("reason").map(|s| s.to_string()))
                    .unwrap_or_else(|| "未报名".into());
                reg_skipped.push(skip_entry(&label, &reason));
            }
        }

        crate::core::audit::record(
            "admin",
            "import.baoming",
            &format!("报名表导入：学生 +{}，报名 +{}", added, reg_added),
        );
        let mut o = Json::obj();
        o.set("ok", Json::Bool(true));
        o.set("added", Json::Int(added));
        o.set("registrations_added", Json::Int(reg_added));
        o.set(
            "grades_added",
            Json::arr(grades_added.iter().map(|g| Json::s(g.clone()))),
        );
        let mut skipped: Vec<Json> = add_res
            .get("skipped")
            .and_then(|v| v.as_arr())
            .cloned()
            .unwrap_or_default();
        skipped.extend(reg_skipped);
        o.set("skipped", Json::arr(skipped));
        Ok(o)
    }

    /// v1.9.3：上传填写好的报名表文件（xlsx / csv），解析后复用既有导入。
    ///
    /// 与 `import_baoming` 的关系：**这里只负责把文件翻译成 payload**，
    /// 真正入库仍走原路径 —— 幂等、限额、性别分组、年级自动补、跳过
    /// 报告等既有校验一条不少，避免"新入口绕过旧规则"。
    pub fn import_baoming_file(&self, body: &Json) -> Result<Json, ApiErr> {
        let events = self.read(|d| d.events.clone());
        let filename = body.get_string("filename");
        let bytes: Vec<u8> = if let Some(b64) = body.get_str("b64") {
            crate::core::baoming::b64_decode(b64)?
        } else {
            body.get_string("text").into_bytes()
        };
        let (payload, report) =
            crate::core::baoming::parse_file(&filename, &bytes, &events)?;
        let mut out = self.import_baoming(&payload)?;
        out.set("parse_report", report);
        Ok(out)
    }

    /// v1.9.7：先导名单，再在「报名」页选项目。
    ///
    /// 与 `import_baoming_file` 的关系：同样只负责把文件翻译成 payload，
    /// 入库仍走 `import_baoming` —— 增量、重名跳过、年级自动补、限额校验
    /// 一条不少。区别只有两点：**不要求项目列**，且**不产生任何报名**。
    /// 原有「报名表导入」保持不动，两条路互不覆盖。
    pub fn import_roster_file(&self, body: &Json) -> Result<Json, ApiErr> {
        let filename = body.get_string("filename");
        let bytes: Vec<u8> = if let Some(b64) = body.get_str("b64") {
            crate::core::baoming::b64_decode(b64)?
        } else {
            body.get_string("text").into_bytes()
        };
        let (payload, report) = crate::core::baoming::parse_roster_file(&filename, &bytes)?;
        let mut out = self.import_baoming(&payload)?;
        out.set("parse_report", report);
        Ok(out)
    }

    pub fn delete_preview_student(&self, id: i64) -> Result<Json, ApiErr> {
        self.read(|d| -> Result<Json, ApiErr> {
            let s = d
                .students
                .iter()
                .find(|s| s.id == id)
                .ok_or_else(|| ApiErr::with_status("学生不存在", 404))?;
            let regs = d.registrations.iter().filter(|r| r.student_id == id).count();
            let results = d.results.iter().filter(|r| r.student_id == Some(id)).count();
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("name", Json::s(s.name.clone()));
            o.set("class_name", Json::s(s.class_name()));
            o.set("registrations", Json::Int(regs as i64));
            o.set("results", Json::Int(results as i64));
            Ok(o)
        })
    }

    pub fn delete_student(&self, id: i64, confirmed: bool) -> Result<Json, ApiErr> {
        if !confirmed {
            let preview = self.delete_preview_student(id)?;
            return Err(ApiErr::with_status("需要确认", 428).with_data(preview));
        }
        let name = self.write(|d| {
            let idx = d
                .students
                .iter()
                .position(|s| s.id == id)
                .ok_or_else(|| ApiErr::with_status("学生不存在", 404))?;
            let stu = d.students.remove(idx);
            let regs: Vec<Json> = d
                .registrations
                .iter()
                .filter(|r| r.student_id == id)
                .map(reg_to_json)
                .collect();
            let results: Vec<Json> = d
                .results
                .iter()
                .filter(|r| r.student_id == Some(id))
                .map(result_to_json)
                .collect();
            d.registrations.retain(|r| r.student_id != id);
            d.results.retain(|r| r.student_id != Some(id));
            let mut p = Json::obj();
            p.set("student", student_to_json(&stu));
            p.set("registrations", Json::Arr(regs));
            p.set("results", Json::Arr(results));
            Self::push_undo(d, "delete_student", p.clone());
            Ok(stu.name.clone())
        })?;
        self.publish(
            EventKind::StudentDeleted,
            Json::obj().set("id", Json::Int(id)).clone(),
        );
        let _ = name;
        let mut o = Json::obj();
        o.set("ok", Json::Bool(true));
        o.set("message", Json::s("学生已删除，可撤销"));
        Ok(o)
    }

    // ------------------------------------------------------------------
    // 报名
    // ------------------------------------------------------------------

    /// 批量报名（与 Python register_many 校验规则对齐）。
    pub fn register_many(
        &self,
        event_id: i64,
        student_ids: &[i64],
        note: &str,
        force_gender: bool,
    ) -> Result<Json, ApiErr> {
        let result = {
            let mut d = self.store.data.lock_recover();
            let ev = d
                .events
                .iter()
                .find(|e| e.id == event_id)
                .ok_or_else(|| ApiErr::with_status("项目不存在", 404))?
                .clone();
            let mut already: Vec<i64> = Vec::new();
            let mut added_names: Vec<String> = Vec::new();
            let mut skipped: Vec<Json> = Vec::new();
            let mut added_regs: Vec<Registration> = Vec::new();
            for sid in student_ids {
                let s = match d.students.iter().find(|s| s.id == *sid) {
                    Some(s) => s.clone(),
                    None => {
                        skipped.push(skip_entry(&format!("ID {}", sid), "学生不存在"));
                        continue;
                    }
                };
                let label = format!("{}（{}）", s.name, s.class_name());
                macro_rules! skip {
                    ($reason:expr) => {{
                        skipped.push(skip_entry(&label, $reason));
                        continue;
                    }};
                }
                if ev.grade != "全部" && s.grade != ev.grade {
                    skip!(format!("该赛事限 {} 年级", ev.grade));
                }
                if d.settings.enforce_gender
                    && !force_gender
                    && ev.gender != "通用"
                    && !s.gender.is_empty()
                {
                    let want = if ev.gender == "男子" { "男" } else { "女" };
                    if s.gender != want {
                        skip!(format!("限{}（{}）", ev.gender, want));
                    }
                }
                if already.contains(sid) {
                    skip!("已在本批次中");
                }
                if d
                    .registrations
                    .iter()
                    .any(|r| r.event_id == event_id && r.student_id == *sid)
                {
                    skip!("已报名该项目");
                }
                let (is_ind, quota) = if ev.is_team {
                    (false, d.settings.max_team)
                } else {
                    (true, d.settings.max_individual)
                };
                let count = d
                    .registrations
                    .iter()
                    .filter(|r| {
                        r.student_id == *sid
                            && d.events.iter().any(|e| e.id == r.event_id && e.is_team != is_ind)
                    })
                    .count() as i64;
                let kind = if ev.is_team { "集体" } else { "单项" };
                if quota > 0 && count >= quota {
                    skip!(format!("{}项目限报 {} 项", kind, quota));
                }
                if !ev.is_team && d.settings.max_per_class_per_event > 0 {
                    let in_class = d
                        .registrations
                        .iter()
                        .filter(|r| {
                            r.event_id == event_id
                                && d.students.iter().any(|x| {
                                    x.id == r.student_id
                                        && x.grade == s.grade
                                        && x.class_no == s.class_no
                                })
                        })
                        .count() as i64;
                    if in_class >= d.settings.max_per_class_per_event {
                        skip!(format!(
                            "每班单项限报 {} 人（{}已有 {} 人）",
                            d.settings.max_per_class_per_event,
                            s.class_name(),
                            in_class
                        ));
                    }
                }
                already.push(*sid);
                added_names.push(label);
            }
            // 写入新增
            for sid in &already {
                let r = Registration {
                    id: d.next_reg_id,
                    event_id,
                    student_id: *sid,
                    note: note.to_string(),
                };
                d.next_reg_id += 1;
                d.registrations.push(r.clone());
                added_regs.push(r);
            }
            if !already.is_empty() {
                let mut p = Json::obj();
                p.set("event_id", Json::Int(event_id));
                p.set("student_ids", Json::arr(already.iter().map(|i| Json::Int(*i))));
                Self::push_undo(&mut d, "register_many", p);
            }
            self.store.save(&d)
                .map_err(|e| ApiErr::new(format!("保存失败：{}", e)))?;
            let mut result = Json::obj();
            result.set("ok", Json::Bool(true));
            result.set("added", Json::Int(already.len() as i64));
            result.set(
                "added_names",
                Json::arr(added_names.iter().map(|n| Json::s(n.clone()))),
            );
            result.set("skipped", Json::Arr(skipped));
            result
        };
        let added_ids: Option<Vec<i64>> = {
            let d = self.store.data.lock_recover();
            let r = d
                .registrations
                .iter()
                .filter(|r| r.event_id == event_id)
                .map(|r| r.student_id)
                .collect::<Vec<_>>();
            if r.is_empty() { None } else { Some(r) }
        };
        if let Some(ids) = added_ids {
            log_info!("api", "报名：项目 id={} 共 {} 人", event_id, ids.len());
            let mut p = Json::obj();
            p.set("event_id", Json::Int(event_id));
            p.set("student_ids", Json::arr(ids.into_iter().map(Json::Int)));
            self.publish(EventKind::Registered, p);
        }
        Ok(result)
    }

    pub fn unregister(&self, student_id: i64, event_id: i64) -> Result<Json, ApiErr> {
        self.write(|d| {
            let pos = d
                .registrations
                .iter()
                .position(|r| r.student_id == student_id && r.event_id == event_id)
                .ok_or_else(|| ApiErr::new("该学生未报名此项目"))?;
            let reg = d.registrations.remove(pos);
            let result = d
                .results
                .iter()
                .find(|r| r.event_id == event_id && r.student_id == Some(student_id))
                .map(result_to_json);
            d.results
                .retain(|r| !(r.event_id == event_id && r.student_id == Some(student_id)));
            let mut p = Json::obj();
            p.set("registration", reg_to_json(&reg));
            if let Some(r) = &result {
                p.set("result", r.clone());
            }
            Self::push_undo(d, "unregister", p);
            Ok(())
        })?;
        log_info!("api", "退报：学生 id={} 项目 id={}", student_id, event_id);
        crate::core::audit::record(
            "admin",
            "registration.remove",
            &format!("退报：学生 id={} 项目 id={}", student_id, event_id),
        );
        let mut p = Json::obj();
        p.set("event_id", Json::Int(event_id));
        p.set("student_id", Json::Int(student_id));
        self.publish(EventKind::Unregistered, p);
        let mut o = Json::obj();
        o.set("ok", Json::Bool(true));
        o.set("message", Json::s("已退报，可撤销"));
        Ok(o)
    }

    // ------------------------------------------------------------------
    // v1.9.3：一键清空报名
    //
    // 背景：批量导入后想推倒重来，过去只能一条条点「退报」，或连点十次
    // 撤销（默认栈深 10）。这里给一个带范围、带预检、且**一步撤销就能
    // 全量恢复**的入口。语义与「退报」保持一致：连带删掉对应的个人成绩，
    // 否则会留下一批指向已退报学生的孤儿成绩。
    // ------------------------------------------------------------------

    /// 预检：该范围会删掉多少东西（不改动任何数据）。
    pub fn clear_registrations_preview(&self, body: &Json) -> Result<Json, ApiErr> {
        let scope = ClearRegScope::from_json(body)?;
        self.read(|d| {
            let picked = collect_clear_regs(d, &scope);
            let keys = clear_result_keys(&picked);
            let n_res = d
                .results
                .iter()
                .filter(|r| clear_result_hit(r, &keys))
                .count();
            let mut stu: Vec<i64> = picked.iter().map(|r| r.student_id).collect();
            stu.sort_unstable();
            stu.dedup();
            let mut evs: Vec<i64> = picked.iter().map(|r| r.event_id).collect();
            evs.sort_unstable();
            evs.dedup();
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("scope", Json::s(scope.kind.clone()));
            o.set("label", Json::s(scope.label()));
            o.set("registrations", Json::Int(picked.len() as i64));
            o.set("results", Json::Int(n_res as i64));
            o.set("students", Json::Int(stu.len() as i64));
            o.set("events", Json::Int(evs.len() as i64));
            Ok(o)
        })
    }

    /// 执行清空。body 必须带 `confirm: true`（前端弹窗确认后置位）；
    /// 未带时返回 428 + 预检数据，避免误触直接清库。
    pub fn clear_registrations(&self, body: &Json) -> Result<Json, ApiErr> {
        let scope = ClearRegScope::from_json(body)?;
        if !body
            .get("confirm")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            let pv = self.clear_registrations_preview(body)?;
            return Err(ApiErr::with_status("需要确认", 428).with_data(pv));
        }
        let (removed, removed_results, depth) =
            self.write(|d| -> Result<(usize, usize, usize), ApiErr> {
                let picked = collect_clear_regs(d, &scope);
                if picked.is_empty() {
                    return Err(ApiErr::new("该范围内没有报名记录"));
                }
                let keys = clear_result_keys(&picked);
                let res_rows: Vec<Json> = d
                    .results
                    .iter()
                    .filter(|r| clear_result_hit(r, &keys))
                    .map(result_to_json)
                    .collect();
                let reg_rows: Vec<Json> = picked.iter().map(reg_to_json).collect();
                let reg_ids: Vec<i64> = picked.iter().map(|r| r.id).collect();
                let removed = picked.len();
                let removed_results = res_rows.len();

                // 整批快照压入一条撤销记录：撤销一次即全量恢复，
                // 不再需要按条数连点十次（这是本次改动的核心痛点）。
                let mut p = Json::obj();
                p.set("scope", Json::s(scope.kind.clone()));
                p.set("label", Json::s(scope.label()));
                p.set("registrations", Json::Arr(reg_rows));
                p.set("results", Json::Arr(res_rows));
                Self::push_undo(d, "clear_registrations", p);

                d.registrations.retain(|r| !reg_ids.contains(&r.id));
                d.results.retain(|r| !clear_result_hit(r, &keys));
                Ok((removed, removed_results, d.undo_stack.len()))
            })?;
        log_warn!(
            "api",
            "清空报名：范围={} 删除报名 {} 条、成绩 {} 条",
            scope.label(),
            removed,
            removed_results
        );
        crate::core::audit::record(
            "admin",
            "registration.clear",
            &format!(
                "清空报名 [{}]：报名 {} 条、成绩 {} 条，可一步撤销",
                scope.label(), removed, removed_results
            ),
        );
        let mut o = Json::obj();
        o.set("ok", Json::Bool(true));
        o.set("removed", Json::Int(removed as i64));
        o.set("results_removed", Json::Int(removed_results as i64));
        o.set("undo_depth", Json::Int(depth as i64));
        o.set("message", Json::s("已清空，点「撤销」可一步全部恢复"));
        Ok(o)
    }

    /// 某项目报名名单（含学生信息与每项限额展示）。
    pub fn event_registrations(&self, event_id: i64) -> Result<Json, ApiErr> {
        self.read(|d| {
            let ev = d
                .events
                .iter()
                .find(|e| e.id == event_id)
                .ok_or_else(|| ApiErr::with_status("项目不存在", 404))?;
            let mut arr = Vec::new();
            let mut regs: Vec<&Registration> = d
                .registrations
                .iter()
                .filter(|r| r.event_id == event_id)
                .collect();
            regs.sort_by_key(|r| {
                d.students
                    .iter()
                    .find(|s| s.id == r.student_id)
                    .map(|s| (s.grade.clone(), s.class_no, s.name.clone()))
                    .unwrap_or_default()
            });
            for r in regs {
                if let Some(s) = d.students.iter().find(|s| s.id == r.student_id) {
                    let mut o = Json::obj();
                    o.set("reg_id", Json::Int(r.id));
                    o.set("student_id", Json::Int(s.id));
                    o.set("name", Json::s(s.name.clone()));
                    o.set("grade", Json::s(s.grade.clone()));
                    o.set("class_no", Json::Int(s.class_no));
                    o.set("class_name", Json::s(s.class_name()));
                    o.set("gender", Json::s(s.gender.clone()));
                    o.set("note", Json::s(r.note.clone()));
                    arr.push(o);
                }
            }
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("event", event_to_json(ev));
            o.set("entries", Json::Arr(arr));
            Ok(o)
        })
    }

    // ------------------------------------------------------------------
    // 成绩
    // ------------------------------------------------------------------

    /// 某项目成绩视图（与 Python /api/results 对齐，含可疑检测）。
    pub fn results_view(&self, event_id: i64) -> Result<Json, ApiErr> {
        let ev = self.read(|d| {
            d.events
                .iter()
                .find(|e| e.id == event_id)
                .map(event_to_json)
                .ok_or_else(|| ApiErr::with_status("项目不存在", 404))
        })?;
        let unit = ev.get_str("unit").unwrap_or("米").to_string();
        let is_track = ev.get("is_track").and_then(|v| v.as_bool()).unwrap_or(false);
        let record_text = ev.get("record_text").cloned().unwrap_or(Json::Null);
        self.read(|d| {
            let students: Vec<(i64, Student)> = d
                .registrations
                .iter()
                .filter(|r| r.event_id == event_id)
                .filter_map(|r| {
                    d.students
                        .iter()
                        .find(|s| s.id == r.student_id)
                        .map(|s| (r.student_id, s.clone()))
                })
                .collect();
            // 集体班级集合
            let mut classes: Vec<(String, i64)> = Vec::new();
            for (_, s) in &students {
                let key = (s.grade.clone(), s.class_no);
                if !classes.contains(&key) {
                    classes.push(key);
                }
            }
            // v1.9.8：已经有集体成绩的班级也要出现。
            // 成绩表导入时，接力项目通常没有逐个学生报名；
            // 若只按报名枚举，成绩写进去了却在页面上看不见。
            for r in d
                .results
                .iter()
                .filter(|r| r.event_id == event_id && r.student_id.is_none())
            {
                if let Some(c) = r.class_no {
                    let key = (r.grade.clone(), c);
                    if !classes.contains(&key) {
                        classes.push(key);
                    }
                }
            }
            classes.sort();

            let rows: Vec<&DomainResult> = d
                .results
                .iter()
                .filter(|r| r.event_id == event_id)
                .collect();

            let mut entries = Vec::new();
            if ev.get("is_team").and_then(|v| v.as_bool()).unwrap_or(false) {
                // 集体视图
                let mut vals: Vec<Option<f64>> = Vec::new();
                let mut keys: Vec<(String, i64)> = Vec::new();
                for (g, c) in &classes {
                    keys.push((g.clone(), *c));
                    vals.push(
                        rows.iter()
                            .find(|r| r.student_id.is_none() && r.grade == *g && r.class_no == Some(*c))
                            .and_then(|r| r.score_value),
                    );
                }
                let flags = detect_outliers(&vals, is_track);
                for (i, (g, c)) in keys.iter().enumerate() {
                    let row = rows.iter().find(|r| {
                        r.student_id.is_none() && r.grade == *g && r.class_no == Some(*c)
                    });
                    let mut o = Json::obj();
                    o.set("label", Json::s(format!("{}{}班", g, c)));
                    o.set("grade", Json::s(g.clone()));
                    o.set("class_no", Json::Int(*c));
                    o.set(
                        "score_text",
                        row.map(|r| Json::s(r.score_text.clone())).unwrap_or(Json::Null),
                    );
                    o.set(
                        "score_value",
                        row.and_then(|r| r.score_value).map(Json::Num).unwrap_or(Json::Null),
                    );
                    o.set("rank", row.and_then(|r| r.rank).map(Json::Int).unwrap_or(Json::Null));
                    o.set(
                        "points",
                        row.and_then(|r| r.points).map(Json::Num).unwrap_or(Json::Null),
                    );
                    o.set(
                        "broke_record",
                        Json::Bool(row.map(|r| r.broke_record).unwrap_or(false)),
                    );
                    o.set("suspect", Json::Bool(flags[i]));
                    o.set("score_ok", Json::Bool(row.map(|r| r.score_value.is_some()).unwrap_or(false)));
                    o.set("registered", Json::Bool(true));
                    entries.push(o);
                }
            } else {
                let mut vals: Vec<Option<f64>> = Vec::new();
                let mut ids: Vec<i64> = Vec::new();
                for (sid, _) in &students {
                    ids.push(*sid);
                    vals.push(
                        rows.iter()
                            .find(|r| r.student_id == Some(*sid))
                            .and_then(|r| r.score_value),
                    );
                }
                let flags = detect_outliers(&vals, is_track);
                for (i, (sid, s)) in students.iter().enumerate() {
                    let row = rows.iter().find(|r| r.student_id == Some(*sid));
                    let mut o = Json::obj();
                    o.set("label", Json::s(s.name.clone()));
                    o.set("student_id", Json::Int(*sid));
                    o.set("grade", Json::s(s.grade.clone()));
                    o.set("class_no", Json::Int(s.class_no));
                    o.set("class_name", Json::s(s.class_name()));
                    o.set("gender", Json::s(s.gender.clone()));
                    o.set(
                        "score_text",
                        row.map(|r| Json::s(r.score_text.clone())).unwrap_or(Json::Null),
                    );
                    o.set(
                        "score_value",
                        row.and_then(|r| r.score_value).map(Json::Num).unwrap_or(Json::Null),
                    );
                    o.set("rank", row.and_then(|r| r.rank).map(Json::Int).unwrap_or(Json::Null));
                    o.set(
                        "points",
                        row.and_then(|r| r.points).map(Json::Num).unwrap_or(Json::Null),
                    );
                    o.set(
                        "broke_record",
                        Json::Bool(row.map(|r| r.broke_record).unwrap_or(false)),
                    );
                    o.set("suspect", Json::Bool(flags[i]));
                    o.set("score_ok", Json::Bool(row.map(|r| r.score_value.is_some()).unwrap_or(false)));
                    o.set("registered", Json::Bool(true));
                    entries.push(o);
                }
            }
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            // v1.9.8：顶层补 is_team / unit。前端一直读这两个字段，
            // 而旧实现只把它们藏在 event 里，导致集体项目按个人列渲染。
            o.set(
                "is_team",
                Json::Bool(ev.get("is_team").and_then(|v| v.as_bool()).unwrap_or(false)),
            );
            o.set("unit", Json::s(unit.clone()));
            o.set("event", ev.clone());
            o.set("record_text", record_text);
            o.set("entries", Json::Arr(entries));
            Ok(o)
        })
    }

    // -----------------------------------------------------------------------
    // v1.9.8：成绩公布表导入 + AI 助手配置
    // -----------------------------------------------------------------------

    /// 项目名归一化：把学校表格里的各种写法压到同一个口径。
    ///
    /// 需要吸收的差异（都来自真实表格）：
    ///   「男子4乘100米决赛」「男子4*100米」「男子4×100米接力」→ 同一个项目
    ///   「一分钟仰卧起坐」→「仰卧起坐」
    ///   「毽球」↔「沙包」（学校同一项目两种叫法）
    fn norm_project_name(s: &str) -> String {
        let mut t: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        for noise in ["决赛", "预赛", "复赛", "初中组", "高中组", "年级组"] {
            t = t.replace(noise, "");
        }
        for c in ['×', 'X', 'x', '*', '＊', '乘'] {
            t = t.replace(c, "x");
        }
        t = t.replace('（', "(").replace('）', ")");
        t = t.replace("一分钟仰卧起坐", "仰卧起坐");
        t = t.replace("毽球", "沙包");
        t = t.trim_end_matches("接力").trim().to_string();
        t
    }

    /// 拆出「男子/女子」前缀，供跨性别写法匹配（系统里可能是「通用」项目）。
    fn split_gender(s: &str) -> (&str, Option<&'static str>) {
        if let Some(r) = s.strip_prefix("男子") {
            (r, Some("男"))
        } else if let Some(r) = s.strip_prefix("女子") {
            (r, Some("女"))
        } else if let Some(r) = s.strip_prefix('男') {
            (r, Some("男"))
        } else if let Some(r) = s.strip_prefix('女') {
            (r, Some("女"))
        } else {
            (s, None)
        }
    }

    /// 按名称在项目表里找最合适的一个。
    ///
    /// 打分优先级：完全同名 > 去掉男女前缀后同名（且性别相容）> 互相包含。
    /// 不用编辑距离 —— 项目名短且高度相似，编辑距离容易把 100 米和 200 米判成同一个。
    fn match_event_by_name<'a>(
        name: &str,
        events: &'a [crate::core::model::Event],
    ) -> Option<&'a crate::core::model::Event> {
        let want = Self::norm_project_name(name);
        if want.is_empty() {
            return None;
        }
        let (want_base, want_g) = Self::split_gender(&want);
        let mut best: Option<(&crate::core::model::Event, i32)> = None;
        for ev in events {
            let have = Self::norm_project_name(&ev.name);
            let (have_base, _) = Self::split_gender(&have);
            let gender_ok = match (want_g, ev.gender.as_str()) {
                (Some("男"), "女子") | (Some("女"), "男子") => false,
                _ => true,
            };
            let score = if have == want {
                100
            } else if gender_ok && have_base == want_base && !want_base.is_empty() {
                80
            } else if gender_ok
                && (have.contains(&want) || want.contains(&have))
                && (have.len() as i32 - want.len() as i32).abs() <= 4
            {
                50
            } else {
                0
            };
            if score > 0 && best.map(|(_, b)| score > b).unwrap_or(true) {
                best = Some((ev, score));
            }
        }
        best.map(|(e, _)| e)
    }

    /// 班级原始值 → (年级, 班号)。纯数字班号时用表内组别补年级。
    fn resolve_class(raw: &str, group_hint: &str, grades: &[String]) -> Option<(String, i64)> {
        if let Some(v) = crate::core::baoming::parse_class(raw) {
            return Some(v);
        }
        let n = raw
            .trim()
            .trim_end_matches('班')
            .trim()
            .parse::<i64>()
            .ok()
            .filter(|n| *n > 0)?;
        if grades.iter().any(|g| g == group_hint) {
            return Some((group_hint.to_string(), n));
        }
        None
    }

    /// 导入《成绩公布表》：整本工作簿，每个 sheet 一个项目。
    ///
    /// `dry_run=true` 只匹配、出报告，不落盘。老师先看清「哪些行没对上」，
    /// 改完表再导一次，避免闷头写入一堆错行。
    ///
    /// 与 `/api/import/scores` 的分工：那个只处理**当前项目**的两列
    /// （姓名,成绩）；这个一次吃整本、自己分派项目。
    pub fn import_scoresheet(&self, bytes: &[u8], dry_run: bool) -> Result<Json, ApiErr> {
        let rows = crate::core::scoresheet::parse_workbook(bytes)?;
        self.import_rows(&rows, dry_run)
    }

    /// v1.9.10：AI 粘贴文本导入。
    ///
    /// 文本先被切成与成绩公布表**同构**的中性行（项目/班级/姓名/成绩），
    /// 再走下面同一段匹配与落盘 —— 两条入口共用一套规则，不会出现
    /// 「xlsx 能对上、粘贴对不上」。
    pub fn import_ai_table(&self, text: &str, dry_run: bool) -> Result<Json, ApiErr> {
        let rows = crate::core::ai_table::parse_text(text)?;
        self.import_rows(&rows, dry_run)
    }

    /// 年级缺省：请求里指定了就用；否则取学生最多的年级。
    fn pick_grade(d: &Data, want: &str) -> String {
        let want = want.trim();
        if !want.is_empty() {
            return want.to_string();
        }
        let mut best: Option<(String, usize)> = None;
        for g in &d.settings.grades {
            let n = d.students.iter().filter(|s| s.grade == *g).count()
                + d.results.iter().filter(|r| r.grade == *g).count();
            if best.as_ref().map(|(_, b)| n > *b).unwrap_or(true) {
                best = Some((g.clone(), n));
            }
        }
        best.map(|(g, _)| g)
            .or_else(|| d.settings.grades.first().cloned())
            .unwrap_or_else(|| "初二".to_string())
    }

    /// v1.9.10：团体总分表（项目 × 班级矩阵），供报表页预览。
    pub fn total_table(&self, grade: &str) -> Json {
        self.read(|d| {
            let g = Self::pick_grade(d, grade);
            let t = crate::core::summary::build(d, &g);
            let num = |v: &f64| Json::Num((v * 10.0).round() / 10.0);
            let mut o = Json::obj();
            o.set("grade", Json::s(t.grade.clone()));
            o.set("title", Json::s(t.title.clone()));
            o.set(
                "classes",
                Json::arr(t.classes.iter().map(|c| Json::s(t.class_label(*c)))),
            );
            o.set(
                "rows",
                Json::arr(t.rows.iter().map(|r| {
                    let mut x = Json::obj();
                    x.set("label", Json::s(r.label.clone()));
                    x.set(
                        "cells",
                        Json::arr(r.cells.iter().map(|c| match c {
                            Some(v) => num(v),
                            None => Json::Null,
                        })),
                    );
                    x
                })),
            );
            o.set("totals", Json::arr(t.totals.iter().map(num)));
            o.set("ranks", Json::arr(t.ranks.iter().map(|v| Json::Int(*v))));
            o.set(
                "pending",
                Json::arr(t.pending.iter().map(|s| Json::s(s.clone()))),
            );
            o.set(
                "empty_rows",
                Json::arr(t.empty_rows.iter().map(|s| Json::s(s.clone()))),
            );
            o.set("class_source", Json::s(t.class_source));
            o.set(
                "grades",
                Json::arr(d.settings.grades.iter().map(|s| Json::s(s.clone()))),
            );
            o
        })
    }

    /// v1.9.10：导出团体总分表 xlsx（文件名, 字节流）。
    pub fn total_table_xlsx(&self, grade: &str) -> (String, Vec<u8>) {
        self.read(|d| {
            let g = Self::pick_grade(d, grade);
            let t = crate::core::summary::build(d, &g);
            (
                format!("{}团体总分表.xlsx", t.grade),
                crate::core::summary::to_xlsx(&t),
            )
        })
    }

    fn import_rows(
        &self,
        rows: &[crate::core::scoresheet::RawRow],
        dry_run: bool,
    ) -> Result<Json, ApiErr> {
        struct Planned {
            event_id: i64,
            event_name: String,
            student_id: Option<i64>,
            grade: String,
            class_no: Option<i64>,
            name: String,
            class_raw: String,
            score_text: String,
            score_value: f64,
        }

        let mut plan: Vec<Planned> = Vec::new();
        let mut unmatched_projects: Vec<Json> = Vec::new();
        let mut missing_students: Vec<Json> = Vec::new();
        let mut ambiguous: Vec<Json> = Vec::new();
        let mut invalid_scores: Vec<Json> = Vec::new();

        self.read(|d| {
            for r in rows {
                // ---- 项目：sheet 名优先，表内「项目：」兜底 ----
                let ev = Self::match_event_by_name(&r.project, &d.events)
                    .or_else(|| Self::match_event_by_name(&r.project_hint, &d.events));
                let Some(ev) = ev.cloned() else {
                    let mut o = Json::obj();
                    o.set("sheet", Json::s(r.sheet.clone()));
                    o.set("project", Json::s(r.project.clone()));
                    o.set("hint", Json::s(r.project_hint.clone()));
                    o.set("score", Json::s(r.score_text.clone()));
                    unmatched_projects.push(o);
                    continue;
                };

                // ---- 成绩：按项目单位解析，解析不了的单独列出 ----
                let Some(val) = crate::core::scoring::parse_score(&r.score_text, &ev.unit) else {
                    let mut o = Json::obj();
                    o.set("sheet", Json::s(r.sheet.clone()));
                    o.set("event", Json::s(ev.name.clone()));
                    o.set("name", Json::s(r.name.clone()));
                    o.set("score", Json::s(r.score_text.clone()));
                    o.set("reason", Json::s(format!("按「{}」解析不了", ev.unit)));
                    invalid_scores.push(o);
                    continue;
                };

                // ---- 集体项目：按班级 ----
                if ev.is_team {
                    let Some((g, c)) = Self::resolve_class(&r.class_raw, &r.group, &d.settings.grades)
                    else {
                        let mut o = Json::obj();
                        o.set("sheet", Json::s(r.sheet.clone()));
                        o.set("event", Json::s(ev.name.clone()));
                        o.set("class", Json::s(r.class_raw.clone()));
                        o.set("score", Json::s(r.score_text.clone()));
                        o.set("reason", Json::s("班级无法识别"));
                        missing_students.push(o);
                        continue;
                    };
                    plan.push(Planned {
                        event_id: ev.id,
                        event_name: ev.name.clone(),
                        student_id: None,
                        grade: g,
                        class_no: Some(c),
                        name: String::new(),
                        class_raw: r.class_raw.clone(),
                        score_text: r.score_text.clone(),
                        score_value: val,
                    });
                    continue;
                }

                if r.name.is_empty() {
                    let mut o = Json::obj();
                    o.set("sheet", Json::s(r.sheet.clone()));
                    o.set("event", Json::s(ev.name.clone()));
                    o.set("class", Json::s(r.class_raw.clone()));
                    o.set("score", Json::s(r.score_text.clone()));
                    o.set("reason", Json::s("个人项目缺姓名"));
                    missing_students.push(o);
                    continue;
                }

                // ---- 个人项目：姓名 + 班级 ----
                let cands: Vec<crate::core::model::Student> = d
                    .students
                    .iter()
                    .filter(|s| s.name == r.name)
                    .cloned()
                    .collect();
                if cands.is_empty() {
                    let mut o = Json::obj();
                    o.set("sheet", Json::s(r.sheet.clone()));
                    o.set("event", Json::s(ev.name.clone()));
                    o.set("name", Json::s(r.name.clone()));
                    o.set("class", Json::s(r.class_raw.clone()));
                    o.set("score", Json::s(r.score_text.clone()));
                    o.set("reason", Json::s("系统里没有这个姓名"));
                    missing_students.push(o);
                    continue;
                }
                let mut chosen: Option<crate::core::model::Student> = None;
                let mut why = String::new();
                if cands.len() == 1 {
                    chosen = Some(cands[0].clone());
                } else {
                    match Self::resolve_class(&r.class_raw, &r.group, &d.settings.grades) {
                        Some((g, c)) => {
                            let f: Vec<&crate::core::model::Student> = cands
                                .iter()
                                .filter(|s| s.grade == g && s.class_no == c)
                                .collect();
                            if f.len() == 1 {
                                chosen = Some(f[0].clone());
                            } else if f.is_empty() {
                                why = format!("同名 {} 人，没有 {}{} 班的", cands.len(), g, c);
                            } else {
                                why = format!("{}{} 班有 {} 个「{}」", g, c, f.len(), r.name);
                            }
                        }
                        None => {
                            why = format!("同名 {} 人，班级「{}」无法识别", cands.len(), r.class_raw)
                        }
                    }
                }
                let Some(stu) = chosen else {
                    let mut o = Json::obj();
                    o.set("sheet", Json::s(r.sheet.clone()));
                    o.set("event", Json::s(ev.name.clone()));
                    o.set("name", Json::s(r.name.clone()));
                    o.set("class", Json::s(r.class_raw.clone()));
                    o.set("score", Json::s(r.score_text.clone()));
                    o.set("reason", Json::s(why));
                    ambiguous.push(o);
                    continue;
                };
                plan.push(Planned {
                    event_id: ev.id,
                    event_name: ev.name.clone(),
                    student_id: Some(stu.id),
                    grade: stu.grade.clone(),
                    class_no: Some(stu.class_no),
                    name: stu.name.clone(),
                    class_raw: r.class_raw.clone(),
                    score_text: r.score_text.clone(),
                    score_value: val,
                });
            }
        });

        let mut written = 0i64;
        let mut reg_added = 0i64;
        if !dry_run {
            self.write(|d| {
                for p in &plan {
                    if let Some(sid) = p.student_id {
                        if !d
                            .registrations
                            .iter()
                            .any(|r| r.event_id == p.event_id && r.student_id == sid)
                        {
                            let id = d.next_reg_id;
                            d.next_reg_id += 1;
                            d.registrations.push(Registration {
                                id,
                                event_id: p.event_id,
                                student_id: sid,
                                note: "成绩表导入自动补报名".into(),
                            });
                            reg_added += 1;
                        }
                    }
                    let pos = d.results.iter().position(|r| {
                        r.event_id == p.event_id
                            && r.student_id == p.student_id
                            && r.grade == p.grade
                            && r.class_no == p.class_no
                    });
                    if let Some(i) = pos {
                        let row = &mut d.results[i];
                        row.score_text = p.score_text.clone();
                        row.score_value = Some(p.score_value);
                        row.rank = None;
                        row.points = None;
                        row.broke_record = false;
                    } else {
                        let id = d.next_result_id;
                        d.next_result_id += 1;
                        d.results.push(DomainResult {
                            id,
                            event_id: p.event_id,
                            student_id: p.student_id,
                            grade: p.grade.clone(),
                            class_no: p.class_no,
                            score_text: p.score_text.clone(),
                            score_value: Some(p.score_value),
                            rank: None,
                            points: None,
                            broke_record: false,
                        });
                    }
                    written += 1;
                }
                Ok(())
            })?;
        }

        // 按项目汇总，前端直接显示「男子100米 × 12 条」
        let mut by_event: Vec<(String, i64)> = Vec::new();
        for p in &plan {
            if let Some(x) = by_event.iter_mut().find(|(n, _)| *n == p.event_name) {
                x.1 += 1;
            } else {
                by_event.push((p.event_name.clone(), 1));
            }
        }
        let detail: Vec<Json> = plan
            .iter()
            .take(300)
            .map(|p| {
                let mut o = Json::obj();
                o.set("event", Json::s(p.event_name.clone()));
                let who = if p.name.is_empty() {
                    p.class_raw.clone()
                } else {
                    format!("{} {}", p.name, p.class_raw)
                };
                o.set("who", Json::s(who));
                o.set("score", Json::s(p.score_text.clone()));
                o
            })
            .collect();

        let mut out = Json::obj();
        out.set("dry_run", Json::Bool(dry_run));
        out.set("rows", Json::Int(rows.len() as i64));
        out.set("matched", Json::Int(plan.len() as i64));
        out.set("written", Json::Int(written));
        out.set("registrations_added", Json::Int(reg_added));
        out.set(
            "by_event",
            Json::arr(by_event.into_iter().map(|(n, c)| {
                let mut o = Json::obj();
                o.set("event", Json::s(n));
                o.set("count", Json::Int(c));
                o
            })),
        );
        out.set("unmatched_projects", Json::Arr(unmatched_projects));
        out.set("missing_students", Json::Arr(missing_students));
        out.set("ambiguous", Json::Arr(ambiguous));
        out.set("invalid_scores", Json::Arr(invalid_scores));
        out.set("detail", Json::Arr(detail));
        Ok(out)
    }

    // -----------------------------------------------------------------------
    // v1.9.8：AI 助手（Agnes）
    // -----------------------------------------------------------------------

    pub fn get_ai_config(&self) -> Json {
        crate::core::ai::AiConfig::load(&self.data_dir()).to_json()
    }

    pub fn set_ai_config(&self, body: &Json) -> Result<Json, ApiErr> {
        let mut c = crate::core::ai::AiConfig::load(&self.data_dir());
        if let Some(v) = body.get_str("base_url") {
            let v = v.trim().trim_end_matches('/');
            if !v.is_empty() {
                c.base_url = v.to_string();
            }
        }
        if let Some(v) = body.get_str("model") {
            if !v.trim().is_empty() {
                c.model = v.trim().to_string();
            }
        }
        if let Some(v) = body.get_str("api_key") {
            // 允许清空（改为空串 = 停用 AI），但不允许写成空白
            c.api_key = v.trim().to_string();
        }
        if let Some(v) = body.get("enabled").and_then(|v| v.as_bool()) {
            c.enabled = v;
        }
        c.save(&self.data_dir()).map_err(ApiErr::new)?;
        Ok(c.to_json())
    }

    /// 给 AI 的现场快照：项目进度 + 班级名单概况。
    ///
    /// 刻意只给聚合量、不给几百个学生明细 —— 一是省 token，
    /// 二是明细可以让模型用 action 让前端去查，避免把全校名单塞进上下文。
    pub fn ai_context(&self) -> Json {
        self.read(|d| {
            let mut evs: Vec<Json> = Vec::new();
            for e in &d.events {
                let reg = d.registrations.iter().filter(|r| r.event_id == e.id).count();
                let scored = d
                    .results
                    .iter()
                    .filter(|r| r.event_id == e.id && !r.score_text.trim().is_empty())
                    .count();
                let mut o = Json::obj();
                o.set("id", Json::Int(e.id));
                o.set("name", Json::s(e.name.clone()));
                o.set("unit", Json::s(e.unit.clone()));
                o.set("gender", Json::s(e.gender.clone()));
                o.set("is_team", Json::Bool(e.is_team));
                o.set("record", e.record.map(Json::Num).unwrap_or(Json::Null));
                // 集体项目常没有个人报名（成绩表直接按班记），
                // 用「已录条数」兜底当分母，否则进度永远显示未完成。
                let denom = if e.is_team { reg.max(scored) } else { reg };
                o.set("registered", Json::Int(denom as i64));
                o.set("scored", Json::Int(scored as i64));
                o.set("done", Json::Bool(denom > 0 && scored >= denom));
                evs.push(o);
            }
            let mut classes: Vec<(String, i64, i64, i64)> = Vec::new();
            for s in &d.students {
                let key = (s.grade.clone(), s.class_no);
                let has_reg = d.registrations.iter().any(|r| r.student_id == s.id);
                match classes.iter_mut().find(|c| c.0 == key.0 && c.1 == key.1) {
                    Some(c) => {
                        c.2 += 1;
                        if has_reg {
                            c.3 += 1;
                        }
                    }
                    None => classes.push((
                        key.0.clone(),
                        key.1,
                        1,
                        if has_reg { 1 } else { 0 },
                    )),
                }
            }
            classes.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
            let cls: Vec<Json> = classes
                .iter()
                .map(|(g, n, total, reg)| {
                    let mut o = Json::obj();
                    o.set("grade", Json::s(g.clone()));
                    o.set("class_no", Json::Int(*n));
                    o.set("students", Json::Int(*total));
                    o.set("with_registration", Json::Int(*reg));
                    o.set("without_registration", Json::Int(total - reg));
                    o
                })
                .collect();
            let mut o = Json::obj();
            o.set("students", Json::Int(d.students.len() as i64));
            o.set("events", Json::Int(d.events.len() as i64));
            o.set("registrations", Json::Int(d.registrations.len() as i64));
            o.set("results", Json::Int(d.results.iter().filter(|r| !r.score_text.trim().is_empty()).count() as i64));
            o.set("grades", Json::arr(d.settings.grades.iter().map(|g| Json::s(g.clone()))));
            o.set("event_list", Json::Arr(evs));
            o.set("classes", Json::Arr(cls));
            o
        })
    }

    /// 批量录入成绩（校验报名，逐条解析；格式错误记为无效）。
    pub fn save_results_bulk(&self, event_id: i64, entries: &[Json]) -> Result<Json, ApiErr> {
        let mut valid = 0i64;
        let mut invalid = 0i64;
        let mut updated = 0i64;
        let mut touched: Vec<Json> = Vec::new();
        self.write(|d| {
            let ev = d
                .events
                .iter()
                .find(|e| e.id == event_id)
                .ok_or_else(|| ApiErr::with_status("项目不存在", 404))?
                .clone();
            for e in entries {
                let score_text = e.get_str("score_text").unwrap_or_default().trim().to_string();
                let score_value = if score_text.is_empty() {
                    None
                } else {
                    scoring::parse_score(&score_text, &ev.unit)
                };
                if !score_text.is_empty() && score_value.is_none() {
                    invalid += 1;
                }
                if let Some(sid) = e.get("student_id").and_then(|v| v.as_i64()) {
                    // 个人（v1.2：改用 if let 绑定，消除 unwrap）
                    if !d
                        .registrations
                        .iter()
                        .any(|r| r.event_id == event_id && r.student_id == sid)
                    {
                        return Err(ApiErr::new("存在未报名该项目的学生，请先在报名管理中完成报名"));
                    }
                    let stu = d.students.iter().find(|s| s.id == sid).cloned();
                    let grade = stu.as_ref().map(|s| s.grade.clone()).unwrap_or_default();
                    let class_no = stu.as_ref().map(|s| s.class_no);
                    if let Some(row) = d
                        .results
                        .iter_mut()
                        .find(|r| r.event_id == event_id && r.student_id == Some(sid))
                    {
                        row.score_text = score_text.clone();
                        row.score_value = score_value;
                        row.rank = None;
                        row.points = None;
                        row.broke_record = false;
                    } else {
                        let r = DomainResult {
                            id: d.next_result_id,
                            event_id,
                            student_id: Some(sid),
                            grade,
                            class_no,
                            score_text: score_text.clone(),
                            score_value,
                            rank: None,
                            points: None,
                            broke_record: false,
                        };
                        d.next_result_id += 1;
                        d.results.push(r);
                    }
                    updated += 1;
                    if score_value.is_some() {
                        valid += 1;
                    }
                    touched.push(Json::Int(sid));
                } else if let Some(c) = e.get_i64("class_no") {
                    // 集体
                    let grade = e
                        .get_str("grade")
                        .unwrap_or_default()
                        .trim()
                        .to_string();
                    if grade.is_empty() {
                        return Err(ApiErr::new("集体成绩缺少年级"));
                    }
                    if !d.registrations.iter().any(|r| {
                        r.event_id == event_id && d.students.iter().any(|s| {
                            s.id == r.student_id && s.grade == grade && s.class_no == c
                        })
                    }) {
                        return Err(ApiErr::new(format!("{}{}班未报名该项目", grade, c)));
                    }
                    if let Some(row) = d.results.iter_mut().find(|r| {
                        r.event_id == event_id
                            && r.student_id.is_none()
                            && r.grade == grade
                            && r.class_no == Some(c)
                    }) {
                        row.score_text = score_text.clone();
                        row.score_value = score_value;
                        row.rank = None;
                        row.points = None;
                        row.broke_record = false;
                    } else {
                        let r = DomainResult {
                            id: d.next_result_id,
                            event_id,
                            student_id: None,
                            grade: grade.clone(),
                            class_no: Some(c),
                            score_text: score_text.clone(),
                            score_value,
                            rank: None,
                            points: None,
                            broke_record: false,
                        };
                        d.next_result_id += 1;
                        d.results.push(r);
                    }
                    updated += 1;
                    if score_value.is_some() {
                        valid += 1;
                    }
                    touched.push(
                        Json::obj()
                            .set("grade", Json::s(grade.clone()))
                            .set("class_no", Json::Int(c))
                            .clone(),
                    );
                }
            }
            Ok(())
        })?;
        log_info!("api", "保存成绩：项目 id={} 共更新 {} 条", event_id, updated);
        crate::core::audit::record(
            "admin",
            "results.save",
            &format!("保存成绩：项目 id={} 共 {} 条", event_id, updated),
        );
        self.publish(
            EventKind::ResultsSaved,
            Json::obj()
                .set("event_id", Json::Int(event_id))
                .set("updated", Json::Int(updated))
                .clone(),
        );
        let _ = touched;
        let mut o = Json::obj();
        o.set("ok", Json::Bool(true));
        o.set("updated", Json::Int(updated));
        o.set("valid", Json::Int(valid));
        o.set("invalid", Json::Int(invalid));
        Ok(o)
    }

    /// 计算某项目名次与得分（返回 [有效条数, 得名次数]）。
    pub fn compute_event_inner(&self, event_id: i64) -> Result<(usize, usize), ApiErr> {
        let (scored, ranked) = self.write(|d| {
            let ev = d
                .events
                .iter()
                .find(|e| e.id == event_id)
                .ok_or_else(|| ApiErr::with_status("项目不存在", 404))?
                .clone();
            let st = d.settings.clone();
            let rows: Vec<usize> = d
                .results
                .iter()
                .enumerate()
                .filter(|(_, r)| r.event_id == event_id)
                .map(|(i, _)| i)
                .collect();
            let values: Vec<Option<f64>> =
                rows.iter().map(|&i| d.results[i].score_value).collect();
            let ranked_list = scoring::rank_entries(&values, &ev, &st);
            for (local, r) in rows.iter().enumerate() {
                let hit = ranked_list.iter().find(|x| x.entry_index == local);
                let row = &mut d.results[*r];
                match hit {
                    Some(h) => {
                        row.rank = Some(h.rank);
                        row.points = Some(h.points);
                        row.broke_record = h.broke_record;
                    }
                    None => {
                        row.rank = None;
                        row.points = None;
                        row.broke_record = false;
                    }
                }
            }
            let scored = values.iter().filter(|v| v.is_some()).count();
            Ok((scored, ranked_list.len()))
        })?;
        log_info!(
            "api",
            "计算名次赋分：项目 id={} 有效成绩 {} 条，赋分 {} 条",
            event_id,
            scored,
            ranked
        );
        self.publish(
            EventKind::ResultsComputed,
            Json::obj()
                .set("event_id", Json::Int(event_id))
                .set("scored", Json::Int(scored as i64))
                .set("ranked", Json::Int(ranked as i64))
                .clone(),
        );
        Ok((scored, ranked))
    }

    /// 单项目成绩模板 CSV（编号,姓名,成绩）。
    pub fn scores_template(&self, event_id: i64) -> Result<String, ApiErr> {
        let view = self.results_view(event_id)?;
        let mut lines = vec!["编号,姓名,成绩".to_string()];
        if let Some(Json::Arr(entries)) = view.get("entries") {
            for e in entries {
                let name = e.get("label").and_then(|v| v.as_str()).unwrap_or("");
                lines.push(csv_row(&[String::new(), name.to_string(), String::new()]));
            }
        }
        Ok(lines.join("\n") + "\n")
    }

    pub fn clear_event_results(&self, event_id: i64, confirmed: bool) -> Result<Json, ApiErr> {
        if !confirmed {
            let n = self.read(|d| d.results.iter().filter(|r| r.event_id == event_id).count());
            let mut pv = Json::obj();
            pv.set("results", Json::Int(n as i64));
            return Err(ApiErr::with_status("需要确认", 428).with_data(pv));
        }
        let cleared = self.write(|d| {
            let rows: Vec<Json> = d
                .results
                .iter()
                .filter(|r| r.event_id == event_id)
                .map(result_to_json)
                .collect();
            if rows.is_empty() {
                return Err(ApiErr::new("该项目还没有成绩"));
            }
            let removed = rows.len();
            let mut p = Json::obj();
            p.set("event_id", Json::Int(event_id));
            p.set("results", Json::Arr(rows));
            Self::push_undo(d, "clear_results", p);
            d.results.retain(|r| r.event_id != event_id);
            Ok(removed)
        })?;
        log_warn!("api", "清空成绩：项目 id={}（共 {} 条）", event_id, cleared);
        crate::core::audit::record(
            "admin",
            "results.clear",
            &format!("清空项目成绩：项目 id={}（影响 {} 条）", event_id, cleared),
        );
        let mut p = Json::obj();
        p.set("event_id", Json::Int(event_id));
        self.publish(EventKind::ResultsCleared, p);
        let mut o = Json::obj();
        o.set("ok", Json::Bool(true));
        o.set("message", Json::s("已清空该项目成绩，可撤销"));
        Ok(o)
    }

    // ------------------------------------------------------------------
    // 报表
    // ------------------------------------------------------------------

    pub fn report_table(&self, grade: Option<&str>) -> Json {
        self.read(|d| {
            let grades: Vec<String> = match grade {
                Some(g) => vec![g.to_string()],
                None => d.settings.grades.clone(),
            };
            let mut table = Json::obj();
            for g in &grades {
                table.set(g, Json::Arr(scoring::grade_total_table(d, g)));
            }
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("table", table);
            o.set(
                "grades",
                Json::arr(grades.iter().map(|g| Json::s(g.clone()))),
            );
            o
        })
    }

    /// 全量报表 JSON（替代 Python 版 xlsx 报表）。
    pub fn report_json(&self) -> Json {
        self.read(|d| {
            let mut grades_obj = Json::obj();
            for g in &d.settings.grades {
                grades_obj.set(g, Json::Arr(scoring::grade_total_table(d, g)));
            }
            let mut events_arr = Vec::new();
            for ev in &d.events {
                let rows: Vec<Json> = d
                    .results
                    .iter()
                    .filter(|r| r.event_id == ev.id && r.rank.is_some())
                    .map(|r| {
                        let mut o = Json::obj();
                        let label = if let Some(sid) = r.student_id {
                            d.students
                                .iter()
                                .find(|s| s.id == sid)
                                .map(|s| format!("{}（{}）", s.name, s.class_name()))
                                .unwrap_or_else(|| format!("ID {}", sid))
                        } else {
                            format!("{}{}班", r.grade, r.class_no.unwrap_or(0))
                        };
                        o.set("label", Json::s(label));
                        o.set("score_text", Json::s(r.score_text.clone()));
                        o.set("rank", r.rank.map(Json::Int).unwrap_or(Json::Null));
                        o.set("points", r.points.map(Json::Num).unwrap_or(Json::Null));
                        o.set("broke_record", Json::Bool(r.broke_record));
                        o
                    })
                    .collect();
                if !rows.is_empty() {
                    let mut e = event_to_json(ev);
                    e.set("rows", Json::Arr(rows));
                    events_arr.push(e);
                }
            }
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("generated_at", Json::s(store::now_string()));
            o.set("grade_totals", grades_obj);
            o.set("events", Json::Arr(events_arr));
            o
        })
    }

    // ------------------------------------------------------------------
    // 备份 / 撤销 / 导入导出
    // ------------------------------------------------------------------

    pub fn backup(&self, label: &str) -> Result<String, ApiErr> {
        let d = self.store.data.lock_recover().clone();
        let dir = self.data_dir().join("backups");
        std::fs::create_dir_all(&dir).map_err(|e| ApiErr::new(format!("创建备份目录失败：{}", e)))?;
        let stamp = store::now_string().replace(['-', ' ', ':'], "_");
        let path = dir.join(format!("backup_{}_{}.json", stamp, label));
        std::fs::write(&path, d.to_json().to_string_pretty())
            .map_err(|e| ApiErr::new(format!("备份写入失败：{}", e)))?;
        self.prune_backups();
        log_info!("api", "创建备份：{}", path.display());
        Ok(path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default())
    }

    fn prune_backups(&self) {
        let dir = self.data_dir().join("backups");
        let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .map(|e| e.path())
                    .filter(|p| {
                        p.file_name()
                            .map(|n| {
                                let n = n.to_string_lossy();
                                n.starts_with("backup_") && n.ends_with(".json")
                            })
                            .unwrap_or(false)
                    })
                    .collect()
            })
            .unwrap_or_default();
        files.sort();
        while files.len() > self.backup_keep {
            let path = files.remove(0);
            let _ = std::fs::remove_file(path);
        }
    }

    pub fn list_backups(&self) -> Json {
        let dir = self.data_dir().join("backups");
        let mut items: Vec<(String, u64, String)> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.filter_map(|e| e.ok()) {
                let name = e.file_name().to_string_lossy().into_owned();
                if name.starts_with("backup_") && name.ends_with(".json") {
                    let size = e.metadata().map(|m| m.len()).unwrap_or(0);
                    items.push((name, size, store::now_string()));
                }
            }
        }
        items.sort_by(|a, b| b.0.cmp(&a.0));
        let mut o = Json::obj();
        o.set("ok", Json::Bool(true));
        o.set(
            "backups",
            Json::arr(items.iter().map(|(file, size, time)| {
                let mut e = Json::obj();
                e.set("file", Json::s(file.clone()));
                e.set("size", Json::Int(*size as i64));
                e.set("time", Json::s(time.clone()));
                e
            })),
        );
        o
    }

    /// 查看栈顶（最近一次）可撤销操作。
    pub fn peek_undo(&self) -> Json {
        self.read(|d| {
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("depth", Json::Int(d.undo_stack.len() as i64));
            match d.undo_stack.last() {
                Some(u) => {
                    let mut e = Json::obj();
                    e.set("time", Json::s(u.time.clone()));
                    e.set("action", Json::s(u.action.clone()));
                    e.set("description", Json::s(undo_description(&u.action, &u.payload)));
                    o.set("undo", e);
                }
                None => {
                    o.set("undo", Json::Null);
                }
            }
            o
        })
    }

    /// 完整撤销历史（v1.2 新增）：栈顶在前，便于前端展示。
    pub fn undo_history(&self) -> Json {
        self.read(|d| {
            let mut arr = Vec::new();
            // 逆序输出：最近的在最前
            for u in d.undo_stack.iter().rev() {
                let mut e = Json::obj();
                e.set("time", Json::s(u.time.clone()));
                e.set("action", Json::s(u.action.clone()));
                e.set("description", Json::s(undo_description(&u.action, &u.payload)));
                arr.push(e);
            }
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("depth", Json::Int(d.undo_stack.len() as i64));
            o.set("keep", Json::Int(d.undo_stack.len() as i64)); // 兼容占位
            o.set("history", Json::Arr(arr));
            o
        })
    }

    pub fn undo_now(&self) -> Result<Json, ApiErr> {
        self.write(|d| -> Result<Json, ApiErr> {
            let u = d
                .undo_stack
                .pop()
                .ok_or_else(|| ApiErr::with_status("没有可撤销的操作", 404))?;
            let p = &u.payload;
            match u.action.as_str() {
                "delete_event" => {
                    if let Some(ev) = p.get("event").and_then(event_from_json) {
                        let id = ev.id;
                        if d.events.iter().all(|e| e.id != id) {
                            d.events.push(ev);
                            d.next_event_id = d.next_event_id.max(id + 1);
                        }
                    }
                    if let Some(Json::Arr(arr)) = p.get("registrations") {
                        for r in arr {
                            let rid = r.get_i64("id").unwrap_or(0);
                            if d.registrations.iter().all(|x| x.id != rid) {
                                d.registrations.push(Registration {
                                    id: rid,
                                    event_id: r.get_i64("event_id").unwrap_or(0),
                                    student_id: r.get_i64("student_id").unwrap_or(0),
                                    note: r.get_string("note").to_string(),
                                });
                                d.next_reg_id = d.next_reg_id.max(rid + 1);
                            }
                        }
                    }
                    if let Some(Json::Arr(arr)) = p.get("results") {
                        for r in arr {
                            let rid = r.get_i64("id").unwrap_or(0);
                            if d.results.iter().all(|x| x.id != rid) {
                                d.results.push(result_from_json(r));
                                d.next_result_id = d.next_result_id.max(rid + 1);
                            }
                        }
                    }
                }
                "delete_student" => {
                    if let Some(s) = p.get("student").and_then(student_from_json) {
                        let id = s.id;
                        if d.students.iter().all(|x| x.id != id) {
                            d.students.push(s);
                            d.next_student_id = d.next_student_id.max(id + 1);
                        }
                    }
                    if let Some(Json::Arr(arr)) = p.get("registrations") {
                        for r in arr {
                            let rid = r.get_i64("id").unwrap_or(0);
                            if d.registrations.iter().all(|x| x.id != rid) {
                                d.registrations.push(Registration {
                                    id: rid,
                                    event_id: r.get_i64("event_id").unwrap_or(0),
                                    student_id: r.get_i64("student_id").unwrap_or(0),
                                    note: r.get_string("note").to_string(),
                                });
                                d.next_reg_id = d.next_reg_id.max(rid + 1);
                            }
                        }
                    }
                    if let Some(Json::Arr(arr)) = p.get("results") {
                        for r in arr {
                            let rid = r.get_i64("id").unwrap_or(0);
                            if d.results.iter().all(|x| x.id != rid) {
                                d.results.push(result_from_json(r));
                                d.next_result_id = d.next_result_id.max(rid + 1);
                            }
                        }
                    }
                }
                "unregister" => {
                    if let Some(r) = p.get("registration") {
                        let rid = r.get_i64("id").unwrap_or(0);
                        if d.registrations.iter().all(|x| x.id != rid) {
                            d.registrations.push(Registration {
                                id: rid,
                                event_id: r.get_i64("event_id").unwrap_or(0),
                                student_id: r.get_i64("student_id").unwrap_or(0),
                                note: r.get_string("note"),
                            });
                            d.next_reg_id = d.next_reg_id.max(rid + 1);
                        }
                    }
                    if let Some(r) = p.get("result") {
                        let rid = r.get_i64("id").unwrap_or(0);
                        if d.results.iter().all(|x| x.id != rid) {
                            d.results.push(result_from_json(r));
                            d.next_result_id = d.next_result_id.max(rid + 1);
                        }
                    }
                }
                "clear_results" => {
                    if let Some(Json::Arr(arr)) = p.get("results") {
                        for r in arr {
                            let rid = r.get_i64("id").unwrap_or(0);
                            if d.results.iter().all(|x| x.id != rid) {
                                d.results.push(result_from_json(r));
                                d.next_result_id = d.next_result_id.max(rid + 1);
                            }
                        }
                    }
                }
                // v1.9.3：整批快照恢复，一次撤销还原所有报名与连带成绩。
                "clear_registrations" => {
                    if let Some(Json::Arr(arr)) = p.get("registrations") {
                        for r in arr {
                            let rid = r.get_i64("id").unwrap_or(0);
                            if d.registrations.iter().all(|x| x.id != rid) {
                                d.registrations.push(Registration {
                                    id: rid,
                                    event_id: r.get_i64("event_id").unwrap_or(0),
                                    student_id: r.get_i64("student_id").unwrap_or(0),
                                    note: r.get_string("note"),
                                });
                                d.next_reg_id = d.next_reg_id.max(rid + 1);
                            }
                        }
                    }
                    if let Some(Json::Arr(arr)) = p.get("results") {
                        for r in arr {
                            let rid = r.get_i64("id").unwrap_or(0);
                            if d.results.iter().all(|x| x.id != rid) {
                                d.results.push(result_from_json(r));
                                d.next_result_id = d.next_result_id.max(rid + 1);
                            }
                        }
                    }
                }
                "register_many" => {
                    if let Some(Json::Arr(arr)) = p.get("student_ids") {
                        let eid = p.get_i64("event_id").unwrap_or(0);
                        let ids: Vec<i64> =
                            arr.iter().filter_map(|v| v.as_i64()).collect();
                        d.registrations.retain(|r| {
                            !(r.event_id == eid && ids.contains(&r.student_id))
                        });
                    }
                }
                _ => {}
            }
            log_warn!("api", "执行撤销：{}", undo_description(&u.action, &u.payload));
        crate::core::audit::record(
            "admin",
            "undo",
            &format!("撤销操作：{}", undo_description(&u.action, &u.payload)),
        );
            let mut ret = Json::obj();
            ret.set(
                "message",
                Json::s(undo_description(&u.action, &u.payload)),
            );
            Ok(ret)
        })
    }

    pub fn export_all(&self) -> Json {
        self.read(export_all_json)
    }

    /// 全量导入（覆盖现有数据）。
    pub fn import_all(&self, payload: &Json) -> Result<Json, ApiErr> {
        let nd = Data::from_json(payload)
            .ok_or_else(|| ApiErr::new("文件格式不正确：缺少 settings 或数据不完整"))?;
        self.write(|d| {
            *d = nd;
            Ok(())
        })?;
        log_warn!("api", "全量导入：覆盖现有数据");
        crate::core::audit::record("admin", "data.import", "全量导入：覆盖现有数据");
        self.publish(EventKind::DataImported, Json::obj());
        let mut o = Json::obj();
        o.set("ok", Json::Bool(true));
        o.set("message", Json::s("导入完成"));
        Ok(o)
    }

    // ------------------------------------------------------------------
    // 路由注册（核心 API 路由表）
    // ------------------------------------------------------------------

    pub fn routes(self: &Arc<Self>) -> Vec<crate::core::http::Route> {
        let _c = Arc::clone(self);
        let mut v: Vec<crate::core::http::Route> = Vec::new();
        let mut r = |method: &'static str,
                     path: &'static str,
                     h: fn(&Core, &Request) -> Result<Response, ApiErr>| {
            v.push(crate::core::http::Route {
                method,
                path,
                handler: Arc::new(move |core: &Core, req: &Request| Ok(h(core, req).unwrap_or_else(|e| {
                    let mut o = Json::obj();
                    o.set("error", Json::s(e.message.clone()));
                    if let Some(data) = e.data.as_ref() {
                        o.set("confirm_required", Json::Bool(true));
                        o.set("preview", data.clone());
                    }
                    Response::json_with_status(&o, e.status)
                }))),
            });
        };

        r("GET", "/api/meta", |c, _| Ok(Response::json(&c.meta_json())));
        r("GET", "/api/stats", |c, _| Ok(Response::json(&c.stats_json())));
        r("GET", "/api/settings", |c, _| Ok(Response::json(&c.get_settings())));
        r("POST", "/api/settings", |c, req| {
            let body = req.json().map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            Ok(Response::json(&c.set_settings(&body)?))
        });
        // v1.9.8：AI 助手配置与现场快照（前端直连 Agnes，无需后端代理）
        r("GET", "/api/ai/config", |c, _| {
            Ok(Response::json(&c.get_ai_config()))
        });
        r("POST", "/api/ai/config", |c, req| {
            let body = req.json().map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            Ok(Response::json(&c.set_ai_config(&body)?))
        });
        r("GET", "/api/ai/context", |c, _| {
            Ok(Response::json(&c.ai_context()))
        });
        r("POST", "/api/backup", |c, _| {
            let name = c.backup("manual")?;
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("message", Json::s(format!("备份完成：{}", name)));
            Ok(Response::json(&o))
        });
        r("GET", "/api/backups", |c, _| Ok(Response::json(&c.list_backups())));
        r("GET", "/api/undo", |c, _| Ok(Response::json(&c.peek_undo())));
        r("GET", "/api/undo/history", |c, _| {
            Ok(Response::json(&c.undo_history()))
        });
        r("POST", "/api/undo", |c, _| {
            let desc = c.undo_now()?;
            let mut o = Json::obj();
            let dmsg = desc.get_str("message").unwrap_or("撤销完成").to_string();
            let depth = c.read(|d| d.undo_stack.len());
            o.set("ok", Json::Bool(true));
            o.set("message", Json::s(format!("{}，已完成", dmsg)));
            o.set("remaining", Json::Int(depth as i64));
            Ok(Response::json(&o))
        });
        // v1.2：日志诊断接口（读取当天日志尾部）
        r("GET", "/api/logs", |c, req| {
            let n = req
                .query_get("lines")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(200)
                .min(2000);
            let text = crate::core::log::tail(&c.data_dir(), n);
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("lines", Json::Int(n as i64));
            o.set("content", Json::s(text));
            o.set(
                "level",
                Json::s(
                    crate::core::log::current_level()
                        .map(|l| l.tag().to_string())
                        .unwrap_or_else(|| "UNKNOWN".into()),
                ),
            );
            Ok(Response::json(&o))
        });

        r("GET", "/api/events", |c, _| Ok(Response::json(&c.list_events())));
        r("POST", "/api/events", |c, req| {
            let body = req.json().map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            Ok(Response::json(&c.add_event(&body)?).with_status(201))
        });
        r("POST", "/api/events/{id}/update", |c, req| {
            let id = path_i64(req, "id")?;
            let body = req.json().map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            Ok(Response::json(&c.update_event(id, &body)?))
        });
        r("GET", "/api/events/{id}/delete_preview", |c, req| {
            Ok(Response::json(&c.delete_preview_event(path_i64(req, "id")?)?))
        });
        r("DELETE", "/api/events/{id}", |c, req| {
            let id = path_i64(req, "id")?;
            // v1.5.1：开发者模式下视同已确认。
            // 业务层的 `?confirm=1` 预检旨在"防误触"，而 devmode 的三重条件
            // （本机 + 密钥 + 风险确认）已足以说明这是**有意为之**的调试动作；
            // 若仍拦一道，诊断页签上的"清理测试数据"就形同虚设。
            //
            // 补偿措施：devmode 下跳过预检的同时**写一条审计**，把"谁在什么
            // 时候用开发者模式删了哪个项目"钉在哈希链上 —— 便利是用可追溯
            // 换来的，不是白拿的（见《自我约束文档》规则 9 的补充说明）。
            if req.dev_mode && req.query_get("confirm").as_deref() != Some("1") {
                crate::core::audit::record(
                    "devmode",
                    "dev_bypass_confirm",
                    &format!("开发者模式跳过删除预检：项目 #{}", id),
                );
            }
            Ok(Response::json(&c.delete_event(
                id,
                req.query_get("confirm").as_deref() == Some("1") || req.dev_mode,
            )?))
        });

        r("GET", "/api/students", |c, req| {
            /* v1.5.2 修复（踩坑 #37）：空查询串必须视为"不筛选"。
               前端始终以 `?grade=&class_no=` 形式调用（下拉框选"全部"时
               value 为空串），而早先的实现是：
                   query_get("class_no").and_then(|v| v.parse::<i64>().ok())
               `""` 能被成功解析为 `0`，于是变成"筛选 class_no == 0" ——
               而班级号从 1 起，结果恒为空。
               用户看到的现象是：**学生名单页在"全部年级/全部班级"下永远
               显示"暂无学生"**，只有手动挑一个具体班级才看得见人。

               v1.6.0：改用 `query_non_empty` + `query_pos_int` 统一入口。
               后者不光过滤空白，还会把"传了非法值"（如 `class_no=abc`）
               显式报为参数错误 —— 而不是悄悄变成 0 再去库里查空。
               顺带让 `with_code` 有了用武之地（本轮引入的错误码能力）。 */
            let grade = req.query_non_empty("grade");
            let class_no = req.query_pos_int("class_no")?;
            Ok(Response::json(&c.list_students(grade.as_deref(), class_no)))
        });
        r("POST", "/api/students", |c, req| {
            let body = req.json().map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            let s = Student {
                id: 0,
                grade: body.get_string("grade"),
                class_no: body.get_i64("class_no").unwrap_or(0),
                name: body.get_string("name"),
                gender: body.get_string("gender"),
            };
            Ok(Response::json(&c.add_students(&[s])?).with_status(201))
        });
        r("POST", "/api/students/batch", |c, req| {
            let body = req.json().map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            let mut list = Vec::new();
            if let Some(Json::Arr(arr)) = body.get("students") {
                for e in arr {
                    list.push(Student {
                        id: 0,
                        grade: e.get_string("grade"),
                        class_no: e.get_i64("class_no").unwrap_or(0),
                        name: e.get_string("name"),
                        gender: e.get_string("gender"),
                    });
                }
            }
            // v1.1：支持 text 表格文本导入（带表头任意列序，或固定顺序）
            if let Some(text) = body.get_str("text") {
                for e in parse_student_import(text)? {
                    list.push(Student {
                        id: 0,
                        grade: e.get_string("grade"),
                        class_no: e.get_i64("class_no").unwrap_or(0),
                        name: e.get_string("name"),
                        gender: e.get_string("gender"),
                    });
                }
            }
            Ok(Response::json(&c.add_students(&list)?).with_status(201))
        });
        r("GET", "/api/students/{id}/delete_preview", |c, req| {
            Ok(Response::json(&c.delete_preview_student(path_i64(req, "id")?)?))
        });
        r("DELETE", "/api/students/{id}", |c, req| {
            let id = path_i64(req, "id")?;
            // v1.5.1：同 DELETE /api/events/{id}，devmode 下视同已确认并留痕
            if req.dev_mode && req.query_get("confirm").as_deref() != Some("1") {
                crate::core::audit::record(
                    "devmode",
                    "dev_bypass_confirm",
                    &format!("开发者模式跳过删除预检：学生 #{}", id),
                );
            }
            Ok(Response::json(&c.delete_student(
                id,
                req.query_get("confirm").as_deref() == Some("1") || req.dev_mode,
            )?))
        });

        r("GET", "/api/registrations", |c, req| {
            let eid = req
                .query_get("event_id")
                .and_then(|v| v.parse::<i64>().ok())
                .ok_or_else(|| ApiErr::new("缺少 event_id"))?;
            Ok(Response::json(&c.event_registrations(eid)?))
        });
        r("POST", "/api/registrations/clear_preview", |c, req| {
            let body = req.json().map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            Ok(Response::json(&c.clear_registrations_preview(&body)?))
        });
        r("POST", "/api/registrations/clear", |c, req| {
            let body = req.json().map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            if req.dev_mode {
                crate::core::audit::record(
                    "devmode",
                    "dev_clear_registrations",
                    "开发者模式清空报名（跳过二次口令）",
                );
            }
            Ok(Response::json(&c.clear_registrations(&body)?))
        });
        // v1.9.3：可下载的报名表模板（xlsx 默认 / ?fmt=csv）。
        // 表头列由当前系统项目动态生成，填完的同一个文件可直接回传。
        r("GET", "/api/export/baoming_template", |c, req| {
            let events = c.read(|d| d.events.clone());
            if req.query_get("fmt").as_deref() == Some("csv") {
                Ok(Response::download(
                    "报名表模板.csv",
                    "text/csv; charset=utf-8",
                    &crate::core::export::baoming_template_csv(&events),
                ))
            } else {
                Ok(Response::download(
                    "报名表模板.xlsx",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    &crate::core::export::baoming_template_xlsx(&events),
                ))
            }
        });
        // v1.9.7：纯名单模板（姓名/年级/班级/性别/学号，不含项目列）。
        r("GET", "/api/export/roster_template", |c, req| {
            let _ = c;
            if req.query_get("fmt").as_deref() == Some("csv") {
                Ok(Response::download(
                    "名单模板.csv",
                    "text/csv; charset=utf-8",
                    &crate::core::export::roster_template_csv(),
                ))
            } else {
                Ok(Response::download(
                    "名单模板.xlsx",
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    &crate::core::export::roster_template_xlsx(),
                ))
            }
        });
        r("GET", "/api/export/scores_template/{id}", |c, req| {
            let eid = path_i64(req, "id")?;
            Ok(Response::download(
                &format!("成绩模板-{}.csv", eid),
                "text/csv; charset=utf-8",
                c.scores_template(eid)?.as_bytes(),
            ))
        });
        r("POST", "/api/import/scores", |c, req| {
            let body = req.json().map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            let eid = body
                .get_i64("event_id")
                .ok_or_else(|| ApiErr::new("缺少 event_id"))?;
            let text = body.get_str("text").unwrap_or_default();
            let (entries, skipped) = parse_score_import(text, c, eid)?;
            let mut resp = c.save_results_bulk(eid, &entries)?;
            if !skipped.is_empty() {
                resp.set(
                    "skipped_names",
                    Json::arr(skipped.iter().map(|n| Json::s(n.clone()))),
                );
            }
            Ok(Response::json(&resp))
        });
        r("POST", "/api/registrations", |c, req| {
            let body = req.json().map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            let eid = body
                .get_i64("event_id")
                .ok_or_else(|| ApiErr::new("缺少 event_id"))?;
            let sid = body
                .get_i64("student_id")
                .ok_or_else(|| ApiErr::new("缺少 student_id"))?;
            let note = body.get_str("note").unwrap_or_default();
            let force = body.get("force_gender").and_then(|v| v.as_bool()).unwrap_or(false);
            let res = c.register_many(eid, &[sid], note, force)?;
            let added = res.get_i64("added").unwrap_or(0);
            if added > 0 {
                return Ok(Response::json(&{
                    let mut o = Json::obj();
                    o.set("ok", Json::Bool(true));
                    o
                })
                .with_status(201));
            }
            let reason = res
                .get("skipped")
                .and_then(|v| v.as_arr())
                .and_then(|a| a.first())
                .and_then(|e| e.get_str("reason").map(|s| s.to_string()))
                .unwrap_or_else(|| "未知原因".into());
            Err(ApiErr::with_status(reason, 409))
        });
        r("POST", "/api/registrations/bulk", |c, req| {
            let body = req.json().map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            let eid = body
                .get_i64("event_id")
                .ok_or_else(|| ApiErr::new("缺少 event_id"))?;
            let ids: Vec<i64> = body
                .get("student_ids")
                .and_then(|v| v.as_arr())
                .map(|a| a.iter().filter_map(|v| v.as_i64()).collect())
                .unwrap_or_default();
            if ids.is_empty() {
                return Err(ApiErr::new("缺少 event_id 或 student_ids"));
            }
            let note = body.get_str("note").unwrap_or_default();
            let force = body.get("force_gender").and_then(|v| v.as_bool()).unwrap_or(false);
            Ok(Response::json(&c.register_many(eid, &ids, note, force)?))
        });
        r("DELETE", "/api/registrations/{eid}/{sid}", |c, req| {
            let eid = path_i64(req, "eid")?;
            let sid = path_i64(req, "sid")?;
            Ok(Response::json(&c.unregister(sid, eid)?))
        });

        // v1.9.8：各项目录入进度（项目下拉里显示 12/24，并支持只看未录完）
        r("GET", "/api/results/progress", |c, _| {
            let ctx = c.ai_context();
            let mut o = Json::obj();
            o.set(
                "events",
                ctx.get("event_list").cloned().unwrap_or(Json::Arr(Vec::new())),
            );
            Ok(Response::json(&o))
        });
        r("GET", "/api/results", |c, req| {
            let eid = req
                .query_get("event_id")
                .and_then(|v| v.parse::<i64>().ok())
                .ok_or_else(|| ApiErr::new("缺少 event_id"))?;
            Ok(Response::json(&c.results_view(eid)?))
        });
        r("POST", "/api/results/bulk", |c, req| {
            let body = req.json().map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            let eid = body
                .get_i64("event_id")
                .ok_or_else(|| ApiErr::new("缺少 event_id"))?;
            let entries: Vec<Json> = body
                .get("entries")
                .and_then(|v| v.as_arr()).cloned()
                .unwrap_or_default();
            Ok(Response::json(&c.save_results_bulk(eid, &entries)?))
        });
        r("POST", "/api/results/clear", |c, req| {
            let body = req.json().map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            let eid = body
                .get_i64("event_id")
                .ok_or_else(|| ApiErr::new("缺少 event_id"))?;
            // v1.5.1：本接口在路由侧直接传 `true`，本就不走预检；
            // 但"清空成绩"损失面大，devmode 下额外留痕便于事后核对。
            if req.dev_mode {
                crate::core::audit::record(
                    "devmode",
                    "dev_clear_results",
                    &format!("开发者模式清空项目 #{} 成绩", eid),
                );
            }
            Ok(Response::json(&c.clear_event_results(eid, true)?))
        });
        r("POST", "/api/compute", |c, req| {
            let body = req.json().map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            let eid = body
                .get_i64("event_id")
                .ok_or_else(|| ApiErr::new("缺少 event_id"))?;
            let (scored, ranked) = c.compute_event_inner(eid)?;
            if scored == 0 {
                return Err(ApiErr::new("该项目还没有可用的成绩，请先录入"));
            }
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set(
                "message",
                Json::s(format!(
                    "计算完成：{} 条有效成绩，{} 人/队获得名次与得分",
                    scored, ranked
                )),
            );
            Ok(Response::json(&o))
        });

        r("GET", "/api/report_table", |c, req| {
            /* v1.5.2：与 /api/students 同理，空串 grade 表示"全部年级"，
               不能当成"筛选一个名为空字符串的年级"（那会返回空表）。
               当前前端不传该参数，但接口契约上这就是个坑，一并堵掉。
               v1.6.0：改用统一的 query_non_empty 入口。 */
            let grade = req.query_non_empty("grade");
            Ok(Response::json(&c.report_table(grade.as_deref())))
        });
        r("GET", "/api/report/json", |c, _| {
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("report", c.report_json());
            Ok(Response::json(&o))
        });
        r("GET", "/api/report", |c, _| {
            let j = c.report_json();
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("filename", Json::s("校运会成绩报表.json"));
            o.set("data", j);
            Ok(Response::json(&o))
        });

        r("GET", "/api/export/json", |c, _| {
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("filename", Json::s("校运会数据备份.json"));
            o.set("data", c.export_all());
            Ok(Response::json(&o))
        });
        r("POST", "/api/import/json", |c, req| {
            let body = req.json().map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            Ok(Response::json(&c.import_all(&body)?))
        });
        // v1.9.0：报名表导入（tools/baoming_import.py 把 xlsx 转成的 JSON）。
        // 与 /api/import/json 的区别：那个是**整库覆盖恢复**（危险操作），
        // 这个是**增量导入**（加学生 + 建报名，重复的自动跳过并报告）。
        r("POST", "/api/import/baoming", |c, req| {
            let body = req.json().map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            Ok(Response::json(&c.import_baoming(&body)?))
        });
        // v1.9.3：直接上传填好的报名表 xlsx / csv（保留上面的 JSON 入口兼容脚本）。
        r("POST", "/api/import/baoming_file", |c, req| {
            let body = req.json().map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            if req.dev_mode {
                crate::core::audit::record(
                    "devmode",
                    "dev_import_baoming_file",
                    "开发者模式从文件导入报名表",
                );
            }
            Ok(Response::json(&c.import_baoming_file(&body)?))
        });
        // v1.9.8：整本《成绩公布表》导入（每个项目一个 sheet）。
        // 先 dry_run=1 出匹配报告，老师确认后再正式写。
        r("POST", "/api/import/scoresheet", |c, req| {
            let body = req.json().map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            let b64 = body.get_str("b64").unwrap_or_default();
            if b64.trim().is_empty() {
                return Err(ApiErr::new("缺少文件内容：请选择 .xlsx 成绩公布表"));
            }
            let bytes = crate::core::scoresheet::decode_upload(&b64)?;
            let dry = body
                .get("dry_run")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if req.dev_mode {
                crate::core::audit::record(
                    "devmode",
                    "dev_import_scoresheet",
                    if dry {
                        "开发者模式预览成绩公布表"
                    } else {
                        "开发者模式导入成绩公布表"
                    },
                );
            }
            Ok(Response::json(&c.import_scoresheet(&bytes, dry)?))
        });
        // v1.9.10：AI 整理好的表格（Markdown / 制表符 / CSV）直接粘贴导入。
        // 与上面的 xlsx 入口共用同一套匹配规则，dry_run=1 先出报告。
        r("POST", "/api/import/ai_table", |c, req| {
            let body = req.json().map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            let text = body.get_str("text").unwrap_or_default();
            let dry = body
                .get("dry_run")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if req.dev_mode {
                crate::core::audit::record(
                    "devmode",
                    "dev_import_ai_table",
                    if dry {
                        "开发者模式预览 AI 表格导入"
                    } else {
                        "开发者模式导入 AI 表格"
                    },
                );
            }
            Ok(Response::json(&c.import_ai_table(text, dry)?))
        });
        // v1.9.10：团体总分表（与学校《得分表》最后一页同版式）。
        // 先看 JSON 预览，再点导出拿 xlsx。
        r("GET", "/api/summary/total", |c, req| {
            let grade = req.query_get("grade").unwrap_or_default();
            Ok(Response::json(&c.total_table(&grade)))
        });
        r("GET", "/api/export/total_table", |c, req| {
            let grade = req.query_get("grade").unwrap_or_default();
            let (name, bytes) = c.total_table_xlsx(&grade);
            Ok(Response::download(
                &name,
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                &bytes,
            ))
        });
        // v1.9.7：只导名单（姓名/班别/性别），随后在「报名」页选项目。
        // 与上面的报名表导入并列，互不覆盖；不产生任何报名。
        r("POST", "/api/import/roster_file", |c, req| {
            let body = req.json().map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            if req.dev_mode {
                crate::core::audit::record(
                    "devmode",
                    "dev_import_roster_file",
                    "开发者模式从文件导入名单",
                );
            }
            Ok(Response::json(&c.import_roster_file(&body)?))
        });
        // v1.1：统一多格式导出 /api/export?fmt=csv|tsv|md|html|xlsx|json&type=results|registrations|students|all
        r("GET", "/api/export", |c, req| {
            let fmt = req
                .query_get("fmt")
                .unwrap_or_else(|| "csv".into())
                .to_lowercase();
            let typ = req
                .query_get("type")
                .unwrap_or_else(|| "results".into())
                .to_lowercase();
            let exp = c.read(|d| {
                crate::core::api::export_data(d, &fmt, &typ)
                    .map_err(ApiErr::new)
            })?;
            Ok(Response::download(&exp.filename, exp.content_type, &exp.bytes))
        });
        r("GET", "/api/export/csv", |c, req| {
            let ctype = req.query_get("type").unwrap_or_default();
            let (name, body) = match ctype.as_str() {
                "students" => ("学生名单", c.read(csv_students)),
                "registrations" => ("报名明细", c.read(csv_registrations)),
                "results" => ("全部成绩", c.read(csv_results)),
                _ => return Err(ApiErr::new("type 须为 students / registrations / results")),
            };
            Ok(Response::download(
                &format!("{}.csv", name),
                "text/csv; charset=utf-8",
                body.as_bytes(),
            ))
        });

        // 扩展清单（元信息，供界面展示）
        // v1.2：改为调用 extensions_json()，返回含健康统计的完整面板
        r("GET", "/api/ext/extensions", |c, _| {
            Ok(Response::json(&c.extensions_json()))
        });

        // ---- v1.5 新增：鉴权令牌 ----
        // 用口令换取带过期时间的签名令牌，避免口令在局域网反复明文传输。
        r("POST", "/api/auth/token", |c, req| {
            let body = req.json().map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            // 换取令牌本身必须出示口令，否则等于白送管理权
            let given = body.get_str("password").unwrap_or_default();
            match &c.password {
                Some(p) => {
                    if !crate::core::http::Router::const_time_eq(given, p) {
                        // 失败审计：口令爆破尝试会留下痕迹
                        crate::core::audit::record("anonymous", "auth.token_failed", "口令错误");
                        return Err(ApiErr::with_status("口令不正确", 401));
                    }
                }
                None => {
                    return Err(ApiErr::new(
                        "当前未启用管理口令，无需令牌（可用 --password 开启）",
                    ))
                }
            }
            let ttl = body.get_i64("ttl");
            let j = c.issue_token(ttl)?;
            crate::core::audit::record("admin", "auth.token_issued", "签发管理令牌");
            Ok(Response::json(&j))
        });
        // 令牌有效性自检（便于前端启动时判断是否需要重新输口令）
        r("GET", "/api/auth/check", |c, req| {
            let given = req
                .headers
                .get("authorization")
                .and_then(|v| v.strip_prefix("Bearer "))
                .unwrap_or("");
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("password_enabled", Json::Bool(c.password.is_some()));
            let role = if c.password.is_none() {
                "open"
            } else if c.is_authorized(given) {
                "admin"
            } else {
                "anonymous"
            };
            o.set("role", Json::s(role));
            // 令牌是否还在有效期内（用于前端提前提醒而非等到 401）
            let expire = if c.password.is_some() {
                c.verify_token(given)
            } else {
                None
            };
            o.set(
                "token_expires_at",
                expire.map(|e| Json::s(unix_to_string(e))).unwrap_or(Json::Null),
            );
            Ok(Response::json(&o))
        });

        // ---- v1.5 新增：审计哈希链 ----
        r("GET", "/api/audit", |c, req| {
            let n = req
                .query_get("limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(100)
                .min(1000);
            Ok(Response::json(&c.audit_panel_json(n)))
        });
        r("GET", "/api/audit/verify", |c, _| {
            Ok(Response::json(&c.audit_verify_json()))
        });

        // ---- v1.5 新增：智能成绩解析预览 ----
        // 只做"解析给你看"，不落库；让老师在录入前确认系统理解正确。
        r("POST", "/api/smart/parse", |_c, req| {
            let body = req.json().map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            let text = body.get_str("text").unwrap_or_default();
            let unit = body.get_str("unit").unwrap_or("时间");
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("input", Json::s(text));
            match crate::core::smart::parse_score_lenient(text, unit) {
                Some(r) => {
                    o.set("recognized", Json::Bool(true));
                    o.set("void", Json::Bool(r.void));
                    if r.void {
                        o.set("value", Json::Null);
                    } else {
                        o.set("value", Json::Num(r.value));
                    }
                    o.set("normalized", Json::s(r.normalized));
                    o.set(
                        "notes",
                        Json::arr(r.notes.iter().map(|n| Json::s(n.clone())).collect::<Vec<_>>()),
                    );
                }
                None => {
                    o.set("recognized", Json::Bool(false));
                    o.set("value", Json::Null);
                    o.set("normalized", Json::s(""));
                    o.set("notes", Json::arr(Vec::new()));
                    o.set(
                        "hint",
                        Json::s(format!(
                            "无法识别「{}」，请按此格式录入：{}",
                            text,
                            crate::core::scoring::unit_hint(unit)
                        )),
                    );
                }
            }
            Ok(Response::json(&o))
        });

        // ---- v1.5 新增：参赛人选推荐（可解释打分） ----
        r("GET", "/api/smart/recommend", |c, req| {
            let eid = req
                .query_get("event_id")
                .and_then(|v| v.parse::<i64>().ok())
                .ok_or_else(|| ApiErr::new("缺少 event_id"))?;
            let limit = req
                .query_get("limit")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(8);
            // 权重可调：便于学校按自身导向调整（例如更强调"人人参与"）
            let w = crate::core::smart::RecoWeights {
                perf: query_f64(req, "w_perf").unwrap_or(0.70),
                stability: query_f64(req, "w_stability").unwrap_or(0.20),
                spread: query_f64(req, "w_spread").unwrap_or(0.10),
            };
            let j = c
                .read(|d| crate::core::smart::recommendations_json(d, eid, limit, w))
                .map_err(ApiErr::new)?;
            Ok(Response::json(&j))
        });

        // ---- v1.5.1 新增：密钥机制与开发者模式 ----
        //
        // 安全设计总纲（三重条件，缺一不可）：
        //   1. 密钥匹配 —— 启动时用 `--devkey` 传入（只存哈希，无明文）
        //   2. 本机来源 —— 请求必须来自回环地址（TCP 层判定，不可伪造）
        //   3. 风险确认 —— 启动时带 `--i-know-the-risk`
        //
        // 这些接口**不设口令鉴权**，因为它们本身就是"高级权限"入口；
        // 想拿到高级权限，得先有密钥 + 坐在本机 + 显式认过风险。
        //
        // `GET /api/dev/status` 是只读的，且**永不返回密钥或种子**，
        // 只返回布尔量与指纹前缀（前 4 位），便于运维核对部署一致性。

        // 开发者模式状态（只读，任何来源可查 —— 不含敏感信息）
        r("GET", "/api/dev/status", |c, req| {
            let mut o = Json::obj();
            match c.license.as_ref() {
                Some(lic) => {
                    for (k, v) in lic.status_json_fields() {
                        o.set(k, v);
                    }
                    // 把「本机来源」这一重条件也如实告知前端，
                    // 这样前端能准确解释"为什么解锁按钮点了没反应"
                    o.set("from_loopback", Json::Bool(req.from_loopback));
                    o.set("dev_mode", Json::s(
                        if req.dev_mode { "unlocked" } else { "locked" }
                    ));
                }
                None => {
                    // 理论上 main.rs 总会设置 Some，这里是防御性分支
                    o.set("key_present", Json::Bool(false));
                    o.set("risk_acked", Json::Bool(false));
                    o.set("can_unlock", Json::Bool(false));
                    o.set("dev_mode", Json::s("locked"));
                    o.set("from_loopback", Json::Bool(req.from_loopback));
                }
            }
            o.set("encrypt_data", Json::Bool(c.encrypt_data));
            // v1.6.0：接口可观测统计（诊断页展示）
            if let Ok(st) = c.http_stats.lock() {
                let mut h = Json::obj();
                h.set("total", Json::Int(st.total as i64));
                h.set("ok", Json::Int(st.ok_count as i64));
                h.set("client_err", Json::Int(st.client_err as i64));
                h.set("server_err", Json::Int(st.server_err as i64));
                h.set("limited", Json::Int(st.limited as i64));
                h.set("avg_ms", Json::Num((st.avg_ms() * 100.0).round() / 100.0));
                h.set("error_rate", Json::Num((st.error_rate() * 10000.0).round() / 10000.0));
                h.set("slowest_ms", Json::Num((st.slowest_ms * 100.0).round() / 100.0));
                h.set("slowest_path", Json::s(st.slowest_path.clone()));
                // v1.6.0：限流快照
                h.set("rate_allowed", Json::Int(st.rate_allowed as i64));
                h.set("rate_rejected", Json::Int(st.rate_rejected as i64));
                h.set("rate_sources", Json::Int(st.rate_sources as i64));
                o.set("http_stats", h);
            }
            o.set(
                "seed_fingerprint",
                Json::s(
                    c.license
                        .as_ref()
                        .and_then(|l| l.stream_seed())
                        .map(crate::core::vault::seed_fingerprint)
                        .unwrap_or_else(|| "（无密钥）".into()),
                ),
            );
            Ok(Response::json(&o))
        });

        // 解锁开发者模式
        r("POST", "/api/dev/unlock", |c, req| {
            let lic = c
                .license
                .as_ref()
                .ok_or_else(|| ApiErr::new("本实例未启用密钥机制"))?;
            // 条件 1+3 已由 License 决定；这里补条件 2（本机来源）
            if !req.from_loopback {
                // 明确告知"必须本机"，因为这**不是**秘密 ——
                // 攻击者本来就知道自己不在本机，隐藏这条没有安全收益，
                // 而如实告知能帮正常使用者快速定位问题。
                let mut o = Json::obj();
                o.set("error", Json::s("开发者模式仅允许从本机（127.0.0.1）解锁"));
                o.set("dev_mode", Json::s("locked"));
                o.set("reason", Json::s("remote_source"));
                return Ok(Response::json_with_status(&o, 403));
            }
            if !lic.can_unlock() {
                let mut o = Json::obj();
                o.set(
                    "error",
                    Json::s("无法解锁：未提供有效密钥，或未以 --i-know-the-risk 确认风险"),
                );
                o.set("dev_mode", Json::s("locked"));
                o.set("reason", Json::s("prerequisites_missing"));
                return Ok(Response::json_with_status(&o, 403));
            }
            if !lic.unlock() {
                return Err(ApiErr::new("解锁失败（状态机拒绝）"));
            }
            // 解锁是安全态变更，必须留痕（actor 固定为 devmode）
            crate::core::audit::record(
                "devmode",
                "dev_unlock",
                "开发者模式已解锁（本机 + 密钥 + 风险确认三重条件齐备）",
            );
            log_warn!("dev", "开发者模式已解锁 —— 本次会话跳过危险操作二次确认");
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("dev_mode", Json::s("unlocked"));
            o.set(
                "warning",
                Json::s("开发者模式已开启：危险操作不再二次确认，全部动作写入审计"),
            );
            Ok(Response::json(&o))
        });

        // 上锁（关闭开发者模式）
        r("POST", "/api/dev/lock", |c, req| {
            let lic = c
                .license
                .as_ref()
                .ok_or_else(|| ApiErr::new("本实例未启用密钥机制"))?;
            let was = lic.lock();
            if was {
                crate::core::audit::record(
                    "devmode",
                    "dev_lock",
                    "开发者模式已上锁，安全边界恢复",
                );
                log_info!("dev", "开发者模式已上锁");
            }
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("dev_mode", Json::s("locked"));
            o.set("was_unlocked", Json::Bool(was));
            o.set("from_loopback", Json::Bool(req.from_loopback));
            Ok(Response::json(&o))
        });

        // ---- v1.7 新增：赛程编排（秩序册）----
        //
        // 设计取舍：这些接口**不设口令鉴权**，与普通的"设置/成绩"同权 ——
        // 因为它们是老师日常编排要用到的，不是高风险入口。
        // （开发者模式那类"高级权限"才需要三重条件，见上方。）
        //
        // 路由前缀遵循规则 6：核心接口走 /api/ 而非 /api/ext/。
        r("GET", "/api/schedule", |c, _req| {
            crate::core::schedule_api::get_schedule(c, _req)
        });
        r("POST", "/api/schedule/venues", |c, req| {
            crate::core::schedule_api::set_venues(c, req)
        });
        r("POST", "/api/schedule/sessions", |c, req| {
            crate::core::schedule_api::set_sessions(c, req)
        });
        r("POST", "/api/schedule/days", |c, req| {
            crate::core::schedule_api::set_days(c, req)
        });
        r("POST", "/api/schedule/arrange", |c, req| {
            crate::core::schedule_api::arrange(c, req)
        });
        r("POST", "/api/schedule/clear", |c, _req| {
            crate::core::schedule_api::clear(c, _req)
        });
        r("GET", "/api/schedule/lanes", |c, req| {
            crate::core::schedule_api::get_lanes(c, req)
        });

        // ---- v1.8.0 新增：服务端授权（机器指纹 + 离线降级）----
        //
        // 接口分工：
        //   GET  /api/aim/status       当前授权状态（脱敏，任何来源可查）
        //   POST /api/aim/activate     用密钥激活（联网校验，写缓存）
        //   POST /api/aim/verify       重新联网校验/续期
        //   POST /api/aim/deactivate   清除本地授权缓存
        //
        // 安全性：这些接口**不要求管理口令** —— 它们自身就是授权入口，
        // 若再要求口令会形成"想授权得先有口令，而口令属于授权能力"的
        // 死锁（与 /api/dev/* 的取舍同理，见 http.rs 的鉴权白名单）。
        // 它们不是危险操作：激活只写本地缓存，不触碰业务数据。
        r("GET", "/api/aim/status", |c, _req| {
            let j = match c.aim.as_ref() {
                Some(m) => {
                    let mgr = m.lock_recover();
                    crate::core::aim::status_json(Some(&mgr))
                }
                None => crate::core::aim::status_json(None),
            };
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("aim", j);
            // 同时告知"无授权时是否拦截业务"，让前端能解释界面为何不可用
            o.set("enforce", Json::Bool(c.aim_enforce));
            Ok(Response::json(&o))
        });

        r("POST", "/api/aim/activate", |c, req| {
            let mgr_ref = c
                .aim
                .as_ref()
                .ok_or_else(|| ApiErr::new("本实例未启用服务端授权校验"))?;
            let body = req
                .json()
                .map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            let key = body.get_str("key").unwrap_or("").to_string();
            let note = body.get_str("note").unwrap_or("").to_string();
            // kind 缺省按持久处理：多数场景是"发一台机器的长期授权"
            let kind = body.get_str("kind").unwrap_or("persistent");
            let mut mgr = mgr_ref.lock_recover();
            let d = if kind == "temporary" {
                mgr.activate_temporary(&key, &note)
            } else {
                mgr.activate_persistent(&key, &note)
            };
            // 授权状态变更属安全事件，写审计（actor 固定 aim）
            crate::core::audit::record(
                "aim",
                "aim_activate",
                &format!(
                    "授权激活：{} / {} / 指纹 {}… / {}",
                    d.kind.as_str(),
                    d.state.as_str(),
                    d.hwid_short,
                    d.message
                ),
            );
            let mut o = Json::obj();
            o.set("ok", Json::Bool(d.state.is_granted()));
            o.set("aim", crate::core::aim::status_json(Some(&mgr)));
            Ok(Response::json(&o))
        });

        r("POST", "/api/aim/verify", |c, _req| {
            let mgr_ref = c
                .aim
                .as_ref()
                .ok_or_else(|| ApiErr::new("本实例未启用服务端授权校验"))?;
            let mut mgr = mgr_ref.lock_recover();
            let d = mgr.verify_online();
            let mut o = Json::obj();
            o.set("ok", Json::Bool(d.state.is_granted()));
            o.set("aim", crate::core::aim::status_json(Some(&mgr)));
            Ok(Response::json(&o))
        });

        r("POST", "/api/aim/trial", |c, req| {
            let mgr_ref = c
                .aim
                .as_ref()
                .ok_or_else(|| ApiErr::new("本实例未启用服务端授权校验"))?;
            // 可选 body：{"key": "..."}。给了 key 就先校验是否是内置试用密钥。
            let key = req
                .json()
                .ok()
                .and_then(|b| b.get_str("key").map(|s| s.to_string()))
                .unwrap_or_default();
            let mut mgr = mgr_ref.lock_recover();
            if !key.is_empty() && !mgr.is_trial_key(&key) {
                // 不是试用密钥 → 明确告知，不误判为"启用失败"
                let mut o = Json::obj();
                o.set("ok", Json::Bool(false));
                o.set("reason", Json::s("这不是内置试用密钥"));
                o.set("aim", crate::core::aim::status_json(Some(&mgr)));
                return Ok(Response::json(&o));
            }
            let d = mgr.activate_trial();
            crate::core::audit::record(
                "aim",
                "aim_trial",
                &format!("试用启用：{} / {}", d.state.as_str(), d.message),
            );
            let mut o = Json::obj();
            o.set("ok", Json::Bool(d.state.is_granted()));
            o.set("aim", crate::core::aim::status_json(Some(&mgr)));
            Ok(Response::json(&o))
        });

        r("POST", "/api/aim/deactivate", |c, _req| {
            let mgr_ref = c
                .aim
                .as_ref()
                .ok_or_else(|| ApiErr::new("本实例未启用服务端授权校验"))?;
            let mut mgr = mgr_ref.lock_recover();
            let d = mgr.deactivate();
            crate::core::audit::record("aim", "aim_deactivate", &d.message);
            let mut o = Json::obj();
            o.set("ok", Json::Bool(false));
            o.set("aim", crate::core::aim::status_json(Some(&mgr)));
            Ok(Response::json(&o))
        });

        // ---- v1.9.0 新增：48 位激活密钥（数字/字母/符号/汉字交替）----
        //
        // 与上面的服务端密钥（在线校验）相互独立：
        //   POST /api/aim/key/activate    用 48 位密钥激活（完全离线）
        //   GET  /api/aim/key/status      密钥状态 + 本机指纹（申请密钥用）
        //   POST /api/aim/key/deactivate  停用密钥（删文件 + 清计量）
        //
        // 为什么单独给完整指纹：密钥与机器指纹绑定，用户必须能把指纹
        // 报给签发方才能买到能用的密钥。指纹由硬件派生、不可伪造，
        // 公开它不削弱任何防护（没有对应密钥，知道指纹也无从激活）。
        // 该接口仍是授权入口，同样不要求管理口令（理由同 /api/aim/*）。
        r("POST", "/api/aim/key/activate", |c, req| {
            let mgr_ref = c
                .aim
                .as_ref()
                .ok_or_else(|| ApiErr::new("本实例未启用授权管理（密钥激活不可用）"))?;
            let body = req
                .json()
                .map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
            let key = body.get_str("key").unwrap_or("").to_string();
            let mut mgr = mgr_ref.lock_recover();
            let d = mgr.activate_key(&key);
            crate::core::audit::record(
                "aim",
                "aim_key_activate",
                &format!("48 位密钥激活：{} / {}", d.state.as_str(), d.message),
            );
            let mut o = Json::obj();
            o.set("ok", Json::Bool(d.state.is_granted()));
            o.set("message", Json::s(d.message.clone()));
            o.set("aim", crate::core::aim::status_json(Some(&mgr)));
            Ok(Response::json(&o))
        });

        r("GET", "/api/aim/key/status", |c, _req| {
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            match c.aim.as_ref() {
                Some(m) => {
                    let mgr = m.lock_recover();
                    // 完整指纹：用户凭它向签发方购买/索取绑定的 48 位密钥
                    o.set("hwid", Json::s(mgr.hwid()));
                    o.set("hwid_short", Json::s(mgr.hwid_info().short_id()));
                    o.set("degraded", Json::Bool(mgr.hwid_info().degraded));
                    if let Some(kj) = mgr.key_fields() {
                        o.set("key", kj);
                    }
                    o.set(
                        "key_activated",
                        Json::Bool(mgr.key_license().is_some()),
                    );
                    o.set(
                        "aim",
                        crate::core::aim::status_json(Some(&mgr)),
                    );
                }
                None => {
                    o.set("hwid", Json::s(""));
                    o.set("key_activated", Json::Bool(false));
                    o.set(
                        "aim",
                        crate::core::aim::status_json(None),
                    );
                }
            }
            o.set("enforce", Json::Bool(c.aim_enforce));
            Ok(Response::json(&o))
        });

        r("POST", "/api/aim/key/deactivate", |c, _req| {
            let mgr_ref = c
                .aim
                .as_ref()
                .ok_or_else(|| ApiErr::new("本实例未启用授权管理（密钥停用不可用）"))?;
            let mut mgr = mgr_ref.lock_recover();
            let d = mgr.deactivate_key();
            crate::core::audit::record("aim", "aim_key_deactivate", &d.message);
            let mut o = Json::obj();
            o.set("ok", Json::Bool(false));
            o.set("message", Json::s(d.message.clone()));
            o.set("aim", crate::core::aim::status_json(Some(&mgr)));
            Ok(Response::json(&o))
        });

        v
    }

    /// 扩展路由（挂载 /api/ext/... 前缀）。
    ///
    /// v1.2 强化：
    ///   1. 注册阶段已校验前缀，此处再次防御性校验并记录告警；
    ///   2. 扩展 handler 返回 Err 时统一转 400，同时计入健康统计；
    ///   3. handler panic 被 catch_unwind 捕获，返回 500 而非拖垮进程。
    pub fn ext_routes(self: &Arc<Self>) -> Vec<crate::core::http::Route> {
        let mut v = Vec::new();
        let exts = self.extensions.lock_recover().clone();
        for ext in exts {
            let ext_name: &'static str = ext.name();
            let expected = format!("/api/ext/{}/", ext_name);
            for r in ext.routes() {
                // 防御性校验：即使注册时漏检，这里也不挂载非法路由
                if !(r.path.starts_with(&expected)
                    || r.path == format!("/api/ext/{}", ext_name))
                {
                    log_warn!(
                        "ext",
                        "跳过非法扩展路由 {} {}（扩展「{}」，应以 {} 开头）",
                        r.method,
                        r.path,
                        ext_name,
                        expected
                    );
                    continue;
                }
                let core_ref = Arc::clone(self);
                v.push(crate::core::http::Route {
                    method: r.method,
                    path: r.path,
                    handler: Arc::new(move |core, req| {
                        let result =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                (r.handler)(core, req)
                            }));
                        match result {
                            Ok(Ok(resp)) => Ok(resp),
                            Ok(Err(e)) => {
                                // 扩展返回错误：计入统计
                                if let Ok(mut hs) = core_ref.ext_health.lock() {
                                    if let Some(h) = hs.get_mut(ext_name) {
                                        h.event_errors += 1;
                                    }
                                }
                                log_warn!("ext", "扩展「{}」路由报错：{}", ext_name, e);
                                let mut o = Json::obj();
                                o.set("error", Json::s(e));
                                Ok(Response::json_with_status(&o, 400))
                            }
                            Err(_) => {
                                // panic 隔离：不让扩展问题导致连接无响应
                                if let Ok(mut hs) = core_ref.ext_health.lock() {
                                    if let Some(h) = hs.get_mut(ext_name) {
                                        h.event_errors += 1;
                                    }
                                }
                                log_error!(
                                    "ext",
                                    "扩展「{}」路由发生 panic：{} {}，已隔离",
                                    ext_name,
                                    r.method,
                                    r.path
                                );
                                // v1.6.0：用 semantic 构造器统一为 500 + E_INTERNAL
                                let err = ApiErr::internal(format!(
                                    "扩展 {} 处理异常",
                                    ext_name
                                ));
                                Ok(Response::json_with_status(
                                    &crate::core::envelope::err_envelope(&err),
                                    500,
                                ))
                            }
                        }
                    }),
                });
            }
        }

        v
    }

    /// 扩展健康面板数据（v1.2 新增）。
    pub fn extensions_json(&self) -> Json {
        let hs = self.ext_health.lock().ok();
        let exts = self.extensions.lock_recover().clone();
        let mut arr = Vec::new();
        for ext in exts {
            let name = ext.name();
            let mut o = Json::obj();
            o.set("name", Json::s(name));
            o.set("description", Json::s(ext.description()));
            match hs.as_ref().and_then(|g| g.get(name)) {
                Some(h) => {
                    o.set("initialized", Json::Bool(h.initialized));
                    o.set(
                        "init_error",
                        h.init_error
                            .as_ref()
                            .map(|e| Json::s(e.clone()))
                            .unwrap_or(Json::Null),
                    );
                    o.set("routes", Json::Int(h.route_count as i64));
                    o.set("events", Json::Int(h.event_count as i64));
                    o.set("errors", Json::Int(h.event_errors as i64));
                    o.set(
                        "last_event_time",
                        h.last_event_time
                            .as_ref()
                            .map(|t| Json::s(t.clone()))
                            .unwrap_or(Json::Null),
                    );
                    // 健康判定：初始化成功且无错误为 healthy
                    let healthy = h.initialized && h.event_errors == 0;
                    o.set(
                        "health",
                        Json::s(if healthy { "healthy" } else { "degraded" }),
                    );
                }
                None => {
                    o.set("initialized", Json::Bool(false));
                    o.set("health", Json::s("unknown"));
                }
            }
            arr.push(o);
        }
        let mut top = Json::obj();
        top.set("ok", Json::Bool(true));
        top.set("extensions", Json::Arr(arr));
        // v1.2：同时暴露撤销栈深度，前端一处拉取即可刷新
        top.set(
            "undo_depth",
            Json::Int(self.read(|d| d.undo_stack.len() as i64)),
        );
        top.set("undo_keep", Json::Int(self.undo_keep as i64));
        top
    }
}

// ---------------------------------------------------------------------------
// 令牌工具（v1.5）
// ---------------------------------------------------------------------------

/// 当前 Unix 时间戳（秒）。
pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Unix 时间戳 → 本地时间字符串（复用 store 的时区换算口径）。
/// 这里只做粗略换算：取 UTC+8 偏移后按天取模求时分秒。
fn unix_to_string(secs: i64) -> String {
    let s = secs + 8 * 3600;
    let days = s.div_euclid(86400);
    let rem = s.rem_euclid(86400);
    // 用 store 已有的公历换算保持口径一致（不重复造轮子）
    let (y, m, d) = crate::core::store::civil_from_days_pub(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// 生成进程内随机密钥 / nonce。
///
/// 熵来源（按可靠性排序，全部来自标准库，不引入 rand）：
/// 1. 系统时间纳秒差值；
/// 2. 地址空间随机化（ASLR）下的栈地址与堆地址；
/// 3. 进程 id 与线程 id；
/// 4. 一个自增计数器（防止同一纳秒内两次调用得到相同结果）。
///
/// 上述来源经 FNV-1a 混合后输出 32 位十六进制。用于"令牌防伪造"是够的：
/// 攻击者即使知道算法，也无法从网络侧推知本进程的时间/地址/计数器组合。
/// **不用于加密密钥派生**——那是 sha2 的职责，本模块不越界。
fn random_secret() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let stack_probe = 0u8;
    let stack_addr = &stack_probe as *const u8 as u64;
    let heap_probe = std::sync::Arc::new(0u8);
    let heap_addr = std::sync::Arc::as_ptr(&heap_probe) as u64;
    let pid = std::process::id() as u64;
    let tid = {
        let t = std::thread::current();
        let id = t.id();
        // ThreadId 无稳定数值接口，用 Debug 文本的特征字节代替（稳定且唯一）
        let text = format!("{:?}", id);
        crate::core::audit::fnv1a64("tid", &[&text])
            .chars()
            .take(8)
            .fold(0u64, |a, c| a.wrapping_mul(31).wrapping_add(c as u64))
    };
    let ctr = COUNTER.fetch_add(1, Ordering::SeqCst);

    let mut acc = String::new();
    acc.push_str(&crate::core::audit::fnv1a64(
        "seed",
        &[
            &nanos.to_string(),
            &stack_addr.to_string(),
            &heap_addr.to_string(),
            &pid.to_string(),
            &tid.to_string(),
            &ctr.to_string(),
        ],
    ));
    // 再混一轮，避免单轮的顺序相关弱点
    acc.push_str(&crate::core::audit::fnv1a64(
        &acc.clone(),
        &[&pid.to_string(), &heap_addr.to_string()],
    ));
    acc
}

/// 令牌签名：H(secret ‖ expire ‖ nonce)。
fn token_sig(secret: &str, expire: i64, nonce: &str) -> String {
    crate::core::audit::fnv1a64(secret, &[&expire.to_string(), nonce])
}

// ---------------------------------------------------------------------------
// 内部工具
// ---------------------------------------------------------------------------

fn skip_entry(student: &str, reason: impl Into<String>) -> Json {
    let mut e = Json::obj();
    e.set("student", Json::s(student));
    e.set("reason", Json::s(reason.into()));
    e
}

/// 读取路径参数中的正整数 id（v1.6.0 强化）。
///
/// 旧实现：`params.get(key).and_then(parse::<i64>().ok()).ok_or("路径参数不合法")`
/// —— 把所有失败原因（缺失 / 非数字 / 负数 / 零）都塌缩成同一句话，
/// 调用方看不出到底哪里错了。
///
/// v1.6.0：委托给 `Request::path_id`，逐种情况给出**具体**原因，
/// 并统一返回 `E_VALIDATION` 错误码。此处保留薄包装，是为了不动
/// 既有约 15 处调用点（手术式修改，规则：每行改动都能追溯到需求）。
fn path_i64(req: &Request, key: &str) -> Result<i64, ApiErr> {
    req.path_id(key)
}

/// 读取查询串中的 f64 参数（v1.5）。
fn query_f64(req: &Request, key: &str) -> Option<f64> {
    req.query_get(key)
        .and_then(|v| v.parse::<f64>().ok())
        .filter(|v| v.is_finite() && (0.0..=1.0).contains(v))
}

fn result_from_json(j: &Json) -> DomainResult {
    DomainResult {
        id: j.get_i64("id").unwrap_or(0),
        event_id: j.get_i64("event_id").unwrap_or(0),
        student_id: j.get("student_id").and_then(|v| v.as_i64()),
        grade: j.get_string("grade"),
        class_no: j.get("class_no").and_then(|v| v.as_i64()),
        score_text: j.get_string("score_text"),
        score_value: j.get("score_value").and_then(|v| v.as_f64()),
        rank: j.get("rank").and_then(|v| v.as_i64()),
        points: j.get("points").and_then(|v| v.as_f64()),
        broke_record: j
            .get("broke_record")
            .and_then(|v| v.as_i64())
            .unwrap_or(0)
            != 0,
    }
}

/// v1.9.3：一键清空报名的范围。
///
/// 范围刻意做成封闭集合，不接受任意条件表达式：清空是破坏性操作，
/// 条件越自由越容易误伤。`class` 必须同时给年级与班号，因为班号
/// 在不同年级会重复（初一 1 班 / 初二 1 班）。
#[derive(Clone)]
struct ClearRegScope {
    kind: String,
    event_id: i64,
    grade: String,
    class_no: i64,
}

impl ClearRegScope {
    fn from_json(body: &Json) -> Result<Self, ApiErr> {
        let kind = body.get_str("scope").unwrap_or("all").trim().to_string();
        let mut s = ClearRegScope {
            kind,
            event_id: 0,
            grade: String::new(),
            class_no: 0,
        };
        match s.kind.as_str() {
            "all" => {}
            "event" => {
                s.event_id = body
                    .get_i64("event_id")
                    .ok_or_else(|| ApiErr::new("按项目清空需要 event_id"))?;
            }
            "grade" => {
                s.grade = body.get_string("grade");
                if s.grade.is_empty() {
                    return Err(ApiErr::new("按年级清空需要 grade"));
                }
            }
            "class" => {
                s.grade = body.get_string("grade");
                s.class_no = body.get_i64("class_no").unwrap_or(0);
                if s.grade.is_empty() || s.class_no <= 0 {
                    return Err(ApiErr::new("按班级清空需要 grade 与 class_no"));
                }
            }
            other => return Err(ApiErr::new(format!("未知的清空范围：{}", other))),
        }
        Ok(s)
    }

    fn label(&self) -> String {
        match self.kind.as_str() {
            "event" => format!("项目 #{}", self.event_id),
            "grade" => format!("年级「{}」", self.grade),
            "class" => format!("{}{}班", self.grade, self.class_no),
            _ => "全部".to_string(),
        }
    }

    /// 学生查不到时（历史脏数据）只保留 `all` / `event` 两种可按报名
    /// 自身判定的范围，避免"范围不明却把记录删了"。
    fn hit(&self, r: &Registration, stu: Option<&Student>) -> bool {
        match self.kind.as_str() {
            "event" => r.event_id == self.event_id,
            "grade" => stu.map(|s| s.grade == self.grade).unwrap_or(false),
            "class" => stu
                .map(|s| s.grade == self.grade && s.class_no == self.class_no)
                .unwrap_or(false),
            _ => true,
        }
    }
}

fn collect_clear_regs(d: &Data, scope: &ClearRegScope) -> Vec<Registration> {
    d.registrations
        .iter()
        .filter(|r| {
            let stu = d.students.iter().find(|s| s.id == r.student_id);
            scope.hit(r, stu)
        })
        .cloned()
        .collect()
}

/// 被删报名对应的成绩键（项目 id + 学生 id），排序去重后用二分查找。
fn clear_result_keys(regs: &[Registration]) -> Vec<(i64, i64)> {
    let mut v: Vec<(i64, i64)> = regs
        .iter()
        .map(|r| (r.event_id, r.student_id))
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// 只删个人成绩；集体项目成绩 `student_id == None`，不属于任何一次退报。
fn clear_result_hit(r: &DomainResult, keys: &[(i64, i64)]) -> bool {
    match r.student_id {
        Some(sid) => keys.binary_search(&(r.event_id, sid)).is_ok(),
        None => false,
    }
}

fn undo_description(action: &str, payload: &Json) -> String {
    match action {
        "delete_event" => format!(
            "删除项目「{}」",
            payload
                .get("event")
                .and_then(|e| e.get_str("name"))
                .unwrap_or("?")
        ),
        "delete_student" => format!(
            "删除学生「{}」",
            payload
                .get("student")
                .and_then(|s| s.get_str("name"))
                .unwrap_or("?")
        ),
        "unregister" => "退报".to_string(),
        "clear_results" => format!(
            "清空项目 #{} 的成绩",
            payload.get_i64("event_id").unwrap_or(0)
        ),
        "clear_registrations" => format!(
            "清空报名 [{}]（{} 条）",
            payload.get_str("label").unwrap_or("全部"),
            payload
                .get("registrations")
                .and_then(|v| v.as_arr())
                .map(|a| a.len())
                .unwrap_or(0)
        ),
        "register_many" => format!(
            "批量报名 {} 人",
            payload
                .get("student_ids")
                .and_then(|v| v.as_arr())
                .map(|a| a.len())
                .unwrap_or(0)
        ),
        _ => action.to_string(),
    }
}

// ---------------------------------------------------------------------------
// 异常成绩检测（IQR + MAD，与 Python anomaly.py 对齐）
// ---------------------------------------------------------------------------

const MIN_SAMPLE: usize = 5;

fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let n = sorted.len();
    if n == 1 {
        return sorted[0];
    }
    let pos = q * (n as f64 - 1.0);
    let lo = pos.floor() as usize;
    let hi = (lo + 1).min(n - 1);
    let frac = pos - lo as f64;
    sorted[lo] * (1.0 - frac) + sorted[hi] * frac
}

fn detect_outliers(values: &[Option<f64>], lower_is_better: bool) -> Vec<bool> {
    let mut flags = vec![false; values.len()];
    let valid: Vec<(usize, f64)> = values
        .iter()
        .enumerate()
        .filter_map(|(i, v)| v.map(|x| (i, x)))
        .collect();
    if valid.len() < MIN_SAMPLE {
        return flags;
    }
    let mut nums: Vec<f64> = valid.iter().map(|(_, v)| *v).collect();
    nums.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let q1 = quantile(&nums, 0.25);
    let q3 = quantile(&nums, 0.75);
    let iqr = q3 - q1;
    let med = quantile(&nums, 0.5);
    let mut abs_devs: Vec<f64> = valid.iter().map(|(_, v)| (v - med).abs()).collect();
    abs_devs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mad = quantile(&abs_devs, 0.5);
    for (i, v) in valid {
        let iqr_flag = if lower_is_better {
            v < q1 - 1.5 * iqr
        } else {
            v > q3 + 1.5 * iqr
        };
        let mad_flag = if mad > 0.0 {
            let z = (v - med).abs() / (1.4826 * mad);
            if lower_is_better {
                z > 3.0 && v < med
            } else {
                z > 3.0 && v > med
            }
        } else {
            false
        };
        flags[i] = iqr_flag || mad_flag;
    }
    flags
}

// ---------------------------------------------------------------------------
// CSV 导出
// ---------------------------------------------------------------------------

fn csv_row(cells: &[String]) -> String {
    cells
        .iter()
        .map(|c| {
            if c.contains(',') || c.contains('"') || c.contains('\n') {
                format!("\"{}\"", c.replace('"', "\"\""))
            } else {
                c.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn csv_students(d: &Data) -> String {
    let mut lines = vec![csv_row(&["年级".into(), "班级".into(), "姓名".into(), "性别".into()])];
    for s in &d.students {
        lines.push(csv_row(&[
            s.grade.clone(),
            s.class_no.to_string(),
            s.name.clone(),
            s.gender.clone(),
        ]));
    }
    lines.join("\n") + "\n"
}

fn csv_registrations(d: &Data) -> String {
    let mut lines = vec![csv_row(&[
        "项目".into(),
        "年级".into(),
        "班级".into(),
        "姓名".into(),
        "备注".into(),
    ])];
    let mut regs: Vec<&Registration> = d.registrations.iter().collect();
    regs.sort_by_key(|r| (r.event_id, r.student_id));
    for r in regs {
        let ev = d.events.iter().find(|e| e.id == r.event_id);
        let s = d.students.iter().find(|s| s.id == r.student_id);
        lines.push(csv_row(&[
            ev.map(|e| e.name.clone()).unwrap_or_default(),
            s.map(|s| s.grade.clone()).unwrap_or_default(),
            s.map(|s| s.class_no.to_string()).unwrap_or_default(),
            s.map(|s| s.name.clone()).unwrap_or_default(),
            r.note.clone(),
        ]));
    }
    lines.join("\n") + "\n"
}

fn csv_results(d: &Data) -> String {
    let mut lines = vec![csv_row(&[
        "项目".into(),
        "参赛者".into(),
        "成绩".into(),
        "名次".into(),
        "得分".into(),
        "破纪录".into(),
    ])];
    for r in &d.results {
        let ev = d.events.iter().find(|e| e.id == r.event_id);
        let label = if let Some(sid) = r.student_id {
            d.students
                .iter()
                .find(|s| s.id == sid)
                .map(|s| format!("{}（{}）", s.name, s.class_name()))
                .unwrap_or_else(|| format!("ID {}", sid))
        } else {
            format!("{}{}班", r.grade, r.class_no.unwrap_or(0))
        };
        lines.push(csv_row(&[
            ev.map(|e| e.name.clone()).unwrap_or_default(),
            label,
            r.score_text.clone(),
            r.rank.map(|x| x.to_string()).unwrap_or_default(),
            r.points.map(|x| x.to_string()).unwrap_or_default(),
            if r.broke_record { "是".into() } else { String::new() },
        ]));
    }
    lines.join("\n") + "\n"
}

// v1.6.0：`ApiErr::with_data` 已上移到 `core::error`（与错误码同处定义，
// 避免"错误类型的能力分散在两个文件"）。此处保留说明，不再重复定义。

// ---------------------------------------------------------------------------
// v1.1：供 export.rs 复用的 csv 渲染包装
// ---------------------------------------------------------------------------
pub fn csv_students_pub(d: &Data) -> String { csv_students(d) }
pub fn csv_registrations_pub(d: &Data) -> String { csv_registrations(d) }
pub fn csv_results_pub(d: &Data) -> String { csv_results(d) }

/// v1.1：多格式统一导出入口。
pub fn export_data(d: &Data, fmt: &str, typ: &str) -> Result<crate::core::export::Exported, String> {
    crate::core::export::export(d, fmt, typ)
}


// ---------------------------------------------------------------------------
// v1.1：成绩导入的表头智能映射（列顺序无关）
// ---------------------------------------------------------------------------

/// 解析粘贴的表格文本（csv/tsv 均可，逗号/制表符/中文逗号自动识别）。
/// 返回 (表头, 数据行)；若无表头则表头为空、按旧固定顺序解析。
fn split_table(text: &str) -> (Vec<Vec<String>>, bool) {
    let sep = if text.contains('\t') {
        '\t'
    } else if text.contains('，') {
        '，'
    } else {
        ','
    };
    let mut rows: Vec<Vec<String>> = Vec::new();
    for line in text.lines().map(str::trim).filter(|l| !l.is_empty()) {
        rows.push(line.split(sep).map(|c| c.trim().to_string()).collect());
    }
    // 表头判定：第一行含非数字中文列名（如 姓名/成绩/班级）
    let has_header = rows
        .first()
        .map(|r| {
            r.iter().any(|c| {
                !c.is_empty()
                    && c.chars().any(|ch| !ch.is_ascii_digit() && ch != '.')
                    && !c.chars().all(|ch| ch.is_ascii_digit() || ch == '.')
            })
        })
        .unwrap_or(false);
    (rows, has_header)
}

/// 成绩文本 → entries：
/// - 有表头：按表头别名映射「编号/学号」「姓名」「成绩/分数/得分」列，顺序任意；
/// - 无表头：兼容 v1.0 行为（第一列编号或姓名，最后一列成绩）；
/// - 姓名匹配仅限该项目已报名学生，避免跨班误录。
fn parse_score_import(
    text: &str,
    core: &Core,
    event_id: i64,
) -> Result<(Vec<Json>, Vec<String>), ApiErr> {
    use crate::core::export::header_index;
    let (rows, has_header) = split_table(text);
    let mut skipped_names: Vec<String> = Vec::new();
    if rows.is_empty() {
        return Ok((Vec::new(), Vec::new()));
    }
    // 报名名单（用于姓名匹配）
    let view = core.event_registrations(event_id)?;
    let mut by_name: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    for e in view.get("entries").and_then(|v| v.as_arr()).into_iter().flatten() {
        if let (Some(name), Some(id)) = (e.get_str("name"), e.get_i64("student_id")) {
            by_name.insert(name.trim().to_string(), id);
        }
    }
    let mut entries: Vec<Json> = Vec::new();
    if has_header {
        let headers: Vec<String> = rows[0].clone();
        let href: Vec<&str> = headers.iter().map(|s| s.as_str()).collect();
        let id_col = header_index(&href, &["编号", "学号", "student_id", "id"]);
        let name_col = header_index(&href, &["姓名", "名字", "参赛者", "学生"]);
        let score_col = header_index(
            &href,
            &["成绩", "分数", "得分", "成绩文本", "score"],
        );
        if name_col.is_none() && id_col.is_none() {
            return Err(ApiErr::new(
                "表头中未找到「姓名」或「编号」列，请检查第一行",
            ));
        }
        // v1.2：改用 ok_or_else 提前返回，消除 unwrap
        let score_col =
            score_col.ok_or_else(|| ApiErr::new("表头中未找到「成绩」列，请检查第一行"))?;
        for row in &rows[1..] {
            let cell = |i: Option<usize>| -> String {
                i.and_then(|i| row.get(i)).cloned().unwrap_or_default()
            };
            let mut e = Json::obj();
            e.set("score_text", Json::s(cell(Some(score_col))));
            let mut resolved = false;
            if let Some(ic) = id_col {
                if let Ok(sid) = cell(Some(ic)).parse::<i64>() {
                    e.set("student_id", Json::Int(sid));
                    resolved = true;
                }
            }
            if !resolved && !name_col_is_idonly(name_col, id_col) {
                let name = cell(name_col);
                if let Some(&sid) = by_name.get(&name) {
                    e.set("student_id", Json::Int(sid));
                } else if !name.is_empty() {
                    // 未匹配到报名名单：跳过并记录，避免误录
                    skipped_names.push(name);
                    continue;
                }
            }
            entries.push(e);
        }
    } else {
        // v1.0 兼容：无表头时第一列编号（纯数字）或姓名，最后一列成绩
        for row in &rows {
            let mut e = Json::obj();
            e.set("score_text", Json::s(row.last().cloned().unwrap_or_default()));
            if let Some(first) = row.first() {
                if let Ok(sid) = first.parse::<i64>() {
                    e.set("student_id", Json::Int(sid));
                } else if let Some(&sid) = by_name.get(first) {
                    e.set("student_id", Json::Int(sid));
                } else if !first.is_empty() {
                    skipped_names.push(first.clone());
                    continue;
                }
            }
            entries.push(e);
        }
    }
    Ok((entries, skipped_names))
}

/// 判断「姓名列」是否实际就是「编号列」（同一列被双重识别）。
/// v1.2：参数改为 Option，与调用处保持一致，内部 unwrap_or 语义不变。
fn name_col_is_idonly(name_col: Option<usize>, id_col: Option<usize>) -> bool {
    name_col == id_col
}

/// 学生名单导入：支持带表头（姓名/年级/班级/性别 任意顺序）或固定顺序。
pub fn parse_student_import(text: &str) -> Result<Vec<Json>, ApiErr> {
    use crate::core::export::header_index;
    let (rows, has_header) = split_table(text);
    let _skipped_names: Vec<String> = Vec::new();
    if rows.is_empty() {
        return Ok(Vec::new());
    }
    let mut out: Vec<Json> = Vec::new();
    if has_header {
        let href: Vec<&str> = rows[0].iter().map(|s| s.as_str()).collect();
        let name_col = header_index(&href, &["姓名", "名字", "学生"])
            .ok_or_else(|| ApiErr::new("表头中未找到「姓名」列"))?;
        let grade_col = header_index(&href, &["年级"]);
        let class_col = header_index(&href, &["班级", "班"]);
        let gender_col = header_index(&href, &["性别"]);
        for row in &rows[1..] {
            let cell = |i: Option<usize>| -> String {
                i.and_then(|i| row.get(i)).cloned().unwrap_or_default()
            };
            let mut e = Json::obj();
            e.set("name", Json::s(cell(Some(name_col))));
            if let Some(g) = grade_col { e.set("grade", Json::s(cell(Some(g)))); }
            if let Some(c) = class_col {
                if let Ok(cn) = cell(Some(c)).parse::<i64>() {
                    e.set("class_no", Json::Int(cn));
                }
            }
            if let Some(gd) = gender_col { e.set("gender", Json::s(cell(Some(gd)))); }
            out.push(e);
        }
    } else {
        for row in &rows {
            if row.len() < 4 {
                continue;
            }
            let mut e = Json::obj();
            e.set("grade", Json::s(row[0].clone()));
            e.set("class_no", Json::s(row[1].clone()));
            e.set("name", Json::s(row[2].clone()));
            e.set("gender", Json::s(row[3].clone()));
            out.push(e);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// 单元测试（v1.2 新增）：扩展注册校验与扩展隔离机制
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// v1.9.8：成绩公布表匹配用的最小 Event 构造器。
    fn evt(id: i64, name: &str, gender: &str, is_team: bool) -> Event {
        Event {
            id,
            name: name.into(),
            category: "径赛".into(),
            gender: gender.into(),
            grade: "全部".into(),
            is_team,
            unit: "时间".into(),
            record: None,
        }
    }

    #[test]
    fn scoresheet_name_variants_resolve_to_same_event() {
        let evs = vec![
            evt(1, "男子100米", "男子", false),
            evt(2, "男子4×100米接力", "男子", true),
            evt(3, "投掷沙包", "通用", false),
            evt(4, "仰卧起坐", "女子", false),
        ];
        let id = |n: &str| Core::match_event_by_name(n, &evs).map(|e| e.id);
        assert_eq!(id("男子4乘100米决赛"), Some(2), "乘号写法");
        assert_eq!(id("男子4*100米"), Some(2), "星号写法");
        assert_eq!(id("男子投掷毽球"), Some(3), "毽球=沙包");
        assert_eq!(id("一分钟仰卧起坐"), Some(4), "一分钟前缀");
        assert_eq!(id("男子100米决赛"), Some(1), "决赛后缀");
        assert_eq!(id("不存在的项目"), None);
    }

    #[test]
    fn scoresheet_class_hint_fills_grade() {
        let grades = vec!["初一".to_string(), "初二".to_string()];
        assert_eq!(
            Core::resolve_class("3", "初二", &grades),
            Some(("初二".to_string(), 3))
        );
        assert_eq!(
            Core::resolve_class("初二（3）班", "", &grades),
            Some(("初二".to_string(), 3))
        );
        // 只有班号又没有组别线索：不猜
        assert_eq!(Core::resolve_class("3", "", &grades), None);
    }
    // v1.4：这些类型仅测试使用（--fix 误删了主 use 中的引用，在测试域内补齐）
    use crate::core::ext::{CoreContext, ExtRoute};

    /// 测试用空扩展：无路由、无副作用。
    struct DummyExt {
        name: &'static str,
        routes: Vec<ExtRoute>,
        panic_on_event: bool,
        init_should_fail: bool,
    }

    impl DummyExt {
        fn simple(name: &'static str) -> DummyExt {
            DummyExt {
                name,
                routes: Vec::new(),
                panic_on_event: false,
                init_should_fail: false,
            }
        }
    }

    impl Extension for DummyExt {
        fn name(&self) -> &'static str {
            self.name
        }
        fn description(&self) -> &'static str {
            "test dummy"
        }
        fn on_init(&self, _ctx: &CoreContext) -> Result<(), String> {
            if self.init_should_fail {
                Err("模拟初始化失败".into())
            } else {
                Ok(())
            }
        }
        fn routes(&self) -> Vec<ExtRoute> {
            self.routes.clone()
        }
        fn on_event(&self, _ctx: &CoreContext, _event: &CoreEvent) {
            if self.panic_on_event {
                panic!("模拟扩展事件处理 panic");
            }
        }
    }

    /// 构造一个使用临时目录的 Core，避免污染真实数据。
    fn tmp_core(tag: &str) -> Arc<Core> {
        let dir = std::env::temp_dir().join(format!("sports_meet_test_{}_{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Arc::new(Core::new(&dir, std::path::Path::new("web")))
    }

    // ---------------- 扩展注册校验 ----------------

    #[test]
    fn register_accepts_valid_extension() {
        let core = tmp_core("valid");
        core.register_extension(Arc::new(DummyExt::simple("good-ext")));
        let n = core.extensions.lock_recover().len();
        assert_eq!(n, 1, "合法扩展应注册成功");
        assert_eq!(core.ext_health.lock_recover().len(), 1);
    }

    #[test]
    fn register_rejects_empty_name() {
        let core = tmp_core("empty_name");
        core.register_extension(Arc::new(DummyExt::simple("")));
        assert_eq!(core.extensions.lock_recover().len(), 0, "空名应被拒绝");
    }

    #[test]
    fn register_rejects_illegal_name_chars() {
        let core = tmp_core("bad_name");
        // 含空格与斜杠，均非法
        core.register_extension(Arc::new(DummyExt::simple("bad name")));
        core.register_extension(Arc::new(DummyExt::simple("bad/name")));
        core.register_extension(Arc::new(DummyExt::simple("中文名")));
        assert_eq!(core.extensions.lock_recover().len(), 0, "非法字符名应被拒绝");
    }

    #[test]
    fn register_rejects_duplicate_name() {
        let core = tmp_core("dup");
        core.register_extension(Arc::new(DummyExt::simple("same")));
        core.register_extension(Arc::new(DummyExt::simple("same")));
        assert_eq!(core.extensions.lock_recover().len(), 1, "重名应只成功一次");
    }

    #[test]
    fn register_rejects_wrong_route_prefix() {
        let core = tmp_core("bad_prefix");
        let ext = DummyExt {
            name: "myext",
            routes: vec![ExtRoute {
                method: "GET",
                // 未使用 /api/ext/myext/ 前缀
                path: "/api/evil/steal",
                handler: Arc::new(|_c, _r| {
                    Ok(Response::json(&Json::obj()))
                }),
            }],
            panic_on_event: false,
            init_should_fail: false,
        };
        core.register_extension(Arc::new(ext));
        assert_eq!(
            core.extensions.lock_recover().len(),
            0,
            "路由前缀不合规的扩展应被整体拒绝"
        );
    }

    #[test]
    fn register_accepts_correct_route_prefix() {
        let core = tmp_core("good_prefix");
        let ext = DummyExt {
            name: "myext",
            routes: vec![
                ExtRoute {
                    method: "GET",
                    path: "/api/ext/myext/stats",
                    handler: Arc::new(|_c, _r| Ok(Response::json(&Json::obj()))),
                },
                ExtRoute {
                    method: "GET",
                    // 恰好等于前缀根也允许
                    path: "/api/ext/myext",
                    handler: Arc::new(|_c, _r| Ok(Response::json(&Json::obj()))),
                },
            ],
            panic_on_event: false,
            init_should_fail: false,
        };
        core.register_extension(Arc::new(ext));
        assert_eq!(core.extensions.lock_recover().len(), 1);
        let hs = core.ext_health.lock_recover();
        assert_eq!(hs.get("myext").unwrap().route_count, 2, "应记录路由条数");
    }

    // ---------------- 初始化状态记录 ----------------

    #[test]
    fn init_failure_recorded_not_fatal() {
        let core = tmp_core("init_fail");
        core.register_extension(Arc::new(DummyExt {
            name: "failing",
            routes: Vec::new(),
            panic_on_event: false,
            init_should_fail: true,
        }));
        core.init_extensions(); // 不应 panic
        let hs = core.ext_health.lock_recover();
        let h = hs.get("failing").unwrap();
        assert!(!h.initialized);
        assert!(h.init_error.is_some(), "失败原因应被记录");
    }

    #[test]
    fn init_success_marks_initialized() {
        let core = tmp_core("init_ok");
        core.register_extension(Arc::new(DummyExt::simple("okext")));
        core.init_extensions();
        let hs = core.ext_health.lock_recover();
        assert!(hs.get("okext").unwrap().initialized);
    }

    // ---------------- 事件隔离（核心不被扩展 panic 拖垮） ----------------

    #[test]
    fn event_panic_is_isolated() {
        let core = tmp_core("event_panic");
        core.register_extension(Arc::new(DummyExt {
            name: "panicky",
            routes: Vec::new(),
            panic_on_event: true,
            init_should_fail: false,
        }));
        core.init_extensions();
        // 关键：publish 不应向外抛出 panic
        core.publish(EventKind::CoreStarted, Json::obj());
        let hs = core.ext_health.lock_recover();
        let h = hs.get("panicky").unwrap();
        assert_eq!(h.event_count, 1, "事件计数应递增");
        assert_eq!(h.event_errors, 1, "panic 应被计入错误数");
    }

    #[test]
    fn healthy_extension_no_errors() {
        let core = tmp_core("healthy");
        core.register_extension(Arc::new(DummyExt::simple("clean")));
        core.init_extensions();
        core.publish(EventKind::CoreStarted, Json::obj());
        core.publish(EventKind::ResultsComputed, Json::obj());
        let hs = core.ext_health.lock_recover();
        let h = hs.get("clean").unwrap();
        assert_eq!(h.event_count, 2);
        assert_eq!(h.event_errors, 0);
        assert!(h.last_event_time.is_some());
    }

    #[test]
    fn panic_in_one_ext_does_not_block_others() {
        let core = tmp_core("multi_ext");
        let counter = Arc::new(AtomicUsize::new(0));

        struct CountingExt {
            c: Arc<AtomicUsize>,
        }
        impl Extension for CountingExt {
            fn name(&self) -> &'static str {
                "counter"
            }
            fn description(&self) -> &'static str {
                ""
            }
            fn on_init(&self, _ctx: &CoreContext) -> Result<(), String> {
                Ok(())
            }
            fn on_event(&self, _ctx: &CoreContext, _e: &CoreEvent) {
                self.c.fetch_add(1, Ordering::SeqCst);
            }
        }

        core.register_extension(Arc::new(DummyExt {
            name: "boom",
            routes: Vec::new(),
            panic_on_event: true,
            init_should_fail: false,
        }));
        core.register_extension(Arc::new(CountingExt {
            c: Arc::clone(&counter),
        }));
        core.init_extensions();
        core.publish(EventKind::CoreStarted, Json::obj());

        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "前一个扩展 panic 不应阻止后续扩展收到事件"
        );
    }

    // ---------------- 撤销栈多步化 ----------------

    #[test]
    fn undo_stack_trims_to_keep() {
        let core = {
            let mut c = Core::new(
                &std::env::temp_dir().join(format!("sports_meet_test_undo_trim_{}", std::process::id())),
                std::path::Path::new("web"),
            );
            c.undo_keep = 3;
            Arc::new(c)
        };
        // 压入 5 条，应只保留最近 3 条
        for i in 0..5 {
            core.write(|d| {
                Core::push_undo(d, "test", Json::obj().set("i", Json::Int(i)).clone());
                Ok(())
            })
            .unwrap();
        }
        let depth = core.read(|d| d.undo_stack.len());
        assert_eq!(depth, 3, "应裁剪到 undo_keep");
        // 栈顶应是最新一条
        let last = core.read(|d| d.undo_stack.last().unwrap().payload.get_i64("i").unwrap());
        assert_eq!(last, 4);
    }

    #[test]
    fn undo_stack_zero_keep_clears() {
        let core = {
            let mut c = Core::new(
                &std::env::temp_dir().join(format!("sports_meet_test_undo_zero_{}", std::process::id())),
                std::path::Path::new("web"),
            );
            c.undo_keep = 0;
            Arc::new(c)
        };
        core.write(|d| {
            Core::push_undo(d, "test", Json::obj());
            Ok(())
        })
        .unwrap();
        assert_eq!(core.read(|d| d.undo_stack.len()), 0);
    }

    #[test]
    fn undo_history_order_newest_first() {
        let core = tmp_core("undo_order");
        for i in 0..3 {
            core.write(|d| {
                Core::push_undo(d, &format!("a{}", i), Json::obj());
                Ok(())
            })
            .unwrap();
        }
        let h = core.undo_history();
        let arr = h.get("history").unwrap().as_arr().unwrap();
        assert_eq!(arr.len(), 3);
        // 最新的 a2 应在最前
        assert_eq!(arr[0].get_str("action").unwrap(), "a2");
        assert_eq!(arr[2].get_str("action").unwrap(), "a0");
    }

    // ---------------- 数据持久化兼容（v1.1 -> v1.2） ----------------

    #[test]
    fn undo_stack_persistence_roundtrip() {
        let mut d = Data::default();
        Core::push_undo(&mut d, "delete_event", Json::obj());
        Core::push_undo(&mut d, "unregister", Json::obj());
        let j = d.to_json();
        let d2 = Data::from_json(&j).unwrap();
        assert_eq!(d2.undo_stack.len(), 2, "撤销栈应能往返序列化");
        assert_eq!(d2.undo_stack[0].action, "delete_event");
        assert_eq!(d2.undo_stack[1].action, "unregister");
    }

    #[test]
    fn legacy_single_undo_is_migrated() {
        // 模拟 v1.1 数据：只有一个 undo 字段
        let mut d = Data::default();
        d.events.push(Event {
            id: 1,
            name: "旧项目".into(),
            category: "径赛".into(),
            gender: "通用".into(),
            grade: "全部".into(),
            is_team: false,
            unit: "时间".into(),
            record: None,
        });
        let mut j = d.to_json();
        // 删掉新字段，写入旧格式
        if let Json::Obj(m) = &mut j {
            m.remove("undo_stack");
            let mut u = Json::obj();
            u.set("time", Json::s("2026-01-01 00:00:00"));
            u.set("action", Json::s("legacy_action"));
            u.set("payload", Json::obj());
            m.insert("undo".into(), u);
        }
        let d2 = Data::from_json(&j).unwrap();
        assert_eq!(d2.undo_stack.len(), 1, "v1.1 单条 undo 应迁移为单元素栈");
        assert_eq!(d2.undo_stack[0].action, "legacy_action");
    }

    // ---------------- 报表与统计 ----------------

    // ---------------- 报名表导入（v1.9.0） ----------------

    /// 造一个带两个**独有名称**项目的 Core（避开 seed_events 的预设名）：
    /// 通用项目 + 男子项目（返回 id 对）。
    fn baoming_core(tag: &str) -> (Arc<Core>, i64, i64) {
        let core = tmp_core(tag);
        let mk = |name: &str, gender: &str| {
            let mut j = Json::obj();
            j.set("name", Json::s(name));
            j.set("category", Json::s("径赛"));
            j.set("gender", Json::s(gender));
            j.set("grade", Json::s("全部"));
            j.set("unit", Json::s("时间"));
            j
        };
        let e1 = core.add_event(&mk("bm通用项", "通用")).unwrap();
        let e2 = core.add_event(&mk("男子bm项", "男子")).unwrap();
        (core, e1.get_i64("id").unwrap(), e2.get_i64("id").unwrap())
    }

    #[test]
    fn import_baoming_adds_students_and_registrations() {
        let (core, e_generic, e_male) = baoming_core("bm_ok");
        let mut body = Json::obj();
        body.set("ensure_grades", Json::Bool(true));
        let s = |name: &str, gender: &str| {
            let mut j = Json::obj();
            j.set("name", Json::s(name));
            j.set("grade", Json::s("奥创七"));
            j.set("class_no", Json::Int(7));
            j.set("gender", Json::s(gender));
            j
        };
        let r = |name: &str, event: &str, note: &str| {
            let mut j = Json::obj();
            j.set("name", Json::s(name));
            j.set("grade", Json::s("奥创七"));
            j.set("class_no", Json::Int(7));
            j.set("event", Json::s(event));
            j.set("note", Json::s(note));
            j
        };
        body.set(
            "students",
            Json::arr(vec![s("张三", "男"), s("李四", "男")]),
        );
        body.set(
            "registrations",
            Json::arr(vec![
                r("张三", "bm通用项", "第1跑道"),
                r("张三", "男子bm项", ""),
                r("李四", "bm通用项", ""),
            ]),
        );
        let out = core.import_baoming(&body).unwrap();
        assert_eq!(out.get_i64("added"), Some(2), "两名新学生");
        assert_eq!(out.get_i64("registrations_added"), Some(3), "三条报名");
        // 年级已自动补上
        assert_eq!(out.get("grades_added").and_then(|v| v.as_arr()).map(|a| a.len()), Some(1));
        let grades = core.read(|d| d.settings.grades.clone());
        assert!(grades.contains(&"奥创七".to_string()), "年级应已加入设置");
        // 数据落地：学生 + 报名关系
        let (ns, nr) = core.read(|d| (d.students.len(), d.registrations.len()));
        assert_eq!((ns, nr), (2, 3));
        // 备注落到了报名记录上
        let note = core.read(|d| {
            d.registrations
                .iter()
                .find(|x| x.event_id == e_generic)
                .map(|x| x.note.clone())
                .unwrap_or_default()
        });
        assert_eq!(note, "第1跑道");
        let _ = e_male;
    }

    #[test]
    fn import_baoming_rerun_is_idempotent() {
        let (core, _, _) = baoming_core("bm_rerun");
        let mut body = Json::obj();
        body.set("ensure_grades", Json::Bool(true));
        let s = |name: &str| {
            let mut j = Json::obj();
            j.set("name", Json::s(name));
            j.set("grade", Json::s("奥创七"));
            j.set("class_no", Json::Int(7));
            j.set("gender", Json::s("男"));
            j
        };
        let r = |name: &str| {
            let mut j = Json::obj();
            j.set("name", Json::s(name));
            j.set("grade", Json::s("奥创七"));
            j.set("class_no", Json::Int(7));
            j.set("event", Json::s("bm通用项"));
            j
        };
        body.set("students", Json::arr(vec![s("张三")]));
        body.set("registrations", Json::arr(vec![r("张三")]));
        let out1 = core.import_baoming(&body).unwrap();
        assert_eq!(out1.get_i64("added"), Some(1));
        // 再跑一遍：学生与报名都应判重跳过，不产生重复数据
        let out2 = core.import_baoming(&body).unwrap();
        assert_eq!(out2.get_i64("added"), Some(0), "重复导入不新增学生");
        assert_eq!(out2.get_i64("registrations_added"), Some(0), "重复导入不新增报名");
        let (ns, nr) = core.read(|d| (d.students.len(), d.registrations.len()));
        assert_eq!((ns, nr), (1, 1), "数据不翻倍");
    }

    #[test]
    fn import_roster_file_adds_students_only() {
        let (core, _, _) = baoming_core("roster_file");
        // 典型名单：只有姓名/年级/班级/性别/学号，没有项目列。
        let csv = "姓名,年级,班级,性别,学号\n张三,初一,1,男,2401\n李四,初一,2,女,2402\n";
        let mut body = Json::obj();
        body.set("filename", Json::s("名单.csv"));
        body.set("text", Json::s(csv));
        let out = core.import_roster_file(&body).unwrap();
        assert_eq!(out.get_i64("added"), Some(2), "两名学生入库");
        assert_eq!(out.get_i64("registrations_added"), Some(0), "名单导入不建报名");
        assert_eq!(
            out.get("parse_report").and_then(|r| r.get_str("mode")),
            Some("roster")
        );
        assert_eq!(core.read(|d| d.students.len()), 2);
        assert_eq!(core.read(|d| d.registrations.len()), 0, "不得产生任何报名");

        // 再导一次：不覆盖、不重复、不报错。
        let out2 = core.import_roster_file(&body).unwrap();
        assert_eq!(out2.get_i64("added"), Some(0), "重复名单应全部跳过");
        assert_eq!(core.read(|d| d.students.len()), 2, "名单不翻倍");
    }

    #[test]
    fn import_baoming_gender_constraint_reported() {
        let (core, _e_generic, e_male) = baoming_core("bm_gender");
        let mut body = Json::obj();
        body.set("ensure_grades", Json::Bool(true));
        let s = |name: &str, gender: &str| {
            let mut j = Json::obj();
            j.set("name", Json::s(name));
            j.set("grade", Json::s("初一"));
            j.set("class_no", Json::Int(1));
            j.set("gender", Json::s(gender));
            j
        };
        let r = |name: &str, event: &str| {
            let mut j = Json::obj();
            j.set("name", Json::s(name));
            j.set("grade", Json::s("初一"));
            j.set("class_no", Json::Int(1));
            j.set("event", Json::s(event));
            j
        };
        body.set("students", Json::arr(vec![s("王五", "女")]));
        // 女子报男子项目 → 被性别规则拦下，进 skipped
        body.set("registrations", Json::arr(vec![r("王五", "男子bm项")]));
        let out = core.import_baoming(&body).unwrap();
        assert_eq!(out.get_i64("added"), Some(1));
        assert_eq!(out.get_i64("registrations_added"), Some(0));
        let skipped = out.get("skipped").and_then(|v| v.as_arr()).unwrap();
        assert!(
            skipped.iter().any(|e| e.get_str("reason").map(|r| r.contains("限男子")).unwrap_or(false)),
            "性别不符应报告：{:?}",
            skipped
        );
        let _ = e_male;
    }

    #[test]
    fn import_baoming_unknown_event_reported() {
        let (core, _, _) = baoming_core("bm_event");
        let mut body = Json::obj();
        body.set("ensure_grades", Json::Bool(true));
        let s = |name: &str| {
            let mut j = Json::obj();
            j.set("name", Json::s(name));
            j.set("grade", Json::s("初一"));
            j.set("class_no", Json::Int(1));
            j.set("gender", Json::s("男"));
            j
        };
        let r = |name: &str, event: &str| {
            let mut j = Json::obj();
            j.set("name", Json::s(name));
            j.set("grade", Json::s("初一"));
            j.set("class_no", Json::Int(1));
            j.set("event", Json::s(event));
            j
        };
        body.set("students", Json::arr(vec![s("赵六")]));
        body.set("registrations", Json::arr(vec![r("赵六", "不存在的项目")]));
        let out = core.import_baoming(&body).unwrap();
        assert_eq!(out.get_i64("added"), Some(1), "学生仍应导入");
        assert_eq!(out.get_i64("registrations_added"), Some(0));
        let skipped = out.get("skipped").and_then(|v| v.as_arr()).unwrap();
        assert!(
            skipped.iter().any(|e| e.get_str("reason").map(|r| r.contains("项目不存在")).unwrap_or(false)),
            "未知项目应报告：{:?}",
            skipped
        );
    }

    #[test]
    fn import_baoming_event_id_and_normalized_name() {
        let (core, e_generic, _e_male) = baoming_core("bm_resolve");
        let mut body = Json::obj();
        body.set("ensure_grades", Json::Bool(true));
        let s = |name: &str| {
            let mut j = Json::obj();
            j.set("name", Json::s(name));
            j.set("grade", Json::s("初一"));
            j.set("class_no", Json::Int(1));
            j.set("gender", Json::s("男"));
            j
        };
        let r_by_id = |name: &str| {
            let mut j = Json::obj();
            j.set("name", Json::s(name));
            j.set("grade", Json::s("初一"));
            j.set("class_no", Json::Int(1));
            j.set("event_id", Json::Int(e_generic));
            j
        };
        // "男子100米" 归一化后命中 "100米"（去性别前缀）
        let r_by_norm = |name: &str| {
            let mut j = Json::obj();
            j.set("name", Json::s(name));
            j.set("grade", Json::s("初一"));
            j.set("class_no", Json::Int(1));
            j.set("event", Json::s("bm项"));
            j
        };
        body.set("students", Json::arr(vec![s("孙七"), s("周八")]));
        body.set("registrations", Json::arr(vec![r_by_id("孙七"), r_by_norm("周八")]));
        let out = core.import_baoming(&body).unwrap();
        assert_eq!(out.get_i64("registrations_added"), Some(2), "event_id 与归一化名称都应命中");
        let nr = core.read(|d| d.registrations.len());
        assert_eq!(nr, 2);
    }

    #[test]
    fn import_baoming_empty_students_rejected() {
        let (core, _, _) = baoming_core("bm_empty");
        let body = Json::obj();
        assert!(core.import_baoming(&body).is_err(), "空 students 必须报错");
    }

    #[test]
    fn stats_and_meta_shapes() {
        let core = tmp_core("stats");
        let s = core.stats_json();
        assert_eq!(s.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert!(s.get("events").is_some());
        assert!(s.get("students").is_some());
        let m = core.meta_json();
        assert_eq!(m.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert!(m.get("categories").is_some());
        assert!(m.get("points_table").is_some());
    }

    // ---------------- v1.9.3 一键清空报名 ----------------

    /// 造 3 名学生 / 4 条报名 / 2 条个人成绩，覆盖两个年级两个项目。
    fn seed_clear_regs(core: &Arc<Core>) {
        let eids = core.read(|d| d.events.iter().take(2).map(|e| e.id).collect::<Vec<_>>());
        core.write(|d| {
            d.students = vec![
                Student { id: 1, grade: "初一".into(), class_no: 1, name: "甲".into(), gender: "男".into() },
                Student { id: 2, grade: "初一".into(), class_no: 1, name: "乙".into(), gender: "女".into() },
                Student { id: 3, grade: "初二".into(), class_no: 2, name: "丙".into(), gender: "男".into() },
            ];
            d.next_student_id = 4;
            d.registrations = vec![
                Registration { id: 1, event_id: eids[0], student_id: 1, note: String::new() },
                Registration { id: 2, event_id: eids[1], student_id: 1, note: String::new() },
                Registration { id: 3, event_id: eids[0], student_id: 2, note: String::new() },
                Registration { id: 4, event_id: eids[0], student_id: 3, note: String::new() },
            ];
            d.next_reg_id = 5;
            d.results = vec![
                DomainResult {
                    id: 1, event_id: eids[0], student_id: Some(1), grade: "初一".into(),
                    class_no: None, score_text: "13.5".into(), score_value: Some(13.5),
                    rank: None, points: None, broke_record: false,
                },
                DomainResult {
                    id: 2, event_id: eids[0], student_id: Some(2), grade: "初一".into(),
                    class_no: None, score_text: "15.1".into(), score_value: Some(15.1),
                    rank: None, points: None, broke_record: false,
                },
            ];
            d.next_result_id = 3;
            Ok(())
        })
        .unwrap();
    }

    fn clear_body(scope: &str) -> Json {
        let mut b = Json::obj();
        b.set("scope", Json::s(scope));
        b
    }

    #[test]
    fn clear_registrations_preview_is_readonly_and_undo_restores_all() {
        let core = tmp_core("clear_regs_all");
        seed_clear_regs(&core);

        let q = clear_body("all");
        let pv = core.clear_registrations_preview(&q).unwrap();
        assert_eq!(pv.get_i64("registrations"), Some(4));
        assert_eq!(pv.get_i64("results"), Some(2), "连带删除的个人成绩应计入预检");
        assert_eq!(pv.get_i64("students"), Some(3));
        assert_eq!(core.read(|d| d.registrations.len()), 4, "预检不得改动数据");

        let err = core.clear_registrations(&q).unwrap_err();
        assert_eq!(err.status, 428, "不带 confirm 必须拦下");
        assert_eq!(core.read(|d| d.registrations.len()), 4);

        let mut q2 = q.clone();
        q2.set("confirm", Json::Bool(true));
        let out = core.clear_registrations(&q2).unwrap();
        assert_eq!(out.get_i64("removed"), Some(4));
        assert_eq!(out.get_i64("results_removed"), Some(2));
        assert_eq!(
            core.read(|d| (d.registrations.len(), d.results.len())),
            (0, 0)
        );
        let desc = core.peek_undo();
        assert!(
            desc.get("undo")
                .and_then(|u| u.get_str("description"))
                .unwrap_or("")
                .contains("清空"),
            "撤销历史应能说明这是一次清空"
        );

        core.undo_now().unwrap();
        assert_eq!(
            core.read(|d| (d.registrations.len(), d.results.len())),
            (4, 2),
            "一次撤销应全量恢复，而不是只回退一条"
        );
        let ids = core.read(|d| d.registrations.iter().map(|r| r.id).collect::<Vec<_>>());
        let mut uniq = ids.clone();
        uniq.sort_unstable();
        uniq.dedup();
        assert_eq!(uniq.len(), ids.len(), "恢复后不得产生重复 id");
    }

    #[test]
    fn clear_registrations_scope_is_exact() {
        let core = tmp_core("clear_regs_scope");
        seed_clear_regs(&core);
        let eids = core.read(|d| d.events.iter().take(2).map(|e| e.id).collect::<Vec<_>>());

        let mut by_event = clear_body("event");
        by_event.set("event_id", Json::Int(eids[0]));
        assert_eq!(
            core.clear_registrations_preview(&by_event)
                .unwrap()
                .get_i64("registrations"),
            Some(3)
        );

        let by_grade = clear_body("grade");
        let mut bg = by_grade.clone();
        bg.set("grade", Json::s("初一"));
        assert_eq!(
            core.clear_registrations_preview(&bg)
                .unwrap()
                .get_i64("registrations"),
            Some(3)
        );

        let mut by_class = clear_body("class");
        by_class.set("grade", Json::s("初一"));
        by_class.set("class_no", Json::Int(1));
        by_class.set("confirm", Json::Bool(true));
        let out = core.clear_registrations(&by_class).unwrap();
        assert_eq!(out.get_i64("removed"), Some(3));
        assert_eq!(
            core.read(|d| d.registrations.len()),
            1,
            "初二2班那条不应被误删"
        );
        assert_eq!(
            core.read(|d| d.results.len()),
            0,
            "被退报学生的成绩应连带删除"
        );

        // 范围参数缺失 / 非法都应明确报错，不能悄悄变成"清空全部"
        assert!(core.clear_registrations_preview(&clear_body("grade")).is_err());
        let mut bad = clear_body("unknown");
        bad.set("confirm", Json::Bool(true));
        assert!(core.clear_registrations(&bad).is_err());
    }

    // ---------------- v1.9.3 报名表模板 / 文件导入 ----------------

    fn rows_to_xlsx(rows: &[Vec<String>]) -> Vec<u8> {
        let mut wb = rust_xlsxwriter::Workbook::new();
        {
            let ws = wb.add_worksheet();
            for (ri, row) in rows.iter().enumerate() {
                for (ci, c) in row.iter().enumerate() {
                    ws.write(ri as u32, ci as u16, c.clone()).ok();
                }
            }
        }
        wb.save_to_buffer().unwrap()
    }

    #[test]
    fn baoming_template_xlsx_filled_roundtrip() {
        let core = tmp_core("bm_tpl_roundtrip");
        let events = core.read(|d| d.events.clone());
        let bytes = crate::core::export::baoming_template_xlsx(&events);
        assert!(bytes.starts_with(b"PK\x03\x04"), "模板应是合法 xlsx");
        let rows = crate::core::baoming::xlsx_rows(&bytes).unwrap();
        assert!(
            rows.iter().filter(|r| r.iter().any(|c| c.starts_with("姓名"))).count() >= 2,
            "模板的男女两节表头都应能读回"
        );

        // 模拟老师填表：删掉/保留示例行，在两节的空行里各填一名真实学生。
        let mut filled = crate::core::export::baoming_template_rows(&events);
        let male_row = 3; // 0 标题 / 1 表头 / 2 示例 / 3 起为空行
        filled[male_row][1] = "王五".into();
        filled[male_row][2] = "初一1".into();
        filled[male_row][3] = "√".into(); // 第一个项目列打勾
        let female_header = filled
            .iter()
            .position(|r| r.iter().any(|c| c.contains("姓名（女）")))
            .unwrap();
        let female_row = female_header + 2; // 跳过女生节示例行
        filled[female_row][1] = "赵六".into();
        filled[female_row][2] = "初一（2）班".into();
        filled[female_row][3] = "√".into();

        let xlsx = rows_to_xlsx(&filled);
        let mut body = Json::obj();
        body.set("filename", Json::s("填好的报名表.xlsx"));
        body.set("b64", Json::s(crate::core::baoming::b64_encode(&xlsx)));
        let out = core.import_baoming_file(&body).unwrap();
        assert_eq!(out.get_i64("added"), Some(2), "两名学生应入库");
        assert_eq!(out.get_i64("registrations_added"), Some(2));
        let rep = out.get("parse_report").unwrap();
        assert_eq!(rep.get_i64("example_skipped"), Some(2), "两节示例行都应跳过");
    }

    #[test]
    fn import_baoming_file_csv_is_idempotent() {
        let core = tmp_core("bm_file_csv");
        let csv = "\u{feff}序号,姓名（男）,班别,100米,备注\n\
                   1,张三（示例）,初一1,√,\n\
                   2,王五,初一1,√,\n\
                   序号,姓名(女）,班别,100米,备注\n\
                   3,赵六,初一（2）班,√,\n";
        let mut body = Json::obj();
        body.set("filename", Json::s("报名表.csv"));
        body.set("text", Json::s(csv));
        let out = core.import_baoming_file(&body).unwrap();
        assert_eq!(out.get_i64("added"), Some(2));
        assert_eq!(out.get_i64("registrations_added"), Some(2));
        assert_eq!(
            out.get("parse_report").unwrap().get_i64("example_skipped"),
            Some(1)
        );
        let again = core.import_baoming_file(&body).unwrap();
        assert_eq!(again.get_i64("added"), Some(0), "重复导入不得翻倍");
        assert_eq!(again.get_i64("registrations_added"), Some(0));
    }
}
