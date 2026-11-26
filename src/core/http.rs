//! 微型 HTTP 框架（核心模块）：基于 std::net，每连接一线程。
//! 支持路由注册（含 {param} 路径参数）、JSON 响应、静态文件、CSV 下载，
//! 以及 **SSE 流式推送**（v1.5 新增）。

use crate::core::api::Core;
use crate::core::error::{ApiErr, ApiResult};
use crate::core::json::{parse_query, url_decode, Json};
use crate::core::sync::LockExt;
use crate::{log_debug, log_error, log_info, log_warn};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;

/// HTTP 请求的完整表示。
/// method/path/headers 字段为语义完整而保留：路由分发已消化 method/path，
/// headers 供 handler 与扩展按需读取（v1.4）。
#[allow(dead_code)]
pub struct Request {
    pub method: String,
    /// 去掉查询串后的路径
    pub path: String,
    pub query: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// 请求头（v1.4）：键统一小写，供鉴权与 Content-Type 校验使用
    pub headers: HashMap<String, String>,
    /// 路由 {param} 匹配结果
    pub params: HashMap<String, String>,
    /// v1.5.1：本请求是否来自本机回环地址（TCP 对端，不可伪造）。
    pub from_loopback: bool,
    /// v1.5.1：本请求是否处于**开发者模式已解锁**状态。
    ///
    /// 该字段是三重条件的合取结果，由 `dispatch_inner` 统一计算后注入，
    /// handler 只读不写 —— handler 不得自行判定 devmode，否则容易漏掉
    /// 某个条件造成边界松动。
    pub dev_mode: bool,
}

impl Request {
    pub fn query_get(&self, key: &str) -> Option<String> {
        self.query
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.clone())
    }

    /// v1.6.0：取路径参数并**校验为正整数 id**。
    ///
    /// 背景：路径参数（`/api/events/{id}`）此前各处各自 `parse().unwrap_or(0)`，
    /// 于是 `/api/events/abc` 会静默变成 `id=0`，再去库里找不到就报
    /// "项目不存在" —— **真正的错误（id 写错了）被伪装成了业务错误**，
    /// 排查时看不到任何线索。这里把它前移为明确的参数错误。
    ///
    /// 返回 `E_VALIDATION` 错误码，客户端知道"是输入格式问题，别重试"。
    pub fn path_id(&self, key: &str) -> Result<i64, crate::core::error::ApiErr> {
        let raw = self
            .params
            .get(key)
            .map(|s| s.as_str())
            .unwrap_or("")
            .trim();
        if raw.is_empty() {
            return Err(crate::core::error::ApiErr::new(format!(
                "路径参数 {} 缺失",
                key
            )));
        }
        match raw.parse::<i64>() {
            Ok(n) if n > 0 => Ok(n),
            Ok(n) => Err(crate::core::error::ApiErr::new(format!(
                "路径参数 {} 必须为正整数，实际为 {}",
                key, n
            ))),
            Err(_) => Err(crate::core::error::ApiErr::new(format!(
                "路径参数 {} 必须是整数，实际为「{}」",
                key, raw
            ))),
        }
    }

    /// v1.6.0：取查询参数并校验为非空字符串。
    ///
    /// `None` / 空串 / 纯空白一律视为"未提供"，返回 `None`。
    /// 这是踩坑 #37 的**根因修复要点**：此前 `class_no=` 空串会被
    /// `parse::<i64>()` 解成 `Ok(0)`，语义从"不筛选"变成"筛选 0 号班"。
    /// 统一在入口把空串归一到 `None`，比在每个调用点各写一遍可靠。
    pub fn query_non_empty(&self, key: &str) -> Option<String> {
        self.query_get(key).filter(|v| !v.trim().is_empty())
    }

    /// v1.6.0：取查询参数并校验为正整数（可选）。
    ///
    /// 未提供 → `Ok(None)`；提供了但非正整数 → `E_VALIDATION`。
    /// 这样"没传"与"传错了"被明确区分开，不再都塌缩成 0。
    pub fn query_pos_int(&self, key: &str) -> Result<Option<i64>, crate::core::error::ApiErr> {
        match self.query_non_empty(key) {
            None => Ok(None),
            Some(raw) => match raw.parse::<i64>() {
                Ok(n) if n > 0 => Ok(Some(n)),
                Ok(n) => Err(crate::core::error::ApiErr::new(format!(
                    "查询参数 {} 必须为正整数，实际为 {}",
                    key, n
                ))),
                Err(_) => Err(crate::core::error::ApiErr::new(format!(
                    "查询参数 {} 必须是整数，实际为「{}」",
                    key, raw
                ))),
            },
        }
    }

    /// 请求体按 JSON 解析（空体返回空对象）。
    pub fn json(&self) -> Result<Json, String> {
        if self.body.is_empty() {
            return Ok(Json::obj());
        }
        let text = String::from_utf8_lossy(&self.body);
        Json::parse(&text)
    }
}

/// 响应体：一次性字节流，或**流式**（SSE）推送。
///
/// v1.5 新增 `Stream`：运动会长跑类项目一条成绩可能挂几十分钟，
/// 大屏必须持续推送而不能靠轮询。流式响应由 handler 自己持有
/// `StreamWriter` 写数据，写完后 drop 即结束（连接关闭）。
pub enum Body {
    /// 一次性发送（默认）
    Bytes(Vec<u8>),
    /// 流式推送：交给 handler 实现，包装函数负责收尾
    Stream(Box<dyn FnOnce(&mut StreamWriter) + Send>),
}

pub struct Response {
    pub status: u16,
    pub content_type: String,
    pub body: Body,
    pub filename: Option<String>,
    /// 额外响应头（v1.5：SSE 需要 `X-Accel-Buffering` 等）
    pub extra_headers: Vec<(String, String)>,
}

impl Clone for Response {
    fn clone(&self) -> Self {
        // Body::Stream 内含 FnOnce 无法 Clone；克隆语义仅用于一次性响应。
        // 遇到流式响应时退化为空体（实际调用链中不会发生，见下方说明）。
        let body = match &self.body {
            Body::Bytes(b) => Body::Bytes(b.clone()),
            Body::Stream(_) => Body::Bytes(Vec::new()),
        };
        Response {
            status: self.status,
            content_type: self.content_type.clone(),
            body,
            filename: self.filename.clone(),
            extra_headers: self.extra_headers.clone(),
        }
    }
}

impl Response {
    fn plain(status: u16, content_type: &str, body: Vec<u8>) -> Response {
        Response {
            status,
            content_type: content_type.into(),
            body: Body::Bytes(body),
            filename: None,
            extra_headers: Vec::new(),
        }
    }
    pub fn json(j: &Json) -> Response {
        Response::json_with_status(j, 200)
    }
    pub fn json_with_status(j: &Json, status: u16) -> Response {
        Response::plain(
            status,
            "application/json; charset=utf-8",
            j.to_string().into_bytes(),
        )
    }
    pub fn with_status(mut self, status: u16) -> Response {
        self.status = status;
        self
    }
    pub fn download(filename: &str, content_type: &str, body: &[u8]) -> Response {
        let mut r = Response::plain(200, content_type, body.to_vec());
        r.filename = Some(filename.into());
        r
    }
    /// 构造 SSE 流式响应（v1.5）。
    ///
    /// `producer` 收到一个 [`StreamWriter`]，可在里面 `loop` 推送事件。
    /// 长连接期间连接不关闭；客户端断开时 `write` 会失败，producer
    /// 据此退出循环（`StreamWriter::is_closed`）。
    pub fn sse(producer: impl FnOnce(&mut StreamWriter) + Send + 'static) -> Response {
        Response {
            status: 200,
            content_type: "text/event-stream; charset=utf-8".into(),
            body: Body::Stream(Box::new(producer)),
            filename: None,
            extra_headers: vec![
                // 反向代理（如 Nginx）不缓冲，保证事件即时到达
                ("X-Accel-Buffering".into(), "no".into()),
                ("Cache-Control".into(), "no-cache".into()),
            ],
        }
    }
}

/// SSE / 流式写出器：只暴露"发一条事件"所需的最小接口。
pub struct StreamWriter {
    stream: &'static mut TcpStream,
    closed: Arc<AtomicBool>,
    /// 是否按 HTTP/1.1 chunked 传输编码分帧写出。
    /// SSE 走 chunked（事先不知长度）；若将来做"边算边下载"可置 false
    /// 配合 `Connection: close` 裸流。
    chunked: bool,
}

impl StreamWriter {
    /// 底层写一帧（内部自动处理 chunked 分帧）。
    fn write_frame(&mut self, payload: &[u8]) -> bool {
        if self.closed.load(Ordering::SeqCst) {
            return false;
        }
        let ok = if self.chunked {
            let header = format!("{:x}\r\n", payload.len());
            self.stream.write_all(header.as_bytes()).is_ok()
                && self.stream.write_all(payload).is_ok()
                && self.stream.write_all(b"\r\n").is_ok()
        } else {
            self.stream.write_all(payload).is_ok()
        };
        if !ok || self.stream.flush().is_err() {
            self.closed.store(true, Ordering::SeqCst);
            return false;
        }
        true
    }

    /// 发送一条 SSE 事件。
    ///
    /// `event` 为事件名（客户端 `addEventListener` 用），`data` 为内容。
    /// 返回 `false` 表示客户端已断开，producer 应立即结束循环。
    pub fn send(&mut self, event: &str, data: &str) -> bool {
        // SSE 规范：data 中的换行需拆成多行 data: 字段
        let mut buf = String::new();
        if !event.is_empty() {
            buf.push_str("event: ");
            buf.push_str(event);
            buf.push('\n');
        }
        for line in data.split('\n') {
            buf.push_str("data: ");
            buf.push_str(line);
            buf.push('\n');
        }
        buf.push('\n'); // 事件结束标志
        self.write_frame(buf.as_bytes())
    }

    /// 发送一条注释行。SSE 注释可作**心跳**，防止中间设备回收空闲连接。
    ///
    /// 心跳是被动防断线的关键：多数反向代理/防火墙会把"超过 30~60 秒
    /// 无任何字节"的连接视为死连接。producer 应至少每 15 秒调一次。
    pub fn comment(&mut self, text: &str) -> bool {
        let buf = format!(": {}\n\n", text.replace('\n', " "));
        self.write_frame(buf.as_bytes())
    }

    /// 客户端是否已断开（producer 可用于主动退出）。
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// 结束流：写出 chunked 终止块。
    fn finish(&mut self) -> std::io::Result<()> {
        if self.closed.load(Ordering::SeqCst) || !self.chunked {
            return Ok(());
        }
        self.stream.write_all(b"0\r\n\r\n")?;
        self.stream.flush()
    }
}

/// 核心 handler 签名（v1.4：提取别名，简化 Route 定义并消除类型复杂度告警）。
pub type CoreHandler =
    dyn Fn(&Core, &Request) -> ApiResult<Response> + Send + Sync;

/// 把请求归类到限流档位（v1.6.0）。
///
/// 判定规则，按优先级从高到低：
///   1. **敏感路径**：换令牌、开发者模式解锁。这两处是"猜密码"的入口，
///      配额必须最严，且**不受方法影响**（它们恰好都是 POST）。
///   2. **只读 POST 白名单**：`/api/smart/parse` 是纯粹的文本解析，
///      与 `is_sensitive_path` 里的只读白名单保持同一份口径（规则 15：
///      凡影响"读写判定"的名单，改动时须两处一起审）。
///   3. **GET** → 读档。
///   4. **其余** → 写档。
///
/// 注意这里与 `is_write` 的判定**故意不完全相同**：限流是"防误用"，
/// 取宽（把不确定的归为写档，配额更保守）；而鉴权是"防越权"，取严。
/// 两者目的不同，别为了"看起来一致"而强行合并。
fn classify_bucket(method: &str, path: &str) -> crate::core::ratelimit::Bucket {
    use crate::core::ratelimit::Bucket;

    // 1. 敏感入口：防字典尝试
    if path == "/api/auth/token" || path.starts_with("/api/dev/") {
        return Bucket::Sensitive;
    }
    // 2. 只读 POST
    if path == "/api/smart/parse" {
        return Bucket::Read;
    }
    // 3. GET → 读
    if method == "GET" {
        return Bucket::Read;
    }
    // 4. 其余 → 写
    Bucket::Write
}

/// 把成功响应包进统一信封（v1.6.0）。
///
/// 仅包装 `application/json` 且非下载的响应；SSE 流与文件下载原样返回
/// （它们不是 JSON 文档，套信封会破坏协议）。
///
/// **重点：识别"藏在 Ok 里的错误"。** 历史代码里有若干 handler（例：扩展
/// 路由转发、`/api/dev/unlock` 的前置条件检查）以 `Ok(Response)` 返回
/// 非 2xx 状态码，错误文案写在 body 的 `error` 键里。若不识别，它们会被
/// 包成 `{"ok":true,"data":{"error":...}}` —— **状态码说失败、信封说成功**，
/// 客户端按 `ok` 分流就会走错分支。这里统一把它们改造成失败信封，
/// 保证"`ok` 字段 == 真实成败"这一不变式。
fn wrap_envelope(resp: Response) -> Response {
    use crate::core::envelope::{envelope_skip, err_envelope, ok_envelope};

    if envelope_skip(&resp.content_type, resp.filename.as_deref()) {
        return resp;
    }
    let bytes = match &resp.body {
        Body::Bytes(b) => b.clone(),
        // 流式响应不会走到这里（content_type 已被 envelope_skip 拦下），
        // 保险起见原样返回而不是把流吞掉。
        Body::Stream(_) => return resp,
    };
    let text = match std::str::from_utf8(&bytes) {
        Ok(t) => t,
        Err(_) => return resp, // 非 UTF-8 的 JSON 不可能，保守返回原样
    };
    let data = match Json::parse(text) {
        Ok(j) => j,
        Err(_) => return resp, // 解析失败说明本就不是合法 JSON，不强行包装
    };

    // 非 2xx 状态 + body 内有 error 文案 → 还原为失败信封。
    if resp.status >= 400 {
        if let Some(msg) = data.get("error").and_then(|v| v.as_str()) {
            let msg = msg.to_string();
            let mut err = ApiErr::with_status(msg, resp.status);
            // 把 body 里除 error 外的其余字段（如 reason / dev_mode）
            // 原样放进 detail，不丢信息；没有剩余字段就不加 detail。
            let detail = match data {
                Json::Obj(mut map) => {
                    map.remove("error");
                    Json::Obj(map)
                }
                other => other,
            };
            if !matches!(&detail, Json::Obj(m) if m.is_empty()) && !detail.is_null() {
                err = err.with_data(detail);
            }
            return Response::json_with_status(&err_envelope(&err), resp.status);
        }
    }

    let env = ok_envelope(Some(&data));
    Response::json_with_status(&env, resp.status)
}

pub struct Route {
    pub method: &'static str,
    pub path: &'static str,
    /// v1.4：返回类型改用统一别名 ApiResult<Response>（原 Result<Response, ApiErr>）。
    pub handler: Arc<CoreHandler>,
}

pub struct Router {
    pub core: Arc<Core>,
    pub routes: Vec<Route>,
    /// v1.6.0：请求限流器（滑窗计数，分读/写/敏感三档）
    pub limiter: crate::core::ratelimit::RateLimiter,
}

/// 路径模板匹配："/api/events/{id}" 匹配 "/api/events/3"，参数写入 params。
pub fn match_path(pattern: &str, path: &str) -> Option<HashMap<String, String>> {
    let pats: Vec<&str> = pattern.split('/').filter(|s| !s.is_empty()).collect();
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if pats.len() != segs.len() {
        return None;
    }
    let mut params = HashMap::new();
    for (p, s) in pats.iter().zip(segs.iter()) {
        if let Some(name) = p.strip_prefix('{').and_then(|x| x.strip_suffix('}')) {
            params.insert(name.to_string(), url_decode(s));
        } else if p != s {
            return None;
        }
    }
    Some(params)
}

impl Router {
    /// 组装路由：核心路由 + 扩展路由。
    ///
    /// v1.5：新增**重复路由检测** —— 同名 method+path 重复注册时打印 WARN
    /// （踩坑记录 #12 的整改：重复注册曾导致新实现被旧实现静默覆盖）。
    pub fn new(core: Arc<Core>) -> Self {
        let mut routes = core.routes();
        routes.extend(core.ext_routes());
        let route_count = routes.len();
        // 重复检测：key = METHOD + 空格 + path
        let mut seen: HashMap<String, usize> = HashMap::new();
        let mut dups: Vec<String> = Vec::new();
        for r in &routes {
            let key = format!("{} {}", r.method, r.path);
            let cnt = seen.entry(key.clone()).or_insert(0);
            *cnt += 1;
            if *cnt == 2 {
                dups.push(key);
            }
        }
        if !dups.is_empty() {
            log_warn!(
                "http",
                "检测到 {} 组重复路由（先注册者生效，请删除冗余实现）：{}",
                dups.len(),
                dups.join("；")
            );
        }
        log_info!("http", "路由表装配完成，共 {} 条", route_count);
        Router {
            core,
            routes,
            limiter: crate::core::ratelimit::RateLimiter::new(),
        }
    }

    /// 分发请求（v1.2：内置耗时统计与访问日志；v1.4：支持鉴权与 Content-Type 校验；
    /// v1.5.1：支持开发者模式判定，需知来源是否为本机）。
    ///
    /// 等价于 `dispatch_from(..., from_loopback = false)`，即**按最保守的
    /// 「非本机」处理**。保留它是为了给单元测试与嵌入式调用方一个不关心
    /// 来源的入口；真实服务路径走 `dispatch_from`。
    #[allow(dead_code)]
    pub fn dispatch(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        body: Vec<u8>,
        headers: HashMap<String, String>,
    ) -> Response {
        // 兼容入口：默认按「非本机」处理，安全边界取严的一侧。
        // 真实服务路径走 `dispatch_from`，会带上 TCP 对端地址。
        self.dispatch_from(method, path, query, body, headers, false)
    }

    /// 带来源信息的请求分发（v1.5.1；v1.6.0 加入限流）。
    ///
    /// `from_loopback` 由 `serve()` 依据 TCP 对端地址填充，**不可由请求头
    /// 推导** —— 这是开发者模式第二重条件的唯一可信来源。
    ///
    /// v1.6.0 起在此处做**限流预检**：超限直接返回 429，不进入 handler。
    /// 放在这一层而非 connection 层，是因为限流需要知道"这是读还是写"，
    /// 而那要解析出 method+path 之后才有答案。
    pub fn dispatch_from(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        body: Vec<u8>,
        headers: HashMap<String, String>,
        from_loopback: bool,
    ) -> Response {
        self.dispatch_from_ip(method, path, query, body, headers, from_loopback, "loopback")
    }

    /// v1.6.0：带来源 IP 的分发入口。
    ///
    /// `peer_ip` 仅用于限流分桶（本机聚合为 `loopback`，远端按 IP 分开计数），
    /// **不参与任何鉴权判定** —— 权限只认 `from_loopback` 这个布尔量，
    /// 避免"字符串 IP 比较"这种易错的判定方式被引入安全路径。
    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_from_ip(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        body: Vec<u8>,
        headers: HashMap<String, String>,
        from_loopback: bool,
        peer_ip: &str,
    ) -> Response {
        let started = std::time::Instant::now();

        // ---- v1.6.0 限流预检 ----
        let bucket = classify_bucket(method, path);
        let key = crate::core::ratelimit::RateLimiter::key_for(peer_ip, from_loopback);
        let decision = self.limiter.check(&key, bucket, from_loopback);
        let resp = if !decision.allowed {
            log_warn!(
                "http",
                "限流触发：{} {}（来源 {} / 档位 {} / 配额 {}/10s）",
                method,
                path,
                key,
                bucket.as_str(),
                decision.limit
            );
            let err = crate::core::error::ApiErr::limit(format!(
                "请求过于频繁（{} 档：10 秒内最多 {} 次），请 {} 秒后重试",
                bucket.as_str(),
                decision.limit,
                decision.retry_after
            ));
            let mut r = Response::json_with_status(
                &crate::core::envelope::err_envelope(&err),
                429,
            );
            // 通知客户端退避（标准头，浏览器/脚本可直接读）
            r.extra_headers
                .push(("Retry-After".into(), decision.retry_after.to_string()));
            r.extra_headers.push((
                "X-RateLimit-Limit".into(),
                decision.limit.to_string(),
            ));
            r.extra_headers.push(("X-RateLimit-Remaining".into(), "0".into()));
            r
        } else {
            let resp = self.dispatch_inner(method, path, query, body, headers, from_loopback);
            let mut resp = resp;
            // 把剩余配额回给客户端，便于前端感知"快到上限了"
            resp.extra_headers
                .push(("X-RateLimit-Limit".into(), decision.limit.to_string()));
            resp.extra_headers.push((
                "X-RateLimit-Remaining".into(),
                decision.remaining.to_string(),
            ));
            resp
        };

        let cost_ms = started.elapsed().as_secs_f64() * 1000.0;
        let status = resp.status;

        // v1.6.0：写入接口可观测统计（供诊断页展示）。
        // 只记聚合量，不记请求内容 —— 见 `HttpStats` 的说明。
        if let Ok(mut st) = self.core.http_stats.lock() {
            st.record(path, status, cost_ms);
            // 顺手把限流器的累计计数同步进来。
            // 限流器挂在 Router 上，而诊断接口只拿得到 &Core，
            // 因此在这里（唯一同时持有两者、且每个请求都会经过的地方）
            // 做一次同步，让诊断页读到一致的快照。
            let (allowed, rejected, sources) = self.limiter.stats();
            st.rate_allowed = allowed;
            st.rate_rejected = rejected;
            st.rate_sources = sources;
        }

        // 访问日志：WARN 及以上级别（4xx/5xx）标记出来，便于排查
        if status >= 500 {
            log_error!("http", "{} {} -> {} ({:.1}ms)", method, path, status, cost_ms);
        } else if status >= 400 {
            log_warn!("http", "{} {} -> {} ({:.1}ms)", method, path, status, cost_ms);
        } else {
            log_debug!("http", "{} {} -> {} ({:.1}ms)", method, path, status, cost_ms);
        }
        resp
    }

    /// v1.4 常量时间比较：口令比对不因前缀匹配提前返回。
    /// v1.5：提升为 `pub(crate)`，供 api.rs 的令牌校验复用。
    pub(crate) fn const_time_eq(a: &str, b: &str) -> bool {
        if a.len() != b.len() {
            return false;
        }
        a.bytes().zip(b.bytes()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
    }

    fn dispatch_inner(
        &self,
        method: &str,
        path: &str,
        query: &[(String, String)],
        body: Vec<u8>,
        headers: HashMap<String, String>,
        from_loopback: bool,
    ) -> Response {
        // ---- v1.5.1 开发者模式生效判定 ----
        // 三重条件的**最后一公里**：前两重（密钥匹配、风险确认）已在
        // `License` 构造时确定，第三重（来源为本机）在这里合入。
        //
        // `dev_mode` 一旦为真，本请求将：
        //   * 跳过敏感操作二次确认（428 预检）；
        //   * 允许访问 `/api/dev/*` 管理接口；
        //   * 审计条的 actor 记为 `devmode`（见下方审计写入点）。
        //
        // 安全性：`from_loopback` 直接来自 TCP 对端地址，客户端无法伪造。
        let dev_mode = from_loopback
            && self
                .core
                .license
                .as_ref()
                .map(|l| l.mode().is_unlocked())
                .unwrap_or(false);

        // ---- v1.5 安全加固：写操作鉴权（令牌优先，口令兜底） ----
        // 语义与 v1.4 保持兼容：未设口令 → 完全免鉴权。
        // 设了口令后，POST/DELETE 需满足以下任一：
        //   (a) `Authorization: Bearer <口令>`        —— v1.4 旧客户端/脚本兼容
        //   (b) `Authorization: Bearer <签名令牌>`     —— v1.5 推荐，带过期时间
        // 令牌由 `/api/auth/token` 用口令换取，避免口令在局域网上反复明文传输。
        let is_write = method == "POST" || method == "DELETE";
        // 例外一：换取令牌的接口本身不能要求令牌，否则构成"鸡生蛋"死锁
        // （客户端还没拿到令牌，拿什么来换令牌？）。它自己校验口令。
        // 例外二：纯计算类 POST 接口不落盘、不改变任何状态，只是让前端
        // "先看一眼解析结果"，因此和 GET 一样免除鉴权 —— 否则老师在录入页
        // 想预览一下成绩写法还得先登录，属于把只读能力误判成了写操作。
        // 例外三（v1.5.1）：`/api/dev/*` 是密钥机制的入口，自带一套更严格的
        // 三重条件（密钥 + 本机 + 风险确认）。若再要求普通口令，就形成新的
        // 死锁 —— 想解锁得先有口令，而解锁请求本身又要口令。**这是 v1.5.1
        // 实测发现的真实缺陷**：设了口令的实例上 `POST /api/dev/unlock` 返回
        // 401，诊断页签的解锁按钮完全失效。切记：鉴权白名单必须与本条
        // `is_sensitive_path` 的覆盖面一起审，别只看 HTTP 方法（规则 15）。
        let readonly_post = matches!(path, "/api/smart/parse");
        let is_dev_endpoint = path.starts_with("/api/dev/");
        let needs_auth = is_write
            && self.core.password.is_some()
            && path != "/api/auth/token"
            && !readonly_post
            && !is_dev_endpoint;
        if needs_auth {
            let given = headers
                .get("authorization")
                .and_then(|v| v.strip_prefix("Bearer "))
                .unwrap_or("");
            if !self.core.is_authorized(given) {
                let mut err = ApiErr::auth(
                    "需要管理员凭证：请先 POST /api/auth/token 换取令牌，或直接提供口令",
                );
                let mut detail = Json::obj();
                detail.set("auth_scheme", Json::s("token_or_password"));
                err = err.with_data(detail);
                return Response::json_with_status(
                    &crate::core::envelope::err_envelope(&err),
                    401,
                );
            }
        }
        // ---- v1.5 敏感操作二次确认（v1.5.1：开发者模式下跳过） ----
        // 删除项目/学生、清空成绩、全量导入四类动作一旦误触，损失面很大
        // （尤其成绩清空无法凭撤销完整恢复）。即便合法持有了令牌，也要求
        // 调用方在 `X-Confirm-Password` 头里再带一次口令 —— 相当于
        // "sudo 再验一次"。仅对这四个精确路径生效，不影响其他接口。
        //
        // **开发者模式的全部意义就在这里**：调试时反复清库、反复导入，
        // 每次都要输口令极度低效。解锁后本预检被跳过，但代价是：
        //   * 仅限本机（远程无法解锁）；
        //   * 每次动作都写审计，actor 标记 `devmode`，事后可追溯。
        // 换句话说，「便利」是用「可追溯」换来的，不是白拿的。
        if is_write
            && self.core.password.is_some()
            && is_sensitive_path(method, path)
            && !dev_mode
        {
            let given = headers
                .get("x-confirm-password")
                .map(|s| s.as_str())
                .unwrap_or("");
            let ok = match &self.core.password {
                Some(p) => Self::const_time_eq(given, p),
                None => true,
            };
            if !ok {
                let mut detail = Json::obj();
                detail.set("confirm_kind", Json::s("password"));
                let err = ApiErr::confirm(
                    "该操作需要二次确认：请在 X-Confirm-Password 头提供管理员口令",
                )
                .with_data(detail);
                return Response::json_with_status(
                    &crate::core::envelope::err_envelope(&err),
                    428,
                );
            }
        }
        // ---- v1.4 安全加固：CSRF 缓解 ----
        // 带请求体的 POST 必须声明 application/json。跨站表单/简单请求
        // 无法携带该 Content-Type，可在未设口令的默认部署下挡住最基础的
        // 跨站写攻击。CSV 导入亦为 JSON 包裹（text 字段），故统一放行。
        if method == "POST" && !body.is_empty() {
            let ct = headers.get("content-type").map(|s| s.as_str()).unwrap_or("");
            if !ct.starts_with("application/json") {
                let err = ApiErr::payload("请求体必须为 application/json");
                return Response::json_with_status(
                    &crate::core::envelope::err_envelope(&err),
                    415,
                );
            }
        }
        // ---- v1.8.0 授权门禁（服务端密钥校验）----
        //
        // 语义：当实例启用了服务端授权（`aim` 为 Some）且配置为强制
        // （`aim_enforce`），而当前授权判定**未通过**时：
        //
        //   * 放行一组"授权自助接口"：状态查询、激活、校验、停用；
        //   * 放行静态页面（否则用户看不到激活界面，陷入死锁）；
        //   * 其余业务接口一律 403，并返回**可执行**的激活指引。
        //
        // 设计要点（踩坑预防）：
        // 1. **必须放行静态页**。若把 `/` 也拦掉，用户打开就是一片 JSON
        //    错误，连"在哪儿输密钥"都看不到 —— 这是最容易犯的错。
        // 2. `aim` 为 None（未启用授权）时本判定**恒为放行**，
        //    因此 v1.7.0 的行为完全不受影响（规则 20：老数据/老配置零迁移）。
        // 3. 判定结果来自 `AuthManager::last_decision()`（启动时算好 + 
        //    激活后刷新），**不在每个请求里发网络请求** —— 否则断网时
        //    每个请求都要等 3 秒超时，界面会卡死。
        let blocked_by_aim = if let Some(m) = self.core.aim.as_ref() {
            if self.core.aim_enforce && !aim_path_allowed(path) {
                // v1.9.0：不再只看启动时快照。密钥过期 / 配额耗尽 /
                // 试用到时必须在**当前请求**生效，否则长跑的服务器会
                // 凭过期快照一直放行（见 AuthManager::recheck_gate）。
                let mut mgr = m.lock_recover();
                !mgr.recheck_gate()
            } else {
                false
            }
        } else {
            false
        };
        if blocked_by_aim {
            let mut detail = Json::obj();
            detail.set("aim_state", Json::s("denied"));
            detail.set(
                "howto",
                Json::s("请在「诊断 → 软件授权」中粘贴 48 位激活密钥并激活（完全离线），或联系管理员获取授权"),
            );
            let err = ApiErr::with_status(
                "本软件尚未获得有效授权：请先在「诊断 → 软件授权」页输入激活密钥完成激活（离线即可，无需联网）",
                403,
            )
            .with_data(detail);
            return Response::json_with_status(&crate::core::envelope::err_envelope(&err), 403);
        }

        // 核心路由
        for r in &self.routes {
            if r.method != method {
                continue;
            }
            if let Some(params) = match_path(r.path, path) {
                let req = Request {
                    method: method.into(),
                    path: path.into(),
                    query: query.to_vec(),
                    body,
                    headers,
                    params,
                    from_loopback,
                    dev_mode,
                };
                // v1.6.0：成功响应统一套信封。**这是唯一的成功包装点** ——
                // 全部 47 条核心路由都从这里出，无需逐个改 handler，
                // 也就不会出现"漏包一条"的破窗。
                // 例外（SSE / 文件下载 / 非 JSON）由 envelope_skip 判定后原样返回。
                let resp = (r.handler)(&self.core, &req).unwrap_or_else(|e| {
                    // v1.6.0：错误统一走信封，携带稳定错误码
                    let o = crate::core::envelope::err_envelope(&e);
                    Response::json_with_status(&o, e.status)
                });
                return wrap_envelope(resp);
            }
        }
        // 静态文件
        if method == "GET" && !path.starts_with("/api/") {
            if let Some(resp) = self.serve_static(path) {
                return resp;
            }
        }
        let e = ApiErr::not_found(format!("未知接口：{} {}", method, path));
        Response::json_with_status(&crate::core::envelope::err_envelope(&e), 404)
    }

    /// 静态文件服务。
    ///
    /// v1.2 安全加固：拒绝路径穿越（`..`、绝对路径、盘符、空字节）。
    /// 原实现直接 `join(trim_start_matches('/'))`，`/../../etc/passwd`
    /// 这类请求在 Windows 上同样可以逃逸 web 根目录。
    ///
    /// v1.5.1 资源内嵌：`index.html` 已通过 `include_str!` 编入可执行文件
    /// （见 `EMBEDDED_INDEX`）。查找顺序为：
    ///   1. `--web` 指定的目录（便于现场热修界面，无需重编译）
    ///   2. 内嵌资源（**默认路径**，单文件分发时唯一可用）
    ///
    /// 这样打包只需一个 exe，且源码/资源不再以明文文件形式躺在安装目录里
    /// —— 想改界面就得反编译，门槛比改一个 html 文件高得多。
    fn serve_static(&self, path: &str) -> Option<Response> {
        if !is_safe_static_path(path) {
            log_warn!("http", "拒绝可疑静态路径：{}", path);
            return None;
        }
        let rel = if path == "/" { "/index.html" } else { path };
        let file_path = self
            .core
            .web_dir
            .join(rel.trim_start_matches('/'));

        // 1) 优先读磁盘（--web 热修场景）
        let body = match std::fs::read(&file_path) {
            Ok(b) => b,
            Err(_) => {
                // 2) 磁盘没有 → 回退到内嵌资源
                if rel == "/index.html" {
                    EMBEDDED_INDEX.as_bytes().to_vec()
                } else {
                    log_debug!("http", "静态资源不存在且无内嵌副本：{}", rel);
                    return None;
                }
            }
        };
        let ct = match file_path.extension().and_then(|e| e.to_str()) {
            Some("html") => "text/html; charset=utf-8",
            Some("js") => "text/javascript; charset=utf-8",
            Some("css") => "text/css; charset=utf-8",
            Some("png") => "image/png",
            Some("svg") => "image/svg+xml",
            Some("ico") => "image/x-icon",
            Some("json") => "application/json; charset=utf-8",
            Some("txt") => "text/plain; charset=utf-8",
            _ => "application/octet-stream",
        };
        Some(Response::plain(200, ct, body))
    }
}

/// 内嵌的前端页面（v1.5.1）。
///
/// 用 `include_str!` 在**编译期**把 `web/index.html` 塞进二进制。
/// 效果：
/// * 单文件分发 —— 拷一个 exe 就能跑，不用带 web 目录；
/// * 资源不可见 —— 安装目录里没有 html 明文，改界面需反编译；
/// * 版本一致 —— 界面与后端**同一次编译**产出，不存在"界面是最新的、
///   后端是旧的"这类错配（现场最常见的一类诡异 bug）。
///
/// 代价：改一行 html 就要重编译（约 2 秒），且二进制大 117 KB。
/// 两者权衡后认为划算 —— 想热修仍可用 `--web` 覆盖。
pub const EMBEDDED_INDEX: &str = include_str!("../../web/index.html");

/// 判定是否为本地回环来源（v1.5.1）。
///
/// 开发者模式解锁的**第二重条件**：请求必须来自本机。这样即使有人
/// 在局域网另一台机器上猜出了密钥，也无法远程解锁。
///
/// 判定规则（从严）：
/// * `127.0.0.0/8`  —— 整个回环段，含 `127.0.0.2` 等
/// * `::1`          —— IPv6 回环
/// * IPv4-mapped 形式 `::ffff:127.x.x.x`（双栈监听时常见）
///
/// **刻意不认**「同网段」「局域网 IP」—— 那不叫本机。
/// 也**不**信任任何请求头（`X-Forwarded-For` 之类），因为那是客户端
/// 可伪造的；只看 TCP 层的对端地址。
pub fn is_loopback(addr: &std::net::SocketAddr) -> bool {
    match addr.ip() {
        std::net::IpAddr::V4(v4) => v4.is_loopback(),
        std::net::IpAddr::V6(v6) => {
            if v6.is_loopback() {
                return true;
            }
            // IPv4-mapped：::ffff:a.b.c.d —— 取低 32 位再判
            if let Some(v4) = v6.to_ipv4_mapped() {
                return v4.is_loopback();
            }
            false
        }
    }
}

/// 判定是否为需要二次确认的敏感写操作（v1.5）。
///
/// 只精确匹配四个高损失动作，避免把整个 API 面都变成"要输两遍密码"：
/// * `DELETE /api/events/{id}`           删除项目（连带成绩）
/// * `DELETE /api/students/{id}`         删除学生（连带报名与成绩）
/// * `POST   /api/results/clear`         清空项目成绩
/// * `POST   /api/import/json`           全量导入（覆盖现有数据）
///
/// 刻意**不含** `?confirm=1` 预检流程本身——预检是只读的 GET，
/// 不存在误伤；确认动作落在随后的 DELETE 上，此处已覆盖。
pub fn is_sensitive_path(method: &str, path: &str) -> bool {
    if method == "DELETE" {
        return path.starts_with("/api/events/") || path.starts_with("/api/students/");
    }
    if method == "POST" {
        return path == "/api/results/clear"
            || path == "/api/import/json"
            || path == "/api/registrations/clear";
    }
    false
}

/// 授权门禁允许放行的路径（v1.8.0）。
///
/// 只放行两类：
/// * **授权自助接口** `/api/aim/*` —— 不放行则用户无法激活，形成死锁；
/// * **非 API 的静态资源**（首页 HTML / 脚本 / 图标）—— 不放行则用户
///   看到的只是一段错误 JSON，找不到激活入口。
///
/// 刻意**不放行** `/api/meta`、`/api/stats` 等业务接口：授权未通过时
/// 这些数据不应下发（否则"读数据"本身就构成部分可用，削弱门禁意义）。
pub fn aim_path_allowed(path: &str) -> bool {
    path.starts_with("/api/aim/") || !path.starts_with("/api/")
}

/// 判定静态资源路径是否安全（v1.2）。
///
/// 规则：
///   * 必须为空或含 `/` 开头之外的普通段；
///   * 任一段不得为 `..` 或 `.`；
///   * 不得含空字节 `\0`；
///   * 不得含反斜杠（Windows 路径分隔符）；
///   * 不得含 `:`（盘符 / NTFS 数据流）。
pub fn is_safe_static_path(path: &str) -> bool {
    if path.contains('\0') || path.contains('\\') || path.contains(':') {
        return false;
    }
    for seg in path.split('/') {
        if seg == ".." || seg == "." {
            return false;
        }
    }
    true
}

/// 请求体大小上限（v1.2 安全加固）：1 MiB。
/// 防止恶意超长 Content-Length 造成内存耗尽。导入类接口的正常载荷
/// （一所中学的全部成绩 JSON）远低于此量级。
const MAX_BODY_BYTES: usize = 1024 * 1024;

/// read_request 的解析结果：
/// `(方法, 路径, 查询串, 请求体, 请求头, 读取器已缓冲的残留字节)`
///
/// 最后一项用于**流式响应**（v1.5）：`BufReader` 会一次读入远多于请求头
/// 的字节，若直接丢弃，后续 SSE 写入前若有客户端数据就会丢包。
/// 正常请求-响应模型下该值恒为空，故对既有行为零影响。
type ParsedRequest = (
    String,
    String,
    Vec<(String, String)>,
    Vec<u8>,
    HashMap<String, String>,
    Vec<u8>,
);

/// 单次读取的最大请求头字节数（v1.5）：防止客户端持续发送垃圾头。
/// 一行限 8 KiB，整体头区限 64 KiB —— 正常浏览器请求头远小于此。
const MAX_HEADER_LINE: usize = 8 * 1024;
const MAX_HEADER_TOTAL: usize = 64 * 1024;

/// 以字节粒度读取一行（含 `\n`），返回不含行尾的字节。
/// 返回 None 表示连接结束或超长/超限。
fn read_line_bytes<R: BufRead>(reader: &mut R, total: &mut usize) -> Option<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    loop {
        let mut b = [0u8; 1];
        match reader.read(&mut b) {
            Ok(0) => return None, // 连接提前关闭
            Ok(_) => {}
            Err(_) => return None,
        }
        *total += 1;
        if *total > MAX_HEADER_TOTAL || out.len() > MAX_HEADER_LINE {
            return None;
        }
        if b[0] == b'\n' {
            break;
        }
        out.push(b[0]);
    }
    // 去掉行尾 \r
    if out.last() == Some(&b'\r') {
        out.pop();
    }
    Some(out)
}

fn read_request(stream: &mut TcpStream) -> Option<ParsedRequest> {
    let mut reader = BufReader::new(stream);
    let mut total = 0usize;

    let line = read_line_bytes(&mut reader, &mut total)?;
    let line = String::from_utf8_lossy(&line).into_owned();
    let mut parts = line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?.to_string();

    let mut content_length = 0usize;
    // v1.4：收集全部请求头（键小写化），供鉴权与 Content-Type 校验
    let mut headers: HashMap<String, String> = HashMap::new();
    loop {
        let h = read_line_bytes(&mut reader, &mut total)?;
        if h.is_empty() {
            break;
        }
        let h = String::from_utf8_lossy(&h).into_owned();
        if let Some((k, v)) = h.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().unwrap_or(0);
            }
        }
    }
    // v1.9.3：报名表 xlsx 以 base64 放进 JSON，体积约为原文件的 4/3；
    // 1 MiB 会被稍大一点的 Excel 顶爆。只对这个精确路径放宽到 8 MiB，
    // 其余接口维持 1 MiB 的既有边界（本机单机服务，8 MiB 无现实风险）。
    let body_limit = if target.starts_with("/api/import/baoming_file") {
        8 * 1024 * 1024
    } else {
        MAX_BODY_BYTES
    };
    // v1.2 安全：拒绝超大请求体，避免内存耗尽
    if content_length > body_limit {
        log_warn!(
            "http",
            "拒绝超大请求体：{} 字节（上限 {} 字节）{} {}",
            content_length,
            body_limit,
            method,
            target
        );
        return None;
    }
    let mut body = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body).ok()?;
    }
    // v1.5：把已缓冲但属于"后续字节"的部分交还调用方（流式响应需要）
    let leftover = reader.buffer().to_vec();

    let (path, query_str) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.clone(), String::new()),
    };
    let query = parse_query(&query_str);
    Some((method, path, query, body, headers, leftover))
}

fn write_response(stream: &mut TcpStream, resp: Response, leftover: Vec<u8>) {
    match resp.body {
        Body::Bytes(bytes) => {
            let mut head = format!("HTTP/1.1 {} {}\r\n", resp.status, status_text(resp.status));
            head.push_str(&format!("Content-Type: {}\r\n", resp.content_type));
            head.push_str(&format!("Content-Length: {}\r\n", bytes.len()));
            for (k, v) in &resp.extra_headers {
                head.push_str(&format!("{}: {}\r\n", k, v));
            }
            if !resp
                .extra_headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("cache-control"))
            {
                head.push_str("Cache-Control: no-store\r\n");
            }
            if let Some(name) = &resp.filename {
                // ASCII 安全文件名（浏览器会自行解码 UTF-8 名称需 RFC5987）
                head.push_str(&format!(
                    "Content-Disposition: attachment; filename*=UTF-8''{}\r\n",
                    encode_uri_component(name)
                ));
            }
            // v1.5：HTTP/1.1 默认长连接。此前一律 `Connection: close`，
            // 而 `read_request` 的行式读取用 `read(&mut [u8;1])` 逐字节推进，
            // 不会把后续请求吞进缓冲区，因此可以安全地支持 keep-alive。
            // 收益：浏览器的连接复用生效，仪表盘数十个请求不必反复握手。
            let close = resp
                .extra_headers
                .iter()
                .any(|(k, v)| k.eq_ignore_ascii_case("connection") && v.contains("close"));
            if close {
                head.push_str("Connection: close\r\n");
            } else {
                head.push_str("Connection: keep-alive\r\n");
            }
            head.push_str("\r\n");
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&bytes);
            let _ = stream.flush();
        }
        Body::Stream(producer) => {
            // v1.5：SSE / 流式响应。HTTP/1.1 用 chunked 传输编码，
            // 事先不声明长度，边写边发；结束时写 0 长度块。
            let mut head = format!("HTTP/1.1 {} {}\r\n", resp.status, status_text(resp.status));
            head.push_str(&format!("Content-Type: {}\r\n", resp.content_type));
            head.push_str("Transfer-Encoding: chunked\r\n");
            // 流式响应结束即断开（无法在流中协商下一个请求的边界）
            head.push_str("Connection: close\r\n");
            for (k, v) in &resp.extra_headers {
                head.push_str(&format!("{}: {}\r\n", k, v));
            }
            head.push_str("\r\n");
            if stream.write_all(head.as_bytes()).is_err() || stream.flush().is_err() {
                return;
            }
            let closed = Arc::new(AtomicBool::new(false));
            // 生命周期处理说明：`StreamWriter::stream` 声明为 `&'static mut`，
            // 是为了让 `StreamWriter` 自身不携带生命周期参数（从而可以被
            // `Vec<Box<dyn ...>>`、闭包捕获等场景自由使用）。
            // 这里通过裸指针把调用方借来的 `&mut TcpStream` 转化为
            // 'static —— 安全性由以下三点保证：
            //   1. `stream` 的生命周期在 `write_response` 全程有效，
            //      且本函数在 `producer` 返回前不会提前结束；
            //   2. `producer` 是 `FnOnce`，由本函数同步调用，不会逃逸；
            //   3. `w` 在函数结束时 drop，之后不再有任何别名。
            // 即：不存在比 `stream` 活得更久的 StreamWriter。
            let raw: *mut TcpStream = stream;
            let stream_ref: &'static mut TcpStream = unsafe { &mut *raw };
            let mut w = StreamWriter {
                stream: stream_ref,
                closed: Arc::clone(&closed),
                chunked: true,
            };
            // v1.5：缓冲区里可能已有"客户端提前发来的字节"。
            // 对 SSE 而言这通常是空；非空时丢弃并记录 —— 不做推测性处理，
            // 因为把未知字节塞回流里比丢弃更危险（可能拼接出畸形帧）。
            if !leftover.is_empty() {
                log_debug!(
                    "http",
                    "流式响应前缓冲区有 {} 字节残留，已丢弃",
                    leftover.len()
                );
            }
            producer(&mut w);
            // 收尾：即使 producer 正常返回（或已检测到断开），
            // 也尝试写出终止块；失败静默即可（客户端已走）。
            let _ = w.finish();
        }
    }
}

fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        428 => "Precondition Required",
        // v1.6.0：限流返回 429。之前落到 `_` 分支会拼出 "HTTP/1.1 429 OK"，
        // 语义矛盾且会被严格的客户端 / 中间件判为异常。
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        // 兜底：绝不返回 "OK"，避免非 2xx 被误读为成功短语
        c if c >= 500 => "Internal Server Error",
        _ => "Bad Request",
    }
}

pub fn encode_uri_component(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{:02X}", b)),
        }
    }
    out
}

/// 连接读/写超时（v1.4 安全加固）：防 slowloris 类慢速攻击长期占用线程。
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// 流式连接（SSE）的**写**超时单独放宽（v1.5）。
///
/// 原因：`IO_TIMEOUT=30s` 是为"请求-响应"设计的，但 SSE 连接可能
/// 静默数分钟（例如跳高项目正在比赛、无人破纪录）。若沿用 30s，
/// 每次心跳间隔宽松一点就会被服务端主动断开。
/// 这里放宽到 1 小时，并要求 producer 每 15 秒发一次心跳注释，
/// 从而使"实际写操作"始终远小于该超时。
const STREAM_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3600);

/// 并发处理线程上限（v1.4 安全加固）：超限立即返回 503 并断开，
/// 防止瞬时连接洪水导致线程/内存耗尽。
const MAX_CONCURRENT: usize = 64;

pub fn serve(addr: &str, router: Arc<Router>) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    log_info!("http", "已绑定 {}", addr);
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                log_warn!("http", "接受连接失败：{}", e);
                continue;
            }
        };
        // v1.4：读写超时（防 slowloris——只发半个请求头长期挂住连接）
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        // v1.4：并发上限（防线程耗尽），超限直接 503 并断开
        if active.load(Ordering::SeqCst) >= MAX_CONCURRENT {
            log_warn!("http", "并发连接已达上限 {}，拒绝新连接", MAX_CONCURRENT);
            let mut stream = stream;
            let mut o = Json::obj();
            o.set("error", Json::s("服务器繁忙，请稍后重试"));
            write_response(&mut stream, Response::json_with_status(&o, 503), Vec::new());
            continue;
        }
        active.fetch_add(1, Ordering::SeqCst);
        let router = Arc::clone(&router);
        let active = Arc::clone(&active);
        // v1.5.1：记录本连接的对端地址，用于开发者模式的「本机来源」判定。
        // 必须在 spawn 之前取好 —— 之后 stream 所有权已转移。
        // v1.6.0：同时保留 IP 字符串供限流分桶（本机聚合为 loopback）。
        let peer = stream.peer_addr().ok();
        let from_loopback = peer.map(|a| is_loopback(&a)).unwrap_or(false);
        let peer_ip = peer.map(|a| a.ip().to_string()).unwrap_or_else(|| "unknown".into());
        std::thread::spawn(move || {
            let mut stream = stream;
            // v1.5：单连接内循环处理多个请求（HTTP/1.1 keep-alive）。
            // 仅对**一次性响应**循环；流式响应处理后立即结束连接。
            loop {
                let parsed = read_request(&mut stream);
                let (method, path, query, body, headers, leftover) = match parsed {
                    Some(p) => p,
                    None => {
                        // 读请求失败（含超大体拒绝、空闲超时）：返回 400，
                        // 避免客户端悬挂；随后关闭连接。
                        log_debug!("http", "请求读取失败或被拒绝，已断开连接");
                        let mut o = Json::obj();
                        o.set("error", Json::s("请求无法解析或超出大小限制"));
                        write_response(
                            &mut stream,
                            Response::json_with_status(&o, 400),
                            Vec::new(),
                        );
                        break;
                    }
                };
                let want_close = headers
                    .get("connection")
                    .map(|v| v.to_ascii_lowercase().contains("close"))
                    .unwrap_or(false);
                let mut resp = router.dispatch_from_ip(
                    &method,
                    &path,
                    &query,
                    body,
                    headers,
                    from_loopback,
                    &peer_ip,
                );
                let is_stream = matches!(resp.body, Body::Stream(_));
                if is_stream {
                    // v1.5：流式响应（SSE）长连接需要宽松的写超时
                    let _ = stream.set_write_timeout(Some(STREAM_WRITE_TIMEOUT));
                    write_response(&mut stream, resp, leftover);
                    break; // 流结束后连接不再复用
                }
                if want_close {
                    resp.extra_headers
                        .push(("Connection".into(), "close".into()));
                }
                write_response(&mut stream, resp, leftover);
                if want_close {
                    break;
                }
            }
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_paths_allowed() {
        assert!(is_safe_static_path("/"));
        assert!(is_safe_static_path("/index.html"));
        assert!(is_safe_static_path("/assets/app.js"));
        assert!(is_safe_static_path("/a/b/c.css"));
    }

    #[test]
    fn path_traversal_rejected() {
        assert!(!is_safe_static_path("/../etc/passwd"));
        assert!(!is_safe_static_path("/a/../../b"));
        assert!(!is_safe_static_path("/./a"));
        assert!(!is_safe_static_path("/a/.."));
        // Windows 风格逃逸
        assert!(!is_safe_static_path("/..\\..\\windows\\system32"));
        assert!(!is_safe_static_path("\\..\\secret"));
        // 盘符 / NTFS 数据流
        assert!(!is_safe_static_path("/C:/windows"));
        assert!(!is_safe_static_path("/file.txt:stream"));
        // 空字节截断
        assert!(!is_safe_static_path("/index.html\0.jpg"));
    }

    #[test]
    fn route_matching_params() {
        let p = match_path("/api/events/{id}", "/api/events/42").unwrap();
        assert_eq!(p.get("id").unwrap(), "42");
        assert!(match_path("/api/events/{id}", "/api/events/42/extra").is_none());
        assert!(match_path("/api/events", "/api/students").is_none());
    }

    #[test]
    fn route_matching_url_decodes_params() {
        let p = match_path("/api/x/{name}", "/api/x/%E5%88%9D%E4%B8%80").unwrap();
        assert_eq!(p.get("name").unwrap(), "初一");
    }

    #[test]
    fn const_time_eq_basics() {
        assert!(Router::const_time_eq("secret", "secret"));
        assert!(!Router::const_time_eq("secret", "secreT"));
        assert!(!Router::const_time_eq("secret", "secret1"));
        assert!(!Router::const_time_eq("", "s"));
        assert!(Router::const_time_eq("", ""));
    }

    #[test]
    fn loopback_detection_v4() {
        use std::net::SocketAddr;
        let cases: &[(&str, bool)] = &[
            ("127.0.0.1:1234", true),
            ("127.0.0.2:80", true),      // 整个 127/8 段
            ("127.255.255.254:9", true),
            ("0.0.0.0:80", false),       // 通配地址不是回环
            ("192.168.1.10:80", false),  // 局域网不是本机
            ("10.0.0.5:80", false),
            ("8.8.8.8:53", false),
        ];
        for (s, want) in cases {
            let a: SocketAddr = s.parse().unwrap();
            assert_eq!(is_loopback(&a), *want, "判定错误：{}", s);
        }
    }

    #[test]
    fn loopback_detection_v6() {
        use std::net::SocketAddr;
        let cases: &[(&str, bool)] = &[
            ("[::1]:80", true),
            ("[::ffff:127.0.0.1]:80", true), // IPv4-mapped 回环
            ("[::ffff:192.168.1.1]:80", false),
            ("[2001:db8::1]:80", false),     // 公网 v6
        ];
        for (s, want) in cases {
            let a: SocketAddr = s.parse().unwrap();
            assert_eq!(is_loopback(&a), *want, "判定错误：{}", s);
        }
    }
}
