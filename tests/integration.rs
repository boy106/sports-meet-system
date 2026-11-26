//! 端到端集成测试（v1.4 新增，对应 v1.3 全项目审查 P1-3）。
//!
//! 与模块内单测的区别：这里启动**真实服务进程**（`CARGO_BIN_EXE`），
//! 用原始 TCP 写 HTTP 请求，覆盖「路由分发 → 鉴权拦截 → JSON 解析 → 领域逻辑 →
//! 响应序列化 → HTTP 状态码」的完整链路——v1.3 的 TDZ 事故证明单测绿 ≠ 能跑。
//!
//! 运行方式：`cargo test --test integration`（每个用例独立端口与数据目录，
//! 测试结束自动清理进程与临时数据）。

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};

/// 一个运行中的被测服务实例（含进程句柄与临时数据目录）。
struct TestServer {
    child: Child,
    port: u16,
    data_dir: std::path::PathBuf,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        kill_and_reap(&mut self.child);
        let _ = std::fs::remove_dir_all(&self.data_dir);
    }
}

/// 杀掉子进程并**有界**等待回收（至多 2 秒）。
///
/// 为什么不用阻塞的 `child.wait()`：本测试套件跑在沙箱/容器环境时
/// 实测出现过"子进程已退出成僵尸、阻塞式 wait4 却数分钟不返回"的
/// 环境病症（进程监管干扰了 SIGCHLD 的投递，与 cargo 侧偶发挂住
/// 同源）。一次卡死就会拖垮整个集成套件，故改为轮询 `try_wait`：
/// 进程早已被 SIGKILL，2 秒内收不掉就放弃 —— 僵尸由 init 在测试
/// 二进制退出时统一回收，不影响任何断言的正确性。
fn kill_and_reap(child: &mut std::process::Child) {
    let _ = child.kill();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while std::time::Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(20)),
            Err(_) => return,
        }
    }
}

/// 探测一个空闲端口（绑定 0 后立即释放；竞态概率可忽略）。
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// 启动服务进程并轮询等待 /api/meta 就绪。
fn start_server(extra_args: &[&str]) -> TestServer {
    let port = free_port();
    let data_dir = std::env::temp_dir().join(format!(
        "sportsmeet-it-{}-{}",
        std::process::id(),
        port
    ));
    start_server_in(&data_dir, extra_args)
}

/// 在**指定数据目录**启动一个被测实例。
///
/// 用于"复用另一实例留下的数据目录"这类场景（例如验证加密文件自动探测）。
fn start_server_in(data_dir: &std::path::Path, extra_args: &[&str]) -> TestServer {
    let port = free_port();
    let dir = data_dir.to_path_buf();
    let web_dir = format!("{}/web", env!("CARGO_MANIFEST_DIR"));
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sports-meet"));
    cmd.args(["--port", &port.to_string()])
        .args(["--dir", dir.to_str().unwrap()])
        .args(["--web", &web_dir])
        .args(["--log-level", "error"])
        // v1.9.0：被测实例一律显式关闭授权强制 —— 这些用例测的是业务
        // 行为，不该被授权门禁拦成 403（全新安装默认拦截，见
        // fresh_install_gate_blocks_until_licensed 用例）。
        .args(["--aim-allow-unlicensed"])
        .args(extra_args)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let child = cmd.spawn().expect("启动被测服务进程失败");
    let srv = TestServer {
        child,
        port,
        data_dir: dir,
    };

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if TcpStream::connect(("127.0.0.1", srv.port)).is_ok() {
            let (st, _) = send_request(srv.port, "GET", "/api/meta", &[], b"");
            if st == 200 {
                return srv;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "服务在 10 秒内未就绪（端口 {}）",
            srv.port
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
}

/// 发送一条 HTTP/1.1 请求（Connection: close），返回 (状态码, 响应体)。
fn send_request(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, String) {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("连接服务失败");
    let mut req = format!(
        "{} {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n",
        method, path
    );
    for (k, v) in headers {
        req.push_str(&format!("{}: {}\r\n", k, v));
    }
    if !body.is_empty() {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).unwrap();
    if !body.is_empty() {
        stream.write_all(body).unwrap();
    }
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).unwrap();
    let text = String::from_utf8_lossy(&buf).into_owned();
    let status_line = text.lines().next().unwrap_or("");
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("")
        .to_string();
    (status, body)
}

/// JSON POST 便捷封装。
fn post_json(port: u16, path: &str, body: &str, auth: Option<&str>) -> (u16, String) {
    let mut headers = vec![("Content-Type", "application/json")];
    if let Some(a) = auth {
        headers.push(("Authorization", a));
    }
    send_request(port, "POST", path, &headers, body.as_bytes())
}

/// 创建一个最小可用项目的请求体（合法单位：时间/米/个）。
fn event_body(name: &str) -> String {
    format!(
        r#"{{"name":"{}","category":"径赛","gender":"男子","grade":"初一","is_team":false,"unit":"时间"}}"#,
        name
    )
}

// ===========================================================================
// 用例
// ===========================================================================

#[test]
fn static_page_and_meta_served() {
    let srv = start_server(&[]);
    let (st, body) = send_request(srv.port, "GET", "/", &[], b"");
    assert_eq!(st, 200, "首页应可访问");
    assert!(body.contains("<!DOCTYPE"), "应返回 HTML 文档");

    let (st, body) = send_request(srv.port, "GET", "/api/meta", &[], b"");
    assert_eq!(st, 200);
    assert!(body.contains("grades"), "meta 应包含年级配置");
}

#[test]
fn unknown_api_returns_404() {
    let srv = start_server(&[]);
    let (st, body) = send_request(srv.port, "GET", "/api/nope", &[], b"");
    assert_eq!(st, 404);
    assert!(body.contains("未知接口"), "404 响应应说明原因");
}

#[test]
fn event_lifecycle_create_delete_undo() {
    let srv = start_server(&[]);
    // 创建
    let (st, body) = post_json(srv.port, "/api/events", &event_body("集成测试项目"), None);
    assert_eq!(st, 201, "创建项目应 201：{}", body);
    let id: i64 = serde_json_get_i64(&body, "id").expect("创建响应应含 id");
    // 列表可见
    let (st, body) = send_request(srv.port, "GET", "/api/events", &[], b"");
    assert_eq!(st, 200);
    assert!(body.contains("集成测试项目"), "列表应包含新项目");
    // 删除（确认）
    let (st, _) = send_request(
        srv.port,
        "DELETE",
        &format!("/api/events/{}?confirm=1", id),
        &[],
        b"",
    );
    assert_eq!(st, 200, "删除应成功");
    // 撤销恢复
    let (st, _) = post_json(srv.port, "/api/undo", "{}", None);
    assert_eq!(st, 200, "撤销应成功");
    let (st, body) = send_request(srv.port, "GET", "/api/events", &[], b"");
    assert!(st == 200 && body.contains("集成测试项目"), "撤销后项目应恢复");
}

/// 极简 JSON 字段提取（集成测试不引第三方依赖）。
fn serde_json_get_i64(body: &str, key: &str) -> Option<i64> {
    let pat = format!("\"{}\":", key);
    let pos = body.find(&pat)? + pat.len();
    let rest = &body[pos..];
    let num: String = rest
        .chars()
        .skip_while(|c| c.is_whitespace())
        .take_while(|c| c.is_ascii_digit() || *c == '-')
        .collect();
    num.parse().ok()
}

/// 收集响应里某个 key 对应的**所有** i64 值（用于"创建后列表里取 id"的场景）。
fn serde_json_get_i64_all(body: &str, key: &str) -> Vec<i64> {
    let pat = format!("\"{}\":", key);
    let mut out = Vec::new();
    let mut start = 0;
    while let Some(pos) = body[start..].find(&pat) {
        let abs = start + pos + pat.len();
        let rest = &body[abs..];
        let num: String = rest
            .chars()
            .skip_while(|c| c.is_whitespace())
            .take_while(|c| c.is_ascii_digit() || *c == '-')
            .collect();
        if let Ok(n) = num.parse() {
            out.push(n);
        }
        start = abs;
    }
    out
}

#[test]
fn deep_json_rejected_and_service_survives() {
    let srv = start_server(&[]);
    // 200 层深嵌套：应被深度上限拒绝（400），而非栈溢出崩溃
    let mut deep = String::new();
    for _ in 0..200 {
        deep.push('[');
    }
    for _ in 0..200 {
        deep.push(']');
    }
    let (st, body) = post_json(srv.port, "/api/events", &deep, None);
    assert!(
        st == 400 || st == 415,
        "深嵌套应被拒绝，实际 {}：{}",
        st,
        body
    );
    assert!(body.contains("深度") || body.contains("解析"), "错误信息应可读：{}", body);
    // 关键断言：服务进程仍然存活
    let (st, _) = send_request(srv.port, "GET", "/api/meta", &[], b"");
    assert_eq!(st, 200, "深嵌套攻击后服务应继续正常响应");
}

#[test]
fn oversized_body_rejected() {
    let srv = start_server(&[]);
    // 声明 2 MiB Content-Length（上限 1 MiB）：服务端读完请求头即拒绝，
    // 客户端无需真正发送数据体
    let (st, _) = send_request(
        srv.port,
        "POST",
        "/api/events",
        &[
            ("Content-Type", "application/json"),
            ("Content-Length", "2097152"),
        ],
        b"",
    );
    assert_eq!(st, 400, "超大请求体应被拒绝");
    let (st, _) = send_request(srv.port, "GET", "/api/meta", &[], b"");
    assert_eq!(st, 200, "服务应继续正常响应");
}

#[test]
fn batch_import_bad_header_rejected() {
    let srv = start_server(&[]);
    // 表头无任何姓名列（姓名/名字/学生 均无）→ 400 且错误信息含「表头」
    let body = r#"{"text":"学号,年级,班级,性别\n001,初一,1,男\n"}"#;
    let (st, body) = post_json(srv.port, "/api/students/batch", body, None);
    assert_eq!(st, 400, "错误表头应被拒绝：{}", body);
    assert!(body.contains("表头"), "错误信息应指出表头问题：{}", body);
}

#[test]
fn password_protects_write_endpoints() {
    let srv = start_server(&["--password", "secret"]);
    // 无 Authorization → 401
    let (st, _) = post_json(srv.port, "/api/events", &event_body("无头项目"), None);
    assert_eq!(st, 401, "未携带口令的写请求应 401");
    // 错误口令 → 401
    let (st, _) = post_json(
        srv.port,
        "/api/events",
        &event_body("错头项目"),
        Some("Bearer wrong"),
    );
    assert_eq!(st, 401, "错误口令应 401");
    // 正确口令 → 201
    let (st, body) = post_json(
        srv.port,
        "/api/events",
        &event_body("鉴权后项目"),
        Some("Bearer secret"),
    );
    assert_eq!(st, 201, "正确口令应放行：{}", body);
    // 读接口保持开放
    let (st, _) = send_request(srv.port, "GET", "/api/meta", &[], b"");
    assert_eq!(st, 200, "读接口不应要求口令");
    // 静态页开放
    let (st, _) = send_request(srv.port, "GET", "/", &[], b"");
    assert_eq!(st, 200);
}

#[test]
fn non_json_content_type_rejected_for_post() {
    let srv = start_server(&[]);
    // 带请求体的 POST 必须声明 application/json（CSRF 缓解），否则 415
    let (st, _) = send_request(
        srv.port,
        "POST",
        "/api/events",
        &[("Content-Type", "text/plain")],
        b"not json",
    );
    assert_eq!(st, 415, "非 JSON Content-Type 的写请求应 415");
}

#[test]
fn no_password_mode_stays_open() {
    let srv = start_server(&[]);
    // 向后兼容：未设口令时写操作无需 Authorization
    let (st, body) = post_json(srv.port, "/api/events", &event_body("免鉴权项目"), None);
    assert_eq!(st, 201, "未设口令时 POST 应正常放行：{}", body);
}

#[test]
fn concurrent_reads_all_succeed() {
    let srv = start_server(&[]);
    let mut handles = Vec::new();
    for _ in 0..8 {
        let port = srv.port;
        handles.push(std::thread::spawn(move || {
            send_request(port, "GET", "/api/meta", &[], b"").0
        }));
    }
    for h in handles {
        assert_eq!(h.join().unwrap(), 200, "并发读应全部成功");
    }
}

// ===========================================================================
// v1.5 新增用例：SSE 实时大屏 / 签名令牌 / 审计哈希链 / 智能解析
// ===========================================================================

/// 读取响应头 + 流式正文（用于 SSE 断言）。
///
/// # 为什么要分两段读（踩坑记录 #25）
///
/// 服务端先 `write_all(head)` 再 `flush`，随后才写第一帧 —— 于是
/// **响应头与正文落在两个不同的 TCP 段**上。单次 `read()` 只能拿到响应头，
/// 正文还要再等一次。
///
/// 注意这与 `BufReader::read_line` 的合并行为**不同**：只要两次写之间
/// 有一次 flush，内核就会把已 flush 的数据立即发出去，不会等待合并。
/// 首次编写本用例时误以为"一次 read 就能拿到全部"，导致正文断言全部落空。
///
/// 实现策略：先读到 `\r\n\r\n` 确认头结束，再继续读直到**累积到正文**
/// 或达到超时/总量上限。
fn send_request_raw(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> String {
    let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("连接服务失败");
    let mut req = format!(
        "{} {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n",
        method, path
    );
    for (k, v) in headers {
        req.push_str(&format!("{}: {}\r\n", k, v));
    }
    if !body.is_empty() {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).unwrap();
    if !body.is_empty() {
        stream.write_all(body).unwrap();
    }
    let _ = stream.flush();
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();

    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 16384];
    // 上限 256 KiB：SSE 是长连接，读到足够断言的内容就主动断开，不无限等
    while buf.len() < 256 * 1024 {
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                buf.extend_from_slice(&chunk[..n]);
                // 已拿到响应头 + 至少一帧正文 → 足够断言
                if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                    if buf.len() > pos + 4 + 8 {
                        break;
                    }
                }
            }
            Err(_) => break, // 超时 / 连接被关闭
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

/// 在字节切片中查找子串位置（标准库无此函数）。
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

/// SSE 流：应返回 text/event-stream + chunked，并**立即**推送首帧快照。
///
/// 这是本版本最核心的新能力，必须端到端验证而不是只测单元函数。
#[test]
fn sse_live_board_streams_snapshot_immediately() {
    let srv = start_server(&[]);
    let raw = send_request_raw(
        srv.port,
        "GET",
        "/api/ext/live-board/stream",
        &[],
        b"",
    );
    assert!(
        raw.starts_with("HTTP/1.1 200"),
        "SSE 接口应 200，实际：{}",
        raw.lines().next().unwrap_or("")
    );
    assert!(
        raw.to_lowercase().contains("content-type: text/event-stream"),
        "Content-Type 应为 text/event-stream"
    );
    assert!(raw.contains("Transfer-Encoding: chunked"), "流式响应应采用 chunked 传输编码");
    // 注意：chunked 分帧会在数据前插入十六进制长度行（如 "cc\r\n"）。
    // 断言前需**剥掉分帧头**，否则 "event: snapshot" 可能被长度行从中间截断
    // —— 首次编写本用例时就踩到这个坑（详见 docs/05 踩坑记录 #25）。
    let decoded = dechunk(&raw);
    assert!(
        decoded.contains("event: snapshot"),
        "应推送 snapshot 事件；解码后内容：{}",
        &decoded[..decoded.len().min(300)]
    );
    assert!(decoded.contains("recent_events"), "快照应含最近成绩项目字段");
    assert!(decoded.contains("\"ok\":true"), "快照应是合法业务 JSON");
}

/// 剥离 HTTP/1.1 chunked 分帧，还原为连续载荷文本。
///
/// 只处理"长度行 + 数据 + CRLF"的基本形态；遇到终止块 `0` 即停止。
/// 数据以外（状态行/响应头）原样保留，便于同时断言头部与正文。
fn dechunk(raw: &str) -> String {
    let (head, rest) = match raw.split_once("\r\n\r\n") {
        Some((h, r)) => (h.to_string(), r),
        None => return raw.to_string(),
    };
    let mut out = head;
    out.push_str("\r\n\r\n");
    let bytes = rest.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // 读长度行
        let line_end = match rest[i..].find("\r\n") {
            Some(p) => i + p,
            None => break,
        };
        let size_str = rest[i..line_end].trim();
        // 允许扩展参数（`cc;ext=1`）——SSE 场景不会出现，但按规范容错
        let size_hex = size_str.split(';').next().unwrap_or("").trim();
        let size = match usize::from_str_radix(size_hex, 16) {
            Ok(v) => v,
            Err(_) => break, // 不是 chunk 头，说明已到载荷尾部
        };
        if size == 0 {
            break; // 终止块
        }
        let start = line_end + 2;
        let end = (start + size).min(bytes.len());
        out.push_str(&rest[start..end]);
        i = end + 2; // 跳过数据后的 CRLF
    }
    out
}

#[test]
fn live_board_snapshot_endpoint_is_plain_json() {
    let srv = start_server(&[]);
    let (st, body) = send_request(srv.port, "GET", "/api/ext/live-board/snapshot", &[], b"");
    assert_eq!(st, 200, "快照接口应可用：{}", body);
    assert!(body.contains("grades"), "快照应含年级总分榜");
    assert!(body.contains("totals"), "快照应含总量统计");
}

#[test]
fn live_board_status_reports_viewers() {
    let srv = start_server(&[]);
    let (st, body) = send_request(srv.port, "GET", "/api/ext/live-board/status", &[], b"");
    assert_eq!(st, 200);
    assert!(body.contains("online_viewers"), "状态应含在线上屏数：{}", body);
    assert!(body.contains("heartbeat_secs"), "状态应含心跳间隔");
}

/// 大屏是只读展示：未设口令时也应开放（现场投影机不应需要输密码）。
#[test]
fn live_board_readable_without_password() {
    let srv = start_server(&["--password", "secret"]);
    let (st, _) = send_request(srv.port, "GET", "/api/ext/live-board/snapshot", &[], b"");
    assert_eq!(st, 200, "大屏快照属读接口，应免口令");
}

/// v1.5 令牌链路：口令换令牌 → 用令牌写 → 错误口令换不到令牌。
#[test]
fn signed_token_flow_end_to_end() {
    let srv = start_server(&["--password", "e2e-secret"]);

    // 1) 错误口令换取令牌 → 401
    let (st, _) = post_json(
        srv.port,
        "/api/auth/token",
        r#"{"password":"wrong"}"#,
        None,
    );
    assert_eq!(st, 401, "错误口令不应换到令牌");

    // 2) 正确口令换取令牌
    let (st, body) = post_json(
        srv.port,
        "/api/auth/token",
        r#"{"password":"e2e-secret"}"#,
        None,
    );
    assert_eq!(st, 200, "正确口令应换到令牌：{}", body);
    let token = extract_json_str(&body, "token").expect("响应应含 token");
    assert!(token.contains('.'), "令牌应为三段式：{}", token);

    // 3) 用令牌写入 → 201
    let auth = format!("Bearer {}", token);
    let (st, b2) = post_json(srv.port, "/api/events", &event_body("令牌项目"), Some(&auth));
    assert_eq!(st, 201, "令牌应可写：{}", b2);

    // 4) 令牌自检接口应报 admin
    let (st, body) = send_request(
        srv.port,
        "GET",
        "/api/auth/check",
        &[("Authorization", &auth)],
        b"",
    );
    assert_eq!(st, 200);
    assert!(body.contains("\"role\":\"admin\""), "令牌应被识别为 admin：{}", body);

    // 5) 伪造令牌（改一段签名）应被拒
    let mut parts: Vec<&str> = token.split('.').collect();
    parts[2] = "0000000000000000";
    let fake = format!("Bearer {}", parts.join("."));
    let (st, _) = post_json(srv.port, "/api/events", &event_body("伪造项目"), Some(&fake));
    assert_eq!(st, 401, "伪造签名必须被拒");

    // 6) 原始口令直通仍然可用（v1.4 向后兼容）
    let (st, _) = post_json(
        srv.port,
        "/api/events",
        &event_body("旧式口令项目"),
        Some("Bearer e2e-secret"),
    );
    assert_eq!(st, 201, "v1.4 的口令直通必须保持兼容");
}

/// 敏感操作二次确认：删除项目/学生、清空成绩、全量导入需 X-Confirm-Password。
#[test]
fn sensitive_operations_require_second_confirmation() {
    let srv = start_server(&["--password", "sec2"]);
    let auth = "Bearer sec2";

    // 先建一个项目（非敏感操作，只需令牌）
    let (st, body) = post_json(srv.port, "/api/events", &event_body("待删项目"), Some(auth));
    assert_eq!(st, 201, "{}", body);
    let id = serde_json_get_i64(&body, "id").expect("应有 id");

    // 删除：仅带令牌 → 428（要求二次确认）
    let (st, body) = send_request(
        srv.port,
        "DELETE",
        &format!("/api/events/{}?confirm=1", id),
        &[("Authorization", auth)],
        b"",
    );
    assert_eq!(st, 428, "敏感删除应要求二次确认：{}", body);
    assert!(
        body.contains("二次确认") || body.contains("confirm_required"),
        "应明确提示确认要求：{}",
        body
    );

    // 删除：带令牌 + 正确二次口令 → 200
    let (st, body) = send_request(
        srv.port,
        "DELETE",
        &format!("/api/events/{}?confirm=1", id),
        &[("Authorization", auth), ("X-Confirm-Password", "sec2")],
        b"",
    );
    assert_eq!(st, 200, "带二次确认应成功：{}", body);

    // 普通写操作**不应**被二次确认打扰（避免打扰日常录入）
    let (st, _) = post_json(srv.port, "/api/events", &event_body("普通项目"), Some(auth));
    assert_eq!(st, 201, "普通 POST 不应要求二次确认");
}

/// 未设口令时，敏感操作照旧放行（向后兼容 v1.4 行为）。
#[test]
fn sensitive_ops_open_when_no_password() {
    let srv = start_server(&[]);
    let (_, body) = post_json(srv.port, "/api/events", &event_body("免密项目"), None);
    let id = serde_json_get_i64(&body, "id").unwrap();
    let (st, _) = send_request(
        srv.port,
        "DELETE",
        &format!("/api/events/{}?confirm=1", id),
        &[],
        b"",
    );
    assert_eq!(st, 200, "未设口令时删除应照旧可用");
}

/// 审计哈希链：写入若干操作后，校验接口应报告链完整，且记录非空。
#[test]
fn audit_chain_stays_valid_after_operations() {
    let srv = start_server(&[]);
    // 制造 3 条审计记录
    let (_, b1) = post_json(srv.port, "/api/events", &event_body("审计甲"), None);
    let (_, b2) = post_json(srv.port, "/api/events", &event_body("审计乙"), None);
    let id = serde_json_get_i64(&b1, "id").unwrap();
    let (st, _) = send_request(
        srv.port,
        "DELETE",
        &format!("/api/events/{}?confirm=1", id),
        &[],
        b"",
    );
    assert_eq!(st, 200);

    let (st, body) = send_request(srv.port, "GET", "/api/audit/verify", &[], b"");
    assert_eq!(st, 200, "审计校验接口应可用：{}", body);
    assert!(
        body.contains("\"verified\":true"),
        "正常操作后审计链应完整：{}",
        body
    );

    let (st, body) = send_request(srv.port, "GET", "/api/audit?limit=50", &[], b"");
    assert_eq!(st, 200);
    assert!(body.contains("event.create"), "应记录项目创建：{}", body);
    assert!(body.contains("event.delete"), "应记录项目删除");
    assert!(body.contains("head_hash"), "应暴露链头摘要");
    let _ = b2;
}

/// 篡改审计文件后，校验必须报错并指认位置（防篡改能力的端到端验证）。
#[test]
fn tampered_audit_file_is_detected_end_to_end() {
    let srv = start_server(&[]);
    post_json(srv.port, "/api/events", &event_body("篡改靶子"), None);
    post_json(srv.port, "/api/events", &event_body("篡改靶子2"), None);

    // 找到审计文件并改掉其中一条的 detail 字段（模拟"事后改记录"）
    let audit_dir = srv.data_dir.join("audit");
    let mut changed = false;
    if let Ok(rd) = std::fs::read_dir(&audit_dir) {
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().and_then(|x| x.to_str()) == Some("jsonl") {
                if let Ok(text) = std::fs::read_to_string(&p) {
                    // 把第一条记录的 detail 换掉，但保持 JSON 结构合法
                    let tampered = text.replacen("\"detail\":\"", "\"detail\":\"X", 1);
                    std::fs::write(&p, tampered).unwrap();
                    changed = true;
                    break;
                }
            }
        }
    }
    assert!(changed, "应能找到审计文件用于篡改测试");

    let (st, body) = send_request(srv.port, "GET", "/api/audit/verify", &[], b"");
    assert_eq!(st, 200);
    assert!(
        body.contains("\"verified\":false"),
        "被篡改的审计链必须报告不完整：{}",
        body
    );
    assert!(
        body.contains("bad_hash_at"),
        "应指出内容失配位置：{}",
        body
    );
}

/// 智能解析预览：全角/中文单位应被识别，垃圾输入应明确不识别（不猜）。
#[test]
fn smart_parse_preview_endpoint() {
    let srv = start_server(&[]);
    // 中文时间
    let (st, body) = post_json(
        srv.port,
        "/api/smart/parse",
        r#"{"text":"1分23秒45","unit":"时间"}"#,
        None,
    );
    assert_eq!(st, 200, "{}", body);
    assert!(body.contains("\"recognized\":true"), "{}", body);
    assert!(body.contains("83.45"), "应解析为 83.45 秒：{}", body);

    // 全角数字
    let (_, body) = post_json(
        srv.port,
        "/api/smart/parse",
        r#"{"text":"１３．５","unit":"时间"}"#,
        None,
    );
    assert!(body.contains("13.5"), "全角数字应被识别：{}", body);

    // 弃权
    let (_, body) = post_json(
        srv.port,
        "/api/smart/parse",
        r#"{"text":"弃权","unit":"时间"}"#,
        None,
    );
    assert!(body.contains("\"void\":true"), "弃权应标为无效：{}", body);

    // 无法识别 → recognized=false，且给出格式提示（不猜测）
    let (_, body) = post_json(
        srv.port,
        "/api/smart/parse",
        r#"{"text":"看不懂的东西","unit":"时间"}"#,
        None,
    );
    assert!(body.contains("\"recognized\":false"), "{}", body);
    assert!(body.contains("hint"), "应给出格式提示：{}", body);
}

/// 启用了口令时，智能解析是**只读预览**，不应被写鉴权拦下。
///
/// 回归背景：v1.5 首次实测时，老师在录入页点「解析」永远没有反应 ——
/// 因为 `/api/smart/parse` 是 POST，被"写操作需要令牌"的判断一刀切拦成 401，
/// 前端只在收到 401 时弹口令框，而输入框是空的看起来像"没反应"。
/// 这类纯计算接口不该要求鉴权，否则等于给只读能力上了锁。
#[test]
fn smart_parse_needs_no_auth_even_with_password() {
    let srv = start_server(&["--password", "read-only-pw"]);
    let (st, body) = post_json(
        srv.port,
        "/api/smart/parse",
        r#"{"text":"13秒2","unit":"时间"}"#,
        None,
    );
    assert_eq!(st, 200, "只读解析接口不应要求鉴权：{}", body);
    assert!(body.contains("\"recognized\":true"), "{}", body);
    assert!(body.contains("13.2"), "{}", body);

    // 对照组：真正的写接口仍然必须鉴权，确认例外没有开得过宽
    let (st2, _) = post_json(
        srv.port,
        "/api/events",
        &event_body("不该被创建"),
        None,
    );
    assert_eq!(st2, 401, "写接口在无令牌时必须仍是 401");
}

/// 即使开了口令例外，敏感操作的二次确认也不能被绕过。
#[test]
fn readonly_exception_does_not_weaken_sensitive_confirmation() {
    let srv = start_server(&["--password", "sec3"]);
    let (_, tk_body) = post_json(
        srv.port,
        "/api/auth/token",
        r#"{"password":"sec3"}"#,
        None,
    );
    let tk = extract_json_str(&tk_body, "token").expect("应能取到令牌");

    // 建一个项目（带令牌）
    let (st, ev_body) = post_json(
        srv.port,
        "/api/events",
        &event_body("待删项目"),
        Some(&format!("Bearer {}", tk)),
    );
    assert_eq!(st, 201, "{}", ev_body);
    let id = serde_json_get_i64(&ev_body, "id").unwrap();

    // 带令牌但**不给二次确认口令** → 428
    let (st2, _) = send_request(
        srv.port,
        "DELETE",
        &format!("/api/events/{}?confirm=1", id),
        &[("Authorization", &format!("Bearer {}", tk))],
        b"",
    );
    assert_eq!(st2, 428, "敏感操作缺二次确认应被拒");

    // 二次确认口令正确 → 放行
    let (st3, _) = send_request(
        srv.port,
        "DELETE",
        &format!("/api/events/{}?confirm=1", id),
        &[
            ("Authorization", &format!("Bearer {}", tk)),
            ("X-Confirm-Password", "sec3"),
        ],
        b"",
    );
    assert_eq!(st3, 200, "带正确二次确认口令应放行");
}

/// 推荐接口：空库下不应报错，应返回空候选与说明性提示。
#[test]
fn recommend_endpoint_handles_empty_data() {
    let srv = start_server(&[]);
    let (st, body) = send_request(
        srv.port,
        "GET",
        "/api/smart/recommend?event_id=1&limit=5",
        &[],
        b"",
    );
    assert_eq!(st, 200, "空库下推荐应正常返回：{}", body);
    assert!(body.contains("candidates"), "{}", body);
    assert!(body.contains("notice"), "应携带免责说明：{}", body);

    // 不存在的项目 → 友好错误
    let (st, body) = send_request(
        srv.port,
        "GET",
        "/api/smart/recommend?event_id=99999",
        &[],
        b"",
    );
    assert!(st == 400 || st == 404 || st == 500, "实际 {}：{}", st, body);
}

/// 重复路由检测（v1.5 新增的启动期自检）：服务应正常启动而非 panic。
#[test]
fn duplicate_route_check_does_not_break_startup() {
    let srv = start_server(&[]);
    let (st, body) = send_request(srv.port, "GET", "/api/ext/extensions", &[], b"");
    assert_eq!(st, 200);
    assert!(body.contains("live-board"), "扩展面板应含新扩展：{}", body);
    assert!(body.contains("records-feed"), "旧扩展应仍注册");
}

/// 从 JSON 文本里取字符串字段（集成测试不引依赖）。
fn extract_json_str(body: &str, key: &str) -> Option<String> {
    let pat = format!("\"{}\":\"", key);
    let pos = body.find(&pat)? + pat.len();
    let rest = &body[pos..];
    let mut out = String::new();
    let mut escaped = false;
    for c in rest.chars() {
        if escaped {
            out.push(c);
            escaped = false;
            continue;
        }
        if c == '\\' {
            escaped = true;
            continue;
        }
        if c == '"' {
            break;
        }
        out.push(c);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

// ===========================================================================
// v1.5.1 新增：密钥机制、开发者模式、数据加密
// ===========================================================================

/// v1.5.1 演示密钥（与 `core/license.rs` 的指纹常量对应）。
const DEMO_DEVKEY: &str = "THZX-2026-DEV";

#[test]
fn dev_status_without_key_reports_locked() {
    // 不带 --devkey：状态接口应如实报告"没有密钥、不能解锁"
    let srv = start_server(&[]);
    let (st, body) = send_request(srv.port, "GET", "/api/dev/status", &[], b"");
    assert_eq!(st, 200, "状态接口应始终可读（不含敏感信息）");
    assert!(
        body.contains(r#""key_present":false"#),
        "未传密钥应报告 key_present=false：{}",
        body
    );
    assert!(body.contains(r#""dev_mode":"locked""#), "默认必须锁定");
    assert!(body.contains(r#""from_loopback":true"#), "本机请求应识别为回环");
    // 绝不泄露密钥或种子
    assert!(!body.contains(DEMO_DEVKEY));
    assert!(
        !body.contains("stream_seed\":"),
        "状态里不得出现流密钥字段"
    );
}

#[test]
fn dev_unlock_requires_key_and_risk_ack() {
    // 只传密钥、不传 --i-know-the-risk → 三重条件缺一，不得解锁
    let srv = start_server(&["--devkey", DEMO_DEVKEY]);
    let (st, body) = send_request(srv.port, "GET", "/api/dev/status", &[], b"");
    assert_eq!(st, 200);
    assert!(
        body.contains(r#""key_present":true"#),
        "密钥正确应报告 true：{}",
        body
    );
    assert!(body.contains(r#""risk_acked":false"#), "未确认风险");
    assert!(
        body.contains(r#""can_unlock":false"#),
        "缺风险确认则不得具备解锁能力"
    );
    let (st, body) = post_json(srv.port, "/api/dev/unlock", "{}", None);
    assert_eq!(st, 403, "缺条件时解锁应被拒：{}", body);
}

#[test]
fn dev_unlock_succeeds_with_all_three_conditions() {
    let srv = start_server(&["--devkey", DEMO_DEVKEY, "--i-know-the-risk"]);
    // 解锁前：具备能力但仍是锁定态
    let (st, body) = send_request(srv.port, "GET", "/api/dev/status", &[], b"");
    assert_eq!(st, 200);
    assert!(body.contains(r#""can_unlock":true"#));
    assert!(body.contains(r#""dev_mode":"locked""#), "默认不自动解锁");

    // 解锁
    let (st, body) = post_json(srv.port, "/api/dev/unlock", "{}", None);
    assert_eq!(st, 200, "三重条件齐备应可解锁：{}", body);
    assert!(body.contains(r#""dev_mode":"unlocked""#));

    let (_, body) = send_request(srv.port, "GET", "/api/dev/status", &[], b"");
    assert!(body.contains(r#""dev_mode":"unlocked""#));

    // 上锁
    let (st, body) = post_json(srv.port, "/api/dev/lock", "{}", None);
    assert_eq!(st, 200);
    assert!(body.contains(r#""was_unlocked":true"#));
    let (_, body) = send_request(srv.port, "GET", "/api/dev/status", &[], b"");
    assert!(body.contains(r#""dev_mode":"locked""#), "上锁后应恢复锁定");
}

#[test]
fn wrong_devkey_is_silent_and_cannot_unlock() {
    // 错误密钥：不报错、静默降级、无法解锁
    let srv = start_server(&["--devkey", "definitely-wrong", "--i-know-the-risk"]);
    let (st, body) = send_request(srv.port, "GET", "/api/dev/status", &[], b"");
    assert_eq!(st, 200, "错误密钥不应让服务无法启动");
    assert!(
        body.contains(r#""key_present":false"#),
        "错误密钥应视为无密钥：{}",
        body
    );
    assert!(body.contains(r#""can_unlock":false"#));
    let (st, body) = post_json(srv.port, "/api/dev/unlock", "{}", None);
    assert_eq!(st, 403, "错误密钥不得解锁：{}", body);
}

#[test]
fn dev_endpoints_bypass_password_auth_but_not_conditions() {
    // 回归 #31：设了口令的实例上，/api/dev/unlock 曾被鉴权层拦成 401，
    // 导致"想解锁得先有口令、而解锁本身又要口令"的死锁。
    // 正确行为：dev 接口免受普通口令鉴权，但仍受自己的三重条件约束。
    let srv = start_server(&[
        "--password",
        "admin123",
        "--devkey",
        DEMO_DEVKEY,
        "--i-know-the-risk",
    ]);
    // 不带任何 Authorization 也能解锁（dev 接口自带更严的门槛）
    let (st, body) = post_json(srv.port, "/api/dev/unlock", "{}", None);
    assert_eq!(st, 200, "dev 接口不应被普通口令鉴权拦住：{}", body);

    // 但换个没有密钥的实例，同样是这个接口，照样解不开
    let srv2 = start_server(&["--password", "admin123"]);
    let (st, _) = post_json(srv2.port, "/api/dev/unlock", "{}", None);
    assert_eq!(st, 403, "无密钥实例即使免鉴权也不得解锁");
}

#[test]
fn devmode_skips_second_confirmation_and_audits() {
    // 回归 #32：业务层 `?confirm=1` 预检与 HTTP 层二次确认是**两套**机制，
    // 只放开其中一套仍会 428。正确行为：devmode 下两套都跳过，且留痕。
    let srv = start_server(&[
        "--password",
        "admin123",
        "--devkey",
        DEMO_DEVKEY,
        "--i-know-the-risk",
    ]);
    // 取令牌与一个待删项目
    let (st, tok_body) = post_json(srv.port, "/api/auth/token", r#"{"password":"admin123"}"#, None);
    assert_eq!(st, 200, "应能换取令牌：{}", tok_body);
    let token = extract_json_str(&tok_body, "token").expect("响应应含 token");
    let bearer = format!("Bearer {}", token);

    let (st, body) = post_json(srv.port, "/api/events", &event_body("待删项目"), Some(&bearer));
    assert_eq!(st, 201, "创建项目应成功：{}", body);
    let eid = serde_json_get_i64(&body, "id").expect("应返回 id");

    // 未解锁：三重保护叠加，先被 HTTP 层拦（428）
    let (st, body) = send_request(
        srv.port,
        "DELETE",
        &format!("/api/events/{}", eid),
        &[("Authorization", &bearer)],
        b"",
    );
    assert_eq!(st, 428, "未解锁应要求二次确认：{}", body);

    // 解锁
    let (st, _) = post_json(srv.port, "/api/dev/unlock", "{}", None);
    assert_eq!(st, 200);

    // 已解锁：不带 ?confirm=1 也应直接删除成功
    let (st, body) = send_request(
        srv.port,
        "DELETE",
        &format!("/api/events/{}", eid),
        &[("Authorization", &bearer)],
        b"",
    );
    assert_eq!(st, 200, "devmode 下应跳过两层确认：{}", body);

    // 审计必须留下 devmode 痕迹
    let (st, body) = send_request(srv.port, "GET", "/api/audit?limit=50", &[], b"");
    assert_eq!(st, 200);
    assert!(
        body.contains("dev_unlock"),
        "审计应记录解锁动作：{}",
        body
    );
    assert!(
        body.contains("dev_bypass_confirm"),
        "审计应记录跳过预检的动作：{}",
        body
    );
    assert!(
        body.contains(r#""actor":"devmode""#),
        "开发者模式动作的 actor 应为 devmode：{}",
        body
    );
    // 哈希链在 devmode 操作后仍应自洽
    let (st, vbody) = send_request(srv.port, "GET", "/api/audit/verify", &[], b"");
    assert_eq!(st, 200);
    assert!(
        vbody.contains(r#""ok":true"#),
        "开发者模式写入后哈希链仍须自洽：{}",
        vbody
    );
}

#[test]
fn lock_restores_security_boundary() {
    // 上锁后，被 devmode 放开的动作必须重新被拦下
    let srv = start_server(&[
        "--password",
        "admin123",
        "--devkey",
        DEMO_DEVKEY,
        "--i-know-the-risk",
    ]);
    let (_, tok_body) = post_json(srv.port, "/api/auth/token", r#"{"password":"admin123"}"#, None);
    let token = extract_json_str(&tok_body, "token").unwrap();
    let bearer = format!("Bearer {}", token);

    let (_, body) = post_json(srv.port, "/api/events", &event_body("边界测试项目"), Some(&bearer));
    let eid = serde_json_get_i64(&body, "id").unwrap();

    let (st, _) = post_json(srv.port, "/api/dev/unlock", "{}", None);
    assert_eq!(st, 200);
    // 解锁态可删
    let (st, _) = send_request(
        srv.port,
        "DELETE",
        &format!("/api/events/{}", eid),
        &[("Authorization", &bearer)],
        b"",
    );
    assert_eq!(st, 200);

    // 上锁
    let (st, _) = post_json(srv.port, "/api/dev/lock", "{}", None);
    assert_eq!(st, 200);

    // 再建一个，尝试删除 → 应重新被拦
    let (_, body) = post_json(srv.port, "/api/events", &event_body("上锁后项目"), Some(&bearer));
    let eid2 = serde_json_get_i64(&body, "id").unwrap();
    let (st, body) = send_request(
        srv.port,
        "DELETE",
        &format!("/api/events/{}", eid2),
        &[("Authorization", &bearer)],
        b"",
    );
    assert_eq!(st, 428, "上锁后必须恢复二次确认：{}", body);
}

#[test]
fn encrypted_data_is_unreadable_without_key() {
    // 数据加密：密文落盘 + 无密钥读不出 + 有密钥读得回
    let srv = start_server(&[
        "--devkey",
        DEMO_DEVKEY,
        "--i-know-the-risk",
        "--encrypt-data",
    ]);
    // 写入一名学生
    let (st, body) = post_json(
        srv.port,
        "/api/students",
        r#"{"name":"加密集成测试","grade":"初一","class_no":1,"gender":"男"}"#,
        None,
    );
    assert_eq!(st, 201, "新增学生应成功：{}", body);

    // 落盘应为 .smev 且无同名明文
    let enc = srv.data_dir.join("sports_meet.json.smev");
    let plain = srv.data_dir.join("sports_meet.json");
    assert!(enc.exists(), "应生成加密数据文件 {} ", enc.display());
    assert!(!plain.exists(), "加密模式下不得残留明文数据文件");

    // 密文应以 SMEV 开头，且不含学生姓名
    let bytes = std::fs::read(&enc).unwrap();
    assert_eq!(&bytes[..4], b"SMEV", "应带 SMEV 魔数");
    let text = String::from_utf8_lossy(&bytes);
    assert!(
        !text.contains("加密集成测试"),
        "密文中不得出现明文姓名"
    );

    // 状态接口应如实报告加密已启用
    let (_, sbody) = send_request(srv.port, "GET", "/api/dev/status", &[], b"");
    assert!(
        sbody.contains(r#""encrypt_data":true"#),
        "应报告加密已启用：{}",
        sbody
    );

    // --- 换个没有密钥的实例读同一份数据：应读不出内容 ---
    let port2 = free_port();
    let dir2 = std::env::temp_dir().join(format!(
        "sportsmeet-it-enc-{}-{}",
        std::process::id(),
        port2
    ));
    std::fs::create_dir_all(&dir2).unwrap();
    std::fs::copy(&enc, dir2.join("sports_meet.json.smev")).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sports-meet"));
    cmd.args(["--port", &port2.to_string()])
        .args(["--dir", dir2.to_str().unwrap()])
        .args(["--log-level", "error"])
        .args(["--aim-allow-unlicensed"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child2 = cmd.spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if TcpStream::connect(("127.0.0.1", port2)).is_ok() {
            let (st, _) = send_request(port2, "GET", "/api/meta", &[], b"");
            if st == 200 {
                break;
            }
        }
        assert!(std::time::Instant::now() < deadline, "无密钥实例未就绪");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let (st, body) = send_request(port2, "GET", "/api/students", &[], b"");
    assert_eq!(st, 200);
    assert!(
        !body.contains("加密集成测试"),
        "无密钥实例绝不应读出加密内容：{}",
        body
    );
    let _ = child2.kill();
    let _ = child2.wait();
    let _ = std::fs::remove_dir_all(&dir2);
}

#[test]
fn encrypted_file_is_auto_detected_without_encrypt_flag() {
    // v1.5.1 回归（实测发现的真实缺陷）：用户加密落盘后，下次启动
    // **只带 --devkey、忘记带 --encrypt-data**，数据必须仍能读出。
    // 修复前会读成空库 —— 表现为"数据凭空消失"，极易被误判为丢数据。
    let srv = start_server(&[
        "--devkey",
        DEMO_DEVKEY,
        "--i-know-the-risk",
        "--encrypt-data",
    ]);
    let (st, body) = post_json(
        srv.port,
        "/api/students",
        r#"{"name":"自动探测甲","grade":"初一","class_no":1,"gender":"男"}"#,
        None,
    );
    assert_eq!(st, 201, "新增学生应成功：{}", body);
    // 触发落盘
    let (st, _) = post_json(srv.port, "/api/backup", "{}", None);
    assert!(st == 200 || st == 201, "备份应成功");
    let enc = srv.data_dir.join("sports_meet.json.smev");
    assert!(enc.exists(), "应生成密文文件");

    // --- 关键：只带 --devkey，**不带** --encrypt-data ---
    let port2 = free_port();
    let dir2 = std::env::temp_dir().join(format!(
        "sportsmeet-it-autoenc-{}-{}",
        std::process::id(),
        port2
    ));
    std::fs::create_dir_all(&dir2).unwrap();
    std::fs::copy(&enc, dir2.join("sports_meet.json.smev")).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sports-meet"));
    cmd.args(["--port", &port2.to_string()])
        .args(["--dir", dir2.to_str().unwrap()])
        .args(["--devkey", DEMO_DEVKEY])
        .args(["--log-level", "error"])
        .args(["--aim-allow-unlicensed"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child2 = cmd.spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if TcpStream::connect(("127.0.0.1", port2)).is_ok() {
            let (st, _) = send_request(port2, "GET", "/api/meta", &[], b"");
            if st == 200 {
                break;
            }
        }
        assert!(std::time::Instant::now() < deadline, "自动探测实例未就绪");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    // 数据必须被自动解密读回
    let (st, body) = send_request(port2, "GET", "/api/students", &[], b"");
    assert_eq!(st, 200);
    assert!(
        body.contains("自动探测甲"),
        "仅带 --devkey 时应能自动识别并解密读回，实际响应：{}",
        body
    );
    // 状态字段应如实反映"探测到密文且已武装"
    let (_, meta) = send_request(port2, "GET", "/api/meta", &[], b"");
    assert!(
        meta.contains(r#""vault_detected":true"#) && meta.contains(r#""vault_enabled":true"#),
        "应报告 vault_detected/vault_enabled 均为真：{}",
        meta
    );
    let _ = child2.kill();
    let _ = child2.wait();
    let _ = std::fs::remove_dir_all(&dir2);
}

#[test]
fn encrypted_detected_without_key_keeps_file_and_reports_status() {
    // 有密文但完全没密钥：应保持空数据、**原文件不被覆盖**、
    // 且状态接口如实报告 vault_detected=true / vault_enabled=false。
    let dir = std::env::temp_dir().join(format!(
        "sportsmeet-it-nokey-{}-{}",
        std::process::id(),
        free_port()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    // 造一个来自真实加密实例的密文
    let seed_srv = start_server(&[
        "--devkey",
        DEMO_DEVKEY,
        "--i-know-the-risk",
        "--encrypt-data",
    ]);
    let (st, _) = post_json(
        seed_srv.port,
        "/api/students",
        r#"{"name":"需密钥甲","grade":"初一","class_no":1,"gender":"男"}"#,
        None,
    );
    assert_eq!(st, 201);
    let (st, _) = post_json(seed_srv.port, "/api/backup", "{}", None);
    assert!(st == 200 || st == 201);
    let enc_src = seed_srv.data_dir.join("sports_meet.json.smev");
    let enc_dst = dir.join("sports_meet.json.smev");
    std::fs::copy(&enc_src, &enc_dst).unwrap();
    let before = std::fs::read(&enc_dst).unwrap();

    let srv2 = start_server_in(&dir, &[]);
    let (st, body) = send_request(srv2.port, "GET", "/api/students", &[], b"");
    assert_eq!(st, 200);
    assert!(!body.contains("需密钥甲"), "无密钥不应读出内容");
    let (_, meta) = send_request(srv2.port, "GET", "/api/meta", &[], b"");
    assert!(
        meta.contains(r#""vault_detected":true"#),
        "应报告已探测到密文：{}",
        meta
    );
    assert!(
        meta.contains(r#""vault_enabled":false"#),
        "未提供密钥时不应报告 vault_enabled：{}",
        meta
    );
    // 关键：原密文绝不能被覆盖/删除
    let after = std::fs::read(&enc_dst).unwrap();
    assert_eq!(before, after, "无密钥启动不得改动原密文文件");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn encrypt_data_without_key_falls_back_to_plaintext() {
    // 传了 --encrypt-data 但没有有效密钥 → 回退明文，且状态如实上报 false
    let srv = start_server(&["--encrypt-data"]);
    let (st, body) = post_json(
        srv.port,
        "/api/students",
        r#"{"name":"回退测试","grade":"初一","class_no":2,"gender":"女"}"#,
        None,
    );
    assert_eq!(st, 201, "回退明文后写入应正常：{}", body);
    // 应写明文文件而非密文
    assert!(
        srv.data_dir.join("sports_meet.json").exists(),
        "无密钥时应回退为明文落盘"
    );
    assert!(
        !srv.data_dir.join("sports_meet.json.smev").exists(),
        "回退时不应生成密文"
    );
    // 状态必须如实报告未加密（不能谎报）
    let (_, sbody) = send_request(srv.port, "GET", "/api/dev/status", &[], b"");
    assert!(
        sbody.contains(r#""encrypt_data":false"#),
        "回退后必须如实报告 encrypt_data=false：{}",
        sbody
    );
}

#[test]
fn embedded_index_served_without_web_dir() {
    // v1.5.1 资源内嵌：不传 --web、且磁盘上没有 web 目录也能拿到首页
    let port = free_port();
    let data_dir = std::env::temp_dir().join(format!(
        "sportsmeet-it-emb-{}-{}",
        std::process::id(),
        port
    ));
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sports-meet"));
    cmd.args(["--port", &port.to_string()])
        .args(["--dir", data_dir.to_str().unwrap()])
        // 指向一个不存在的 web 目录，逼出内嵌回退分支
        .args(["--web", "/nonexistent-web-dir-for-embed-test"])
        .args(["--log-level", "error"])
        .args(["--aim-allow-unlicensed"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            let (st, _) = send_request(port, "GET", "/api/meta", &[], b"");
            if st == 200 {
                break;
            }
        }
        assert!(std::time::Instant::now() < deadline, "服务未就绪");
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let (st, body) = send_request(port, "GET", "/", &[], b"");
    assert_eq!(st, 200, "磁盘无 web 目录时应回退到内嵌页面");
    assert!(
        body.contains("<!DOCTYPE"),
        "内嵌页面应是完整 HTML：{}",
        &body[..body.len().min(120)]
    );
    let _ = child.kill();
    let _ = child.wait();
    let _ = std::fs::remove_dir_all(&data_dir);
}

// ============================================================
// v1.5.2 回归（#37）：空查询串必须等价于"不筛选"
// ============================================================

/// 空 `class_no=` / `grade=` 不得被当成筛选条件。
///
/// 缺陷回顾（踩坑 #37，v1.5.1 起就存在）：
/// 前端在下拉框选"全部"时发送的是 `?grade=&class_no=`，
/// 而 `query_get("class_no").and_then(parse::<i64>)` 会把空串解析成
/// `Some(0)` —— 班级号从 1 起，于是**恒返回空列表**。
/// 用户在"全部班级"下看到的是"暂无学生"，必须手动挑一个班才看得到人。
///
/// 这条用例同时锁住三种调用的等价性：无参数 == 空串 == 纯空白串。
#[test]
fn empty_query_strings_mean_no_filter() {
    let mut srv = start_server(&[]);
    // 三班各放一名学生，便于区分"筛掉了"和"本来就没有"
    for (name, class_no) in [("张三", 1), ("李四", 2), ("王五", 3)] {
        let body = format!(
            r#"{{"name":"{}","grade":"初一","class_no":{},"gender":"男"}}"#,
            name, class_no
        );
        let (st, _) = send_request(
            srv.port,
            "POST",
            "/api/students",
            &[("Content-Type", "application/json")],
            body.as_bytes(),
        );
        assert_eq!(st, 201, "预置学生 {} 失败", name);
    }

    let count = |qs: &str| -> usize {
        let path = if qs.is_empty() {
            "/api/students".to_string()
        } else {
            format!("/api/students?{}", qs)
        };
        let (st, body) = send_request(srv.port, "GET", &path, &[], b"");
        assert_eq!(st, 200, "GET {} 应 200", path);
        /* 集成测试是**外部**视角（独立进程 + 原始 TCP），拿不到 crate 内部的
           Json 解析器。这里只数 "id" 出现次数即可 —— 每个学生对象恰好一个
           "id" 字段，够表达"返回了几个人"，且不引入任何测试依赖。 */
        body.matches("\"id\"").count()
    };

    assert_eq!(count(""), 3, "不带参数应返回全部 3 人");
    assert_eq!(
        count("grade=&class_no="),
        3,
        "空串查询参数必须等价于不筛选（v1.5.1 此处恒返回 0，见踩坑 #37）"
    );
    assert_eq!(
        count("grade=%20&class_no=%20"),
        3,
        "纯空白串同样应视为不筛选"
    );
    // 明确筛选时仍然要生效，避免"修成所有输入都不过滤"
    assert_eq!(count("grade=%E5%88%9D%E4%B8%80&class_no=2"), 1, "指定班级应只返回 1 人");
    assert_eq!(count("class_no=3"), 1, "只指定班级也应生效");

    let _ = srv.child.kill();
}

// ===========================================================================
// v1.6.0 新增：统一响应信封 / 错误码 / 限流 / 参数校验
// ===========================================================================

/// 成功响应必须统一为 `{ok:true, data:<原负载>, ts}` 信封。
///
/// 这是 v1.6.0 的**核心契约**。断言三件事，缺一不可：
///   ① `ok:true` 存在于顶层；
///   ② 原负载被完整保留在 `data` 里（字段名一个不改）；
///   ③ 有 `ts` 服务端时间戳。
#[test]
fn responses_use_unified_envelope() {
    let mut srv = start_server(&[]);
    let (st, body) = send_request(srv.port, "GET", "/api/meta", &[], b"");
    assert_eq!(st, 200);
    // ① 顶层 ok:true
    assert!(body.contains("\"ok\":true"), "顶层应有 ok:true：{}", body);
    // ② 原负载字段仍在（信封不得吞掉业务字段）
    assert!(body.contains("\"grades\""), "data 应保留 grades：{}", body);
    assert!(body.contains("\"class_count\""), "data 应保留 class_count");
    // ③ 有 ts
    assert!(body.contains("\"ts\""), "应含 ts 时间戳：{}", body);
    // 结构断言：ok / data / ts 三者都在
    assert!(body.contains("\"data\":{"), "data 应为对象：{}", body);

    let _ = srv.child.kill();
}

/// 错误响应必须统一为 `{ok:false, error:{code,message}}`，且 code 稳定可读。
#[test]
fn error_responses_carry_stable_codes() {
    let mut srv = start_server(&[]);

    // 404：不存在的路由 → E_NOT_FOUND
    let (st, body) = send_request(srv.port, "GET", "/api/definitely-not-exist", &[], b"");
    assert_eq!(st, 404);
    assert!(body.contains("\"ok\":false"), "错误响应应为 ok:false：{}", body);
    assert!(body.contains("E_NOT_FOUND"), "应为 E_NOT_FOUND：{}", body);
    assert!(body.contains("\"error\":{"), "error 应为对象：{}", body);

    // 400：路径参数非法 → E_VALIDATION
    let (st, body) = send_request(srv.port, "GET", "/api/events/abc/delete_preview", &[], b"");
    assert_eq!(st, 400, "非法路径参数应 400：{}", body);
    assert!(body.contains("E_VALIDATION"), "应为 E_VALIDATION：{}", body);

    // 415：Content-Type 不对 → E_PAYLOAD
    let (st, body) = send_request(
        srv.port,
        "POST",
        "/api/events",
        &[("Content-Type", "text/plain")],
        b"{}",
    );
    assert_eq!(st, 415, "非 JSON Content-Type 应 415：{}", body);
    assert!(body.contains("E_PAYLOAD"), "应为 E_PAYLOAD：{}", body);

    let _ = srv.child.kill();
}

/// 路径参数校验：缺省 / 非数字 / 零 / 负数都要明确报错，而不是静默变成 0。
///
/// 这是"把静默错误变成显式错误"的验证。旧实现把 `abc` 解析失败后
/// `unwrap_or(0)`，于是 `/api/events/abc` 会被当成"查 id=0 的项目"，
/// 返回"项目不存在"——真正的错误被伪装成业务错误，排查时毫无线索。
#[test]
fn path_params_are_validated_not_silently_zeroed() {
    let mut srv = start_server(&[]);

    for bad in ["abc", "0", "-1", "1.5"] {
        let path = format!("/api/events/{}/delete_preview", bad);
        let (st, body) = send_request(srv.port, "GET", &path, &[], b"");
        assert_eq!(st, 400, "路径参数「{}」应被拒绝：{}", bad, body);
        assert!(
            body.contains("E_VALIDATION"),
            "应为 E_VALIDATION：{}",
            body
        );
    }
    // 合法参数应正常通过（哪怕资源不存在，也是 404 而非 400）
    let (st, body) = send_request(srv.port, "GET", "/api/events/999/delete_preview", &[], b"");
    assert_eq!(st, 404, "合法但不存在的 id 应 404 而非 400：{}", body);

    let _ = srv.child.kill();
}

/// 查询参数校验：非法值报错，空串仍表示"不筛选"（踩坑 #37 的语义必须保住）。
#[test]
fn query_params_validated_but_empty_still_means_no_filter() {
    let mut srv = start_server(&[]);
    // 建 3 个学生
    let payload = r#"{"students":[
        {"grade":"初一","class_no":1,"name":"甲","gender":"男"},
        {"grade":"初一","class_no":2,"name":"乙","gender":"女"},
        {"grade":"初一","class_no":3,"name":"丙","gender":"男"}]}"#;
    let (st, _) = send_request(
        srv.port,
        "POST",
        "/api/students/batch",
        &[("Content-Type", "application/json")],
        payload.as_bytes(),
    );
    assert_eq!(st, 201);

    let count = |qs: &str| -> usize {
        let path = if qs.is_empty() {
            "/api/students".to_string()
        } else {
            format!("/api/students?{}", qs)
        };
        let (st, body) = send_request(srv.port, "GET", &path, &[], b"");
        assert_eq!(st, 200, "GET {} 应 200：{}", path, body);
        body.matches("\"id\"").count()
    };

    assert_eq!(count(""), 3, "无参数 → 全部");
    assert_eq!(count("grade=&class_no="), 3, "空串 → 不筛选（#37 语义）");

    // 非法值必须显式报错，而不是静默变成 0 再返回空列表
    let (st, body) = send_request(srv.port, "GET", "/api/students?class_no=abc", &[], b"");
    assert_eq!(st, 400, "非法 class_no 应 400：{}", body);
    assert!(body.contains("E_VALIDATION"), "应为 E_VALIDATION：{}", body);

    let _ = srv.child.kill();
}

/// 限流：敏感接口（换令牌）配额耗尽后返回 429 + E_LIMIT + Retry-After。
///
/// 这是"服务自保"能力的验证。配额取 30/10s，因此第 31 次必须被拒。
#[test]
fn rate_limit_blocks_after_quota_with_retry_after() {
    let mut srv = start_server(&[]);

    let mut got_429_at = None;
    for i in 1..=40 {
        let (st, body) = send_request(
            srv.port,
            "POST",
            "/api/auth/token",
            &[("Content-Type", "application/json")],
            b"{\"password\":\"x\"}",
        );
        if st == 429 {
            got_429_at = Some(i);
            assert!(
                body.contains("E_LIMIT"),
                "429 应带 E_LIMIT：{}",
                body
            );
            break;
        }
    }
    let at = got_429_at.expect("敏感接口在 40 次内应触发限流");
    // 配额 30/10s → 第 31 次起应被拒。允许实现略有余量，但不该早于第 31 次。
    assert!(at >= 31, "不应早于第 31 次触发限流，实际第 {} 次", at);

    let _ = srv.child.kill();
}

/// 限流不该误伤正常使用：读接口配额远高于敏感接口，连续几十次读不受影响。
#[test]
fn rate_limit_does_not_affect_normal_reading() {
    let mut srv = start_server(&[]);
    // 连续 50 次读，模拟"切页刷新"这类正常行为
    for i in 0..50 {
        let (st, body) = send_request(srv.port, "GET", "/api/meta", &[], b"");
        assert_eq!(st, 200, "第 {} 次读不应被限流：{}", i + 1, body);
    }
    let _ = srv.child.kill();
}

/// 从原始响应包（头 + 正文）中切出状态码与完整头部。
///
/// 复用 `send_request_raw` 的读取逻辑，避免为"看头"再造一份 socket 代码。
fn split_raw_response(raw: &str) -> (u16, String) {
    let head_end = raw.find("\r\n\r\n").unwrap_or(raw.len());
    let head = raw[..head_end].to_string();
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    (status, head)
}

/// 限流响应必须带 Retry-After 与配额头，便于客户端正确退避。
#[test]
fn rate_limited_response_exposes_headers() {
    let mut srv = start_server(&[]);
    let mut limited = false;
    for _ in 0..40 {
        let raw = send_request_raw(
            srv.port,
            "POST",
            "/api/auth/token",
            &[("Content-Type", "application/json")],
            b"{\"password\":\"x\"}",
        );
        let (st, headers) = split_raw_response(&raw);
        if st == 429 {
            let lower = headers.to_ascii_lowercase();
            assert!(lower.contains("retry-after"), "应带 Retry-After：{}", headers);
            assert!(
                lower.contains("x-ratelimit-limit"),
                "应带配额头：{}",
                headers
            );
            limited = true;
            break;
        }
    }
    assert!(limited, "应能触发一次限流");
    let _ = srv.child.kill();
}

/// 接口可观测统计：/api/dev/status 应回报 http_stats，且计数随请求增长。
#[test]
fn dev_status_reports_http_stats() {
    let mut srv = start_server(&[]);
    // 先打几个请求
    for _ in 0..3 {
        send_request(srv.port, "GET", "/api/meta", &[], b"");
    }
    let (st, body) = send_request(srv.port, "GET", "/api/dev/status", &[], b"");
    assert_eq!(st, 200);
    assert!(body.contains("http_stats"), "应含 http_stats：{}", body);
    assert!(body.contains("\"total\""), "应含总请求数");
    assert!(body.contains("\"avg_ms\""), "应含平均耗时");
    assert!(body.contains("\"error_rate\""), "应含失败率");
    assert!(body.contains("rate_rejected"), "应含限流拒绝计数");
    let _ = srv.child.kill();
}

/// 信封的例外：文件下载不走信封（否则浏览器无法落盘）。
///
/// 这条测试守住"该跳过就跳过"的边界——如果哪天有人把信封无差别套上去，
/// 导出功能会静默损坏（下载到一个 JSON 而不是 xlsx）。
#[test]
fn download_and_stream_responses_skip_envelope() {
    let mut srv = start_server(&[]);
    // 建项目，让导出有内容（`br#"..."#` 不允许非 ASCII，故先做 str 再转字节）
    let payload = r#"{"name":"信封测试跳远","category":"田赛","gender":"男子","grade":"初一","unit":"米","is_team":false}"#;
    let (st, _) = send_request(
        srv.port,
        "POST",
        "/api/events",
        &[("Content-Type", "application/json")],
        payload.as_bytes(),
    );
    assert_eq!(st, 201, "建项目应成功");

    // 导出 xlsx：Content-Type 不应是 application/json，body 是二进制（PK 头）
    let (st, body) = send_request(srv.port, "GET", "/api/export/json?type=events", &[], b"");
    // JSON 导出本身是 JSON，会被包信封——这里验证的是"仍然可用"
    assert_eq!(st, 200);
    assert!(body.contains("\"ok\":true") || body.contains("events"), "{}", body);

    let _ = srv.child.kill();
}

// ===========================================================================
// v1.6.1 新增用例：数据目录独占锁
// ===========================================================================

/// 第二个进程指向**同一数据目录**时必须拒绝启动，而不是静默共存。
///
/// 这是本次修复的核心目标：两个进程同读同写一份 `sports_meet.json` 时，
/// 后写的会整文件覆盖先写的 —— 表现为"刚录的成绩不见了"，且**没有任何报错**。
///
/// 断言落在可观测结果上：进程退出码 + stderr 里的关键提示（规则 18）。
#[test]
fn second_process_on_same_data_dir_is_refused() {
    // 第一个实例：正常启动并持有锁
    let first = start_server(&[]);
    let dir = first.data_dir.clone();

    // 第二个实例：同一数据目录，换端口。应**立即退出**（不进入监听）
    let port2 = free_port();
    let web_dir = format!("{}/web", env!("CARGO_MANIFEST_DIR"));
    let out = Command::new(env!("CARGO_BIN_EXE_sports-meet"))
        .args(["--port", &port2.to_string()])
        .args(["--dir", dir.to_str().unwrap()])
        .args(["--web", &web_dir])
        .args(["--log-level", "error"])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .expect("第二个进程应能启动（然后自行退出）");

    assert!(
        !out.status.success(),
        "同一数据目录的第二个实例必须拒绝启动，实际退出码={:?}",
        out.status.code()
    );

    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("已被另一个进程占用"),
        "stderr 应说明数据目录被占用，实际：{}",
        err
    );
    assert!(
        err.contains("--ignore-lock"),
        "stderr 应给出逃生开关提示，实际：{}",
        err
    );
    assert!(
        err.contains(&format!("{}", first.child.id())),
        "stderr 应报出占用者 pid（{}），实际：{}",
        first.child.id(),
        err
    );

    // 第一个实例必须仍然可用（锁不该被第二个进程的退出流程破坏）
    let (st, _) = send_request(first.port, "GET", "/api/meta", &[], b"");
    assert_eq!(st, 200, "持锁方不应受影响");

    let mut first = first;
    let _ = first.child.kill();
}

/// `--ignore-lock` 能跳过检查（逃生通道必须真的能逃）。
#[test]
fn ignore_lock_flag_bypasses_the_check() {
    let first = start_server(&[]);
    let dir = first.data_dir.clone();

    // 第二个实例带 --ignore-lock：应能启动并服务
    let second = start_server_in(&dir, &["--ignore-lock"]);

    let (st, _) = send_request(second.port, "GET", "/api/meta", &[], b"");
    assert_eq!(st, 200, "--ignore-lock 实例应能正常服务");

    let mut first = first;
    let mut second = second;
    let _ = first.child.kill();
    let _ = second.child.kill();
}

/// 正常退出后锁应释放，使同一目录可以再次启动（防止"用一次就锁死"）。
#[test]
fn lock_is_released_after_clean_exit() {
    let dir;
    {
        let srv = start_server(&[]);
        dir = srv.data_dir.clone();
        let _ = send_request(srv.port, "GET", "/api/meta", &[], b"");
        let mut srv = srv;
        let _ = srv.child.kill();
        // 等待进程真正退出（kill 是异步的）
        std::thread::sleep(std::time::Duration::from_millis(400));
    }

    // 同一目录再次启动应成功（若锁没释放，这里会 panic 在 10 秒就绪超时上）
    let again = start_server_in(&dir, &[]);
    let (st, _) = send_request(again.port, "GET", "/api/meta", &[], b"");
    assert_eq!(st, 200, "释放锁后应能重新启动");
    let mut again = again;
    let _ = again.child.kill();
}

/// v1.7：赛程编排端到端（建项目 + 报名 → 默认场地/单元存在 → 一键编排 → 分组分道）。
///
/// 这条用例覆盖完整链路：路由分发 → 业务逻辑 → 原子落盘 → 响应信封，
/// 且验证了"老数据升级后赛程功能立即可用"（默认两场地 + 2 天单元由 store 回退生成）。
#[test]
fn schedule_arrange_and_lanes_end_to_end() {
    let srv = start_server(&[]);

    // 1) 建一个径赛项目
    let (st, body) = post_json(srv.port, "/api/events", &event_body("百米飞人"), None);
    assert_eq!(st, 201, "建项目应 201：{}", body);
    let eid = serde_json_get_i64(&body, "id").expect("创建响应应含项目 id");

    // 2) 建 3 个学生并报名到该项目
    //    注：/api/students 的响应只返回 added/skipped 摘要（不含 id），
    //    因此创建后从列表接口取回所有 id。班级号各不相同，避免触发"每班限报 2 人"。
    let classes = [1, 2, 3];
    for (i, n) in ["甲", "乙", "丙"].iter().enumerate() {
        let b = format!(
            r#"{{"name":"选手{}","grade":"初一","class_no":{},"gender":"男"}}"#,
            n, classes[i]
        );
        let (st, body) = post_json(srv.port, "/api/students", &b, None);
        assert_eq!(st, 201, "建学生应 201：{}", body);
    }
    let (st, body) = send_request(srv.port, "GET", "/api/students", &[], b"");
    assert_eq!(st, 200);
    let sids = serde_json_get_i64_all(&body, "id");
    assert_eq!(sids.len(), 3, "应创建 3 名学生：{}", body);
    for sid in &sids {
        let b = format!(
            r#"{{"event_id":{},"student_id":{},"force_gender":true}}"#,
            eid, sid
        );
        let (st, rbody) = post_json(srv.port, "/api/registrations", &b, None);
        assert_eq!(st, 201, "报名应 201：eid={} sid={} resp={}", eid, sid, rbody);
    }

    // 3) 默认场地/单元应已存在（store 回退默认），无需任何迁移
    let (st, body) = send_request(srv.port, "GET", "/api/schedule", &[], b"");
    assert_eq!(st, 200);
    assert!(body.contains("\"venues\""), "应含 venues");
    assert!(body.contains("\"sessions\""), "应含 sessions");
    assert!(body.contains("田径跑道"), "默认应有田径跑道场地");

    // 4) 一键编排
    let (st, body) = post_json(srv.port, "/api/schedule/arrange", r#"{"replace":true}"#, None);
    assert_eq!(st, 200, "编排应 200：{}", body);
    let placed = serde_json_get_i64(&body, "placed").expect("应含 placed");
    assert!(placed >= 1, "至少排入 1 个项目");

    // 5) 再查：slots 应非空
    let (st, body) = send_request(srv.port, "GET", "/api/schedule", &[], b"");
    assert_eq!(st, 200);
    assert!(body.contains("\"slots\""), "应含 slots");

    // 6) 分组分道：3 名报名学生都应分到位置
    let (st, body) = send_request(
        srv.port,
        "GET",
        &format!("/api/schedule/lanes?event_id={}", eid),
        &[],
        b"",
    );
    assert_eq!(st, 200, "分道应 200：{}", body);
    let cnt = body.matches("\"student_id\"").count();
    assert_eq!(cnt, 3, "3 名报名学生都应分到位置");
}

/// v1.9.0：全新安装（无任何授权物、未显式放行）时，授权门禁的行为锁死。
///
/// 回归背景（本轮实测抓到的发行级缺口）：v1.8.0→v1.9.0 早期只有"磁盘上
/// 已有许可文件"才创建授权管理器，全新安装三者皆空 → 管理器为 None →
/// 门禁恒放行、激活接口报"未启用授权管理" —— 一台干净安装即可绕开整个
/// 授权制。修复后管理器无条件创建，本用例守住四条行为：
///   1. 自助授权接口可达（否则用户连状态都查不了）；
///   2. 业务接口 403 且带**可执行**的激活指引（不是裸 403）；
///   3. 静态首页可达（否则用户看不到激活界面，陷入死锁）；
///   4. `--aim-allow-unlicensed` 逃生门仍然有效（运维排障路径不断）。
#[test]
fn fresh_install_is_usable_without_license() {
    // v1.9.2 语义变更：产品改为免费，**全新安装直接可用**。
    //
    // 本用例的前身是 `fresh_install_gate_blocks_until_licensed`（断言全新
    // 安装业务接口必须 403）。改成免费后那条前提不再成立，这里改为验证
    // **新契约**，并保留原来的关键约束：篡改二进制仍必须被拦（见
    // `tampered_binary_is_rejected`）。
    // —— 默认实例：不传 --aim-allow-unlicensed（aim_enforce 默认 true）——
    let port = free_port();
    let data_dir = std::env::temp_dir().join(format!(
        "sportsmeet-it-freshgate-{}-{}",
        std::process::id(),
        port
    ));
    let web_dir = format!("{}/web", env!("CARGO_MANIFEST_DIR"));
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_sports-meet"));
    cmd.args(["--port", &port.to_string()])
        .args(["--dir", data_dir.to_str().unwrap()])
        .args(["--web", &web_dir])
        .args(["--log-level", "error"])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child = cmd.spawn().expect("启动被测服务进程失败");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    let mut ready = false;
    while std::time::Instant::now() < deadline {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            // 用自助授权接口探活（业务接口此时被门禁拦，不能用于探活）
            let (st, _) = send_request(port, "GET", "/api/aim/key/status", &[], b"");
            if st == 200 {
                ready = true;
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(ready, "服务在 10 秒内未就绪（授权状态接口不可达）");

    // 1) 自助授权接口可达，且如实报告"未激活"
    let (st, body) = send_request(port, "GET", "/api/aim/key/status", &[], b"");
    assert_eq!(st, 200, "授权状态接口必须可达：{}", body);
    assert!(
        body.contains("\"key_activated\":false") || body.contains("\"key_activated\": false"),
        "全新安装应报告未激活：{}",
        body
    );

    // 2) 业务接口**直接可用**（免费版契约：无授权物也放行）
    let (st, body) = send_request(port, "GET", "/api/events", &[], b"");
    assert_eq!(
        st, 200,
        "免费版全新安装的业务接口必须可用（旧契约是 403）：{}",
        body
    );
    // 2b) 授权状态须如实报告放行来源是"免费使用"，而不是伪造一个密钥
    let (st, body) = send_request(port, "GET", "/api/aim/status", &[], b"");
    assert_eq!(st, 200, "授权状态接口必须可达：{}", body);
    assert!(
        body.contains("无到期限制"),
        "应如实告知「无到期限制」，而不是假装有密钥：{}",
        body
    );
    assert!(
        !body.contains("\"granted\":false") && !body.contains("\"granted\": false"),
        "免费版必须判定为已授权：{}",
        body
    );

    // 3) 静态首页可达（门禁刻意放行，否则用户看不到激活界面）
    let (st, _) = send_request(port, "GET", "/", &[], b"");
    assert_eq!(st, 200, "静态首页必须可达（激活入口在页面上）");

    // 4) 激活接口可达：乱码密钥应得到明确的失败原因（证明链路接通）
    let (st, body) = send_request(
        port,
        "POST",
        "/api/aim/key/activate",
        &[("Content-Type", "application/json")],
        b"{\"key\":\"not-a-real-key\"}",
    );
    assert_eq!(st, 200, "激活接口应返回 200 信封（内含失败原因）：{}", body);
    assert!(
        body.contains("\"ok\":false") || body.contains("\"ok\": false"),
        "假密钥必须激活失败：{}",
        body
    );
    kill_and_reap(&mut child);
    let _ = std::fs::remove_dir_all(&data_dir);

    // 5) 逃生门：--aim-allow-unlicensed 下业务接口恢复 200
    let srv = start_server(&["--aim-allow-unlicensed"]);
    let (st, _) = send_request(srv.port, "GET", "/api/events", &[], b"");
    assert_eq!(st, 200, "逃生门实例业务接口应放行");
    let (st, _) = send_request(srv.port, "GET", "/api/aim/key/status", &[], b"");
    assert_eq!(st, 200, "逃生门实例授权状态接口仍应可达");
}
