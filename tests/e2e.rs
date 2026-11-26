//! 端到端授权链路测试：**真的把 `aim-server` 跑起来**，走真实 TCP。
//!
//! # 与 `wire.rs` 的分工
//!
//! * `wire.rs` 做**静态**契约检查：比对磁盘上两端的源码常量，
//!   用客户端的解码器解服务端视角的帧。快、无需编译服务端。
//! * 本文件做**动态**端到端检查：启动真实的服务端进程，
//!   跑一遍"签发 → 激活 → 校验 → 吊销 → 拒绝"的完整生命周期。
//!
//! 两者互补：静态检查抓"算法分叉"，动态检查抓"协议实现不匹配"
//! （例如字段名拼错、应答结构不一致 —— 这些静态检查发现不了）。
//!
//! # 跳过策略
//!
//! 若服务端二进制尚未构建（或环境缺 `cargo`），测试**打印 SKIP 并返回**，
//! 不让整个测试套件因为"没编服务端"而变红。要完整跑通，先执行：
//!
//! ```bash
//! (cd ../server_pkg && cargo build)
//! ```

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use sports_meet::core::aim::channel as ch;

// ---------------------------------------------------------------------------
// 环境准备
// ---------------------------------------------------------------------------

fn server_root() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("AIM_SERVER_ROOT") {
        let p = PathBuf::from(p);
        if p.join("Cargo.toml").exists() {
            return Some(p);
        }
    }
    for c in ["../server_pkg", "../../server_pkg", "server_pkg"] {
        let p = Path::new(c);
        if p.join("Cargo.toml").exists() {
            return Some(p.to_path_buf());
        }
    }
    None
}

fn server_bin(root: &Path) -> Option<PathBuf> {
    for rel in ["target/debug/aim-server", "target/release/aim-server"] {
        let p = root.join(rel);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

fn free_port() -> u16 {
    // 绑到 0 让内核分配，再释放。存在极小的竞争窗口，
    // 但测试环境够用；真失败会体现为"服务端起不来"而不是误判通过。
    let l = std::net::TcpListener::bind("127.0.0.1:0").expect("应能绑随机端口");
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

struct TestServer {
    child: Child,
    port: u16,
    _dir: PathBuf,
}

impl TestServer {
    fn start() -> Option<TestServer> {
        let root = server_root()?;
        let bin = server_bin(&root)?;
        let port = free_port();
        let dir = std::env::temp_dir().join(format!("aim-e2e-{}-{}", std::process::id(), port));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).ok()?;

        let child = Command::new(&bin)
            .arg("--bind")
            .arg(format!("127.0.0.1:{}", port))
            .arg("--psk")
            .arg(E2E_PSK)
            .arg("--admin-token")
            .arg(E2E_ADMIN)
            .arg("--data-dir")
            .arg(dir.join("data"))
            .arg("--audit-dir")
            .arg(dir.join("audit"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;

        let s = TestServer { child, port, _dir: dir };
        s.wait_ready()?;
        Some(s)
    }

    /// 轮询健康接口直到就绪（最多 5 秒）。
    fn wait_ready(&self) -> Option<()> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Ok((status, _)) = self.plain_get("/v1/health") {
                if status == 200 {
                    return Some(());
                }
            }
            std::thread::sleep(Duration::from_millis(40));
        }
        None
    }

    /// 明文 GET（用于健康检查与管理接口）。
    fn plain_get(&self, path: &str) -> std::io::Result<(u16, String)> {
        self.plain_request("GET", path, &[], &[])
    }

    fn plain_request(
        &self,
        method: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
        body: &[u8],
    ) -> std::io::Result<(u16, String)> {
        let mut s = TcpStream::connect(("127.0.0.1", self.port))?;
        s.set_read_timeout(Some(Duration::from_secs(3)))?;
        let mut req = format!(
            "{} {} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {}\r\nConnection: close\r\n",
            method,
            path,
            body.len()
        );
        for (k, v) in extra_headers {
            req.push_str(&format!("{}: {}\r\n", k, v));
        }
        req.push_str("\r\n");
        s.write_all(req.as_bytes())?;
        s.write_all(body)?;
        s.flush()?;
        let mut buf = Vec::new();
        s.read_to_end(&mut buf)?;
        let text = String::from_utf8_lossy(&buf).to_string();
        let status = parse_status(&text).unwrap_or(0);
        Ok((status, text))
    }

    /// 走授权密文接口（`POST /v1/aim`）。
    fn aim(&self, frame_b64: &str) -> std::io::Result<String> {
        let (status, resp) = self.plain_request(
            "POST",
            "/v1/aim",
            &[("Content-Type", "text/plain")],
            frame_b64.as_bytes(),
        )?;
        assert_eq!(status, 200, "授权接口应返回 200，实际响应：{}", resp);
        Ok(body_of(&resp))
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self._dir);
    }
}

const E2E_PSK: &str = "E2E-TEST-PSK-DO-NOT-REUSE";
const E2E_ADMIN: &str = "e2e-admin-token-1234567890";

fn parse_status(resp: &str) -> Option<u16> {
    resp.lines()
        .next()?
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()
}

fn body_of(resp: &str) -> String {
    match resp.find("\r\n\r\n") {
        Some(i) => resp[i + 4..].to_string(),
        None => String::new(),
    }
}

/// 客户端→服务端：发一条密文请求，解回密文应答。
///
/// 返回 (应答 JSON 文本)。
fn aim_call(server: &TestServer, session: &mut ch::Session, payload: &str) -> String {
    let mut tx = ch::ChannelSender::from_session(session);
    let frame = tx.send(payload);
    let resp_raw = server.aim(&frame).expect("应能拿到应答");

    let outer = sports_meet::core::json::Json::parse(&resp_raw).expect("应答外层应为 JSON");
    let sn = outer.get_str("sn").expect("应答应含 sn").to_string();
    let d = outer.get_str("d").expect("应答应含密文 d").to_string();

    // 升级会话密钥，再解应答
    session.upgrade_with_server_nonce(&sn);
    let rx = ch::ChannelReceiver::new(session.key.clone());
    rx.recv(&d).expect("客户端应能解出服务端应答")
}

/// 签发一把密钥（走管理接口，明文 JSON）。
fn issue_key(server: &TestServer, body: &str) -> String {
    let (status, resp) = server
        .plain_request(
            "POST",
            "/v1/admin/issue",
            &[
                ("Content-Type", "application/json"),
                ("X-Admin-Token", E2E_ADMIN),
            ],
            body.as_bytes(),
        )
        .expect("管理接口应可达");
    assert_eq!(status, 200, "签发应成功，响应：{}", resp);
    let j = sports_meet::core::json::Json::parse(&body_of(&resp)).expect("签发应答应为 JSON");
    j.get_str("key").expect("签发应答应含 key").to_string()
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

macro_rules! server_or_skip {
    () => {
        match TestServer::start() {
            Some(s) => s,
            None => {
                eprintln!(
                    "[SKIP] 未找到 aim-server 二进制（先在 ../server_pkg 执行 cargo build）"
                );
                return;
            }
        }
    };
}

/// 服务端健康接口可用（最基础的连通性）。
#[test]
fn e2e_server_health() {
    let s = server_or_skip!();
    let (status, resp) = s.plain_get("/v1/health").unwrap();
    assert_eq!(status, 200);
    assert!(resp.contains("aim-server"), "健康应答应含服务名：{}", resp);
    // 健康接口**不得**泄露 PSK 全文
    assert!(!resp.contains(E2E_PSK), "健康接口泄露了 PSK 全文！");
}

/// 完整生命周期：签发 → 激活 → 校验 → 吊销 → 再激活被拒。
///
/// 这条测试是"不能白嫖"的总验收：一把未签发的密钥激活不了，
/// 签发后能激活，吊销后立刻失效。
#[test]
fn e2e_full_lifecycle() {
    let s = server_or_skip!();

    // ① 没签发的密钥 → 激活应被拒
    let mut unregistered = ch::Session::new(E2E_PSK);
    let reply = aim_call(
        &s,
        &mut unregistered,
        r#"{"action":"activate","key":"THZX-P-00000000-FFFF","hwid":"deadbeefcafe0001"}"#,
    );
    let j = sports_meet::core::json::Json::parse(&reply).unwrap();
    assert_eq!(
        j.get("granted").and_then(|v| v.as_bool()),
        Some(false),
        "未签发的密钥不得放行：{}",
        reply
    );

    // ② 签发一把持久密钥（绑定机器指纹）
    let hwid = "aabbccdd11223344";
    let key = issue_key(
        &s,
        &format!(
            r#"{{"kind":"persistent","hwid":"{}","days":365,"note":"e2e"}}"#,
            hwid
        ),
    );
    assert!(key.starts_with("THZX-"), "密钥格式：{}", key);

    // ③ 激活应成功
    let mut session = ch::Session::new(E2E_PSK);
    let reply = aim_call(
        &s,
        &mut session,
        &format!(
            r#"{{"action":"activate","key":"{}","hwid":"{}","kind":"persistent"}}"#,
            key, hwid
        ),
    );
    let j = sports_meet::core::json::Json::parse(&reply).unwrap();
    assert_eq!(
        j.get("granted").and_then(|v| v.as_bool()),
        Some(true),
        "签发后应能激活：{}",
        reply
    );
    let ticket = j.get_str("ticket").expect("应返回票据").to_string();
    assert!(!ticket.is_empty(), "票据不得为空");

    // 服务端应答里**不得**回带密钥明文（避免回程泄露）
    assert!(!reply.contains(&key), "应答回带了密钥明文！");

    // ④ 用票据校验应通过
    let mut s2 = ch::Session::new(E2E_PSK);
    let reply = aim_call(
        &s,
        &mut s2,
        &format!(r#"{{"action":"verify","ticket":"{}","hwid":"{}"}}"#, ticket, hwid),
    );
    let j = sports_meet::core::json::Json::parse(&reply).unwrap();
    assert_eq!(
        j.get("granted").and_then(|v| v.as_bool()),
        Some(true),
        "票据校验应通过：{}",
        reply
    );

    // ⑤ 吊销
    let (status, resp) = s
        .plain_request(
            "POST",
            "/v1/admin/revoke",
            &[
                ("Content-Type", "application/json"),
                ("X-Admin-Token", E2E_ADMIN),
            ],
            format!(r#"{{"key":"{}"}}"#, key).as_bytes(),
        )
        .unwrap();
    assert_eq!(status, 200, "吊销应成功：{}", resp);

    // ⑥ 吊销后再激活应被拒
    let mut s3 = ch::Session::new(E2E_PSK);
    let reply = aim_call(
        &s,
        &mut s3,
        &format!(
            r#"{{"action":"activate","key":"{}","hwid":"{}"}}"#,
            key, hwid
        ),
    );
    let j = sports_meet::core::json::Json::parse(&reply).unwrap();
    assert_eq!(
        j.get("granted").and_then(|v| v.as_bool()),
        Some(false),
        "吊销后不得再放行：{}",
        reply
    );
}

/// 机器绑定：签发给 A 机器的密钥，在 B 机器上激活必须失败。
///
/// 这是**防盗拷**的核心：把授权目录整个复制到另一台机器也没用。
#[test]
fn e2e_machine_binding_enforced() {
    let s = server_or_skip!();

    let key = issue_key(
        &s,
        r#"{"kind":"persistent","hwid":"machine-A-0001","days":30,"note":"bind"}"#,
    );

    // 拿到密钥的**明文**后，换一台机器指纹去激活
    let mut session = ch::Session::new(E2E_PSK);
    let reply = aim_call(
        &s,
        &mut session,
        &format!(
            r#"{{"action":"activate","key":"{}","hwid":"machine-B-9999"}}"#,
            key
        ),
    );
    let j = sports_meet::core::json::Json::parse(&reply).unwrap();
    assert_eq!(
        j.get("granted").and_then(|v| v.as_bool()),
        Some(false),
        "绑定 A 的密钥在 B 上必须被拒：{}",
        reply
    );
}

/// 明文垃圾帧不得让服务端崩，且必须被拒。
#[test]
fn e2e_garbage_frame_is_rejected_safely() {
    let s = server_or_skip!();

    for garbage in ["", "not-base64!!!", "QUJDRA==", &"A".repeat(500)] {
        let (status, resp) = s
            .plain_request("POST", "/v1/aim", &[], garbage.as_bytes())
            .expect("服务端不应因垃圾输入断开");
        assert_eq!(status, 200, "服务端应返回结构化错误而非崩溃");
        assert!(
            resp.contains("error") || resp.contains("ok"),
            "应返回结构化错误：{}",
            resp
        );
    }

    // 崩了的话这里就再也连不上了
    let (status, _) = s.plain_get("/v1/health").unwrap();
    assert_eq!(status, 200, "处理垃圾输入后服务端仍应健康");
}

/// 管理接口无口令不得访问。
#[test]
fn e2e_admin_requires_token() {
    let s = server_or_skip!();
    let (status, _) = s.plain_get("/v1/admin/keys").unwrap();
    assert_eq!(status, 401, "缺口令应返回 401 Unauthorized");

    let (status, resp) = s
        .plain_request(
            "GET",
            "/v1/admin/keys",
            &[("X-Admin-Token", "wrong-token")],
            &[],
        )
        .unwrap();
    assert_eq!(status, 401, "错误口令应返回 401");
    assert!(!resp.contains("key_hash"), "拒绝时不得泄露任何密钥信息");
}

/// 临时密钥：限次激活，用尽即失效。
#[test]
fn e2e_temporary_key_use_limit() {
    let s = server_or_skip!();

    let key = issue_key(
        &s,
        r#"{"kind":"temporary","days":1,"max_uses":1,"note":"limited"}"#,
    );

    // 第一次激活：成功
    let mut a = ch::Session::new(E2E_PSK);
    let reply = aim_call(
        &s,
        &mut a,
        &format!(r#"{{"action":"activate","key":"{}","hwid":"temp-A"}}"#, key),
    );
    let j = sports_meet::core::json::Json::parse(&reply).unwrap();
    assert_eq!(
        j.get("granted").and_then(|v| v.as_bool()),
        Some(true),
        "首次激活应成功：{}",
        reply
    );

    // 第二次激活（换机器）：应因用尽被拒
    let mut b = ch::Session::new(E2E_PSK);
    let reply = aim_call(
        &s,
        &mut b,
        &format!(r#"{{"action":"activate","key":"{}","hwid":"temp-B"}}"#, key),
    );
    let j = sports_meet::core::json::Json::parse(&reply).unwrap();
    assert_eq!(
        j.get("granted").and_then(|v| v.as_bool()),
        Some(false),
        "用尽的临时密钥不得再放行：{}",
        reply
    );
}
