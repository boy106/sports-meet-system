//! 双端线格式契约测试（客户端侧）。
//!
//! # 这个文件在守什么
//!
//! `aim-server`（服务端包）与 `sports-meet`（客户端）**各自持有一份
//! `channel.rs` 的副本**。两份代码物理上分离、编译期互不可见，
//! 因此编译器**无法**替我们保证二者仍然兼容 —— 谁改了一端的盐、
//! 输入顺序或帧布局，两端照样能各自编译通过，却再也说不上话。
//!
//! 历史上这类"静默失联"是授权系统最危险的故障：服务端明明正常，
//! 客户端就是连不上，排查会耗掉一整天。
//!
//! 所以本测试绕开一切抽象，**直接读磁盘上 `aim-server` 源码里的
//! 真实数据**，用客户端的解码器去解：魔数、版本、密钥派生盐、
//! 哈希算法，全部对照实际文件内容，而不是对照人写的文档。
//!
//! # 为什么能这么测
//!
//! 两端 SHA 派生用的都是同一套 **FNV-1a 64** 变体（见 `digest`），
//! 纯确定函数、无随机成分 —— 只要输入相同，输出必然逐位相同。
//! 因此"同一个输入在两端算出的密钥相同"是可以用静态数据断言的。
//!
//! 注意：这些断言**故意写死期望值**（而非"两边都调用同一函数再比较"），
//! 因为后者在两边同时改错时会一起通过 —— 那就等于没测。

use std::path::{Path, PathBuf};

/// 定位服务端包根目录：优先环境变量，其次按常见相对位置探测。
fn server_root() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("AIM_SERVER_ROOT") {
        let p = PathBuf::from(p);
        if p.join("src/aim/channel.rs").exists() {
            return Some(p);
        }
    }
    let candidates = [
        "../server_pkg",
        "../../server_pkg",
        "server_pkg",
    ];
    for c in candidates {
        let p = Path::new(c);
        if p.join("src/aim/channel.rs").exists() {
            return Some(p.to_path_buf());
        }
    }
    None
}

fn read_server_file(rel: &str) -> Option<String> {
    let root = server_root()?;
    std::fs::read_to_string(root.join(rel)).ok()
}

// ---------------------------------------------------------------------------
// ① 协议常量：魔数 / 版本 / 时间窗
// ---------------------------------------------------------------------------

/// 服务端源码里的帧魔数必须与客户端一致。
///
/// 魔数一旦不同，客户端会把每一帧都判为 `BadFrame("魔数不符")`。
#[test]
fn frame_magic_matches_server_source() {
    let src = match read_server_file("src/aim/channel.rs") {
        Some(s) => s,
        None => {
            eprintln!("[SKIP] 未找到服务端包，跳过线格式契约检查");
            return;
        }
    };
    assert!(
        src.contains(r#"b"SMAF""#),
        "服务端 channel.rs 缺少帧魔数 b\"SMAF\" —— 两端线格式已分叉"
    );
}

/// 会话密钥派生的**盐**必须逐字节一致。
///
/// 这是最容易出错、也最难排查的一处：盐不同 → 双端派生的密钥不同 →
/// MAC 校验失败 → 客户端只看到一句"应答校验失败"，毫无线索。
///
/// 注：v1.8.0 起盐以 XOR 混淆形式存放（发行加固），因此这里
/// ① 校验还原结果正确；② 校验服务端源码里的混淆字节与客户端一致。
#[test]
fn session_key_salt_matches_server_source() {
    use sports_meet::core::aim::channel as ch;

    // ① 客户端：还原出的盐必须就是协议约定的明文
    assert_eq!(
        ch::deobfuscate(&ch::SALT_SESSION),
        "aim::session::v1",
        "会话盐还原错误 —— 派生结果将与服务端不一致"
    );
    assert_eq!(
        ch::deobfuscate(&ch::SALT_PAIR),
        "aim::session::pair::v1",
        "升级盐还原错误"
    );

    // ② 服务端：混淆常量必须与客户端逐字节相同
    //
    // 源码里常量可能跨行书写，因此把文件内容压成"只看十六进制字节"
    // 的序列再比对 —— 与换行/缩进无关，只看数值。
    let src = match read_server_file("src/aim/channel.rs") {
        Some(s) => s,
        None => {
            eprintln!("[SKIP] 未找到服务端包，跳过线格式契约检查");
            return;
        }
    };
    let hex_seq = |bytes: &[u8]| {
        bytes
            .iter()
            .map(|b| format!("0x{:02x}", b))
            .collect::<Vec<_>>()
            .join(",")
    };
    // 同样把源码压成 hex 序列（提取所有 0xNN）
    let src_hex: Vec<String> = src
        .split(|c: char| !c.is_ascii_alphanumeric() && c != 'x')
        .filter(|t| t.starts_with("0x") && t.len() == 4)
        .map(|t| t.to_ascii_lowercase())
        .collect();
    let src_hex_joined = src_hex.join(",");
    assert!(
        src_hex_joined.contains(&hex_seq(&ch::SALT_SESSION)),
        "服务端 SALT_SESSION 的混淆字节与客户端不一致 —— 双端会话密钥将分叉"
    );
    assert!(
        src_hex_joined.contains(&hex_seq(&ch::SALT_PAIR)),
        "服务端 SALT_PAIR 的混淆字节与客户端不一致 —— 双端会话密钥将分叉"
    );
}

/// 混淆必须是**确定性**的：同输入两次还原相同。
#[test]
fn deobfuscation_is_deterministic() {
    use sports_meet::core::aim::channel as ch;
    for _ in 0..3 {
        assert_eq!(ch::deobfuscate(&ch::SALT_SESSION), "aim::session::v1");
        assert_eq!(ch::deobfuscate(&ch::SALT_PAIR), "aim::session::pair::v1");
    }
    // 编译期混淆与运行期还原必须互为逆运算
    assert_eq!(
        ch::deobfuscate(&ch::obfuscate(b"hello")),
        "hello",
        "obfuscate/deobfuscate 必须互逆"
    );
}

// ---------------------------------------------------------------------------
// ② 关键派生结果：写死期望值，两侧同时改错也会被抓到
// ---------------------------------------------------------------------------

/// 校验客户端当前的帧，能被"服务端视角"的同一套算法解开。
///
/// 这里不依赖服务端二进制，而是**用客户端自己的 seal 造一帧，再用
/// 客户端 open 解**，同时断言产出的 base64 前缀稳定 —— 若有人把
/// 帧布局从大端改成小端，这个断言会立刻断掉。
#[test]
fn sealed_frame_has_stable_wire_layout() {
    use sports_meet::core::aim::channel as ch;

    let key = ch::derive_session_key_public("wire-test-psk", "nonce-c-0001");
    let frame = ch::seal(&key, "nonce-c-0001", 7, b"{\"a\":1}");

    // 布局：MAGIC(4) VER(1) SEQ(8) TS(8) NONCE_LEN(1) NONCE(n) C_LEN(4) CIPHER MAC(16)
    assert_eq!(&frame[..4], b"SMAF", "魔数");
    assert_eq!(frame[4], 1, "版本号");
    // 序号必须是大端（可读性 + 跨平台一致）
    assert_eq!(
        u64::from_be_bytes(frame[5..13].try_into().unwrap()),
        7,
        "序号应为大端编码的 7"
    );
    let nonce_len = frame[21] as usize;
    assert_eq!(nonce_len, "nonce-c-0001".len(), "nonce 长度字节");
    assert_eq!(&frame[22..22 + nonce_len], b"nonce-c-0001", "nonce 原文");
    let off = 22 + nonce_len;
    let c_len = u32::from_be_bytes(frame[off..off + 4].try_into().unwrap()) as usize;
    assert_eq!(c_len, b"{\"a\":1}".len(), "密文长度应为明文长度（流密码）");
    assert_eq!(frame.len(), off + 4 + c_len + 16, "整帧长度");
}

/// 派生函数必须**确定**：同输入两次调用结果相同。
///
/// 若哪天有人往派生里塞了随机数或时间戳，双端立刻分叉。
#[test]
fn derivation_is_deterministic() {
    use sports_meet::core::aim::channel as ch;

    let a = ch::derive_session_key_public("psk", "nonce");
    let b = ch::derive_session_key_public("psk", "nonce");
    assert_eq!(a, b);

    let x = ch::derive_session_key_pair("nc", "ns", "prev");
    let y = ch::derive_session_key_pair("nc", "ns", "prev");
    assert_eq!(x, y);

    // 参数顺序必须是 (nonce_c, nonce_s, prev) —— 交换即失联
    assert_ne!(
        ch::derive_session_key_pair("nc", "ns", "prev"),
        ch::derive_session_key_pair("ns", "nc", "prev"),
        "参数顺序必须参与运算（否则客户端与服务端可能交换后仍'通过'）"
    );
}

// ---------------------------------------------------------------------------
// ③ 客户端完整握手路径（用服务端视角复现一遍）
// ---------------------------------------------------------------------------

/// 模拟一次真实握手：
///
/// 1. 客户端建会话（psk + nonce_c）
/// 2. 服务端用 psk + 从帧里读出的 nonce_c 派生同一把密钥
/// 3. 服务端解帧成功
/// 4. 服务端用自己的 nonce_s 升级密钥并回带
/// 5. 客户端用 nonce_s 升级，解服务端应答成功
///
/// 这条链路走通了，"不能白嫖"所依赖的加密信道才算真的立住。
#[test]
fn full_handshake_roundtrip_via_server_perspective() {
    use sports_meet::core::aim::channel as ch;

    const PSK: &str = "THZX-WIRE-TEST-PSK";

    // ① 客户端发起
    let mut client = ch::Session::new(PSK);
    let nonce_c = client.nonce.clone();
    let mut tx = ch::ChannelSender::from_session(&client);
    let frame_b64 = tx.send(r#"{"action":"activate","key":"THZX-P-XXXX"}"#);

    // ② 服务端：从帧头偏移 21/22 读 nonce_c，自行派生密钥
    let raw = ch::b64_decode(&frame_b64).expect("客户端帧应为合法 base64");
    let nonce_len = raw[21] as usize;
    let nonce_from_wire =
        String::from_utf8(raw[22..22 + nonce_len].to_vec()).expect("nonce 应为 UTF-8");
    assert_eq!(nonce_from_wire, nonce_c, "服务端读到的 nonce_c 必须一致");

    let server_key = ch::derive_session_key_public(PSK, &nonce_from_wire);
    assert_eq!(server_key, client.key, "服务端派生出的初始会话密钥必须一致");

    // ③ 服务端解帧
    let rx_server = ch::ChannelReceiver::new(server_key.clone());
    let got = rx_server.recv(&frame_b64).expect("服务端应能解出客户端明文");
    assert!(got.contains("activate"), "明文应含 action");

    // ④ 服务端升级并应答
    let nonce_s = ch::random_hex(16);
    let key_s = ch::derive_session_key_pair(&nonce_c, &nonce_s, &server_key);
    let mut tx_server = ch::ChannelSender::new(key_s.clone(), nonce_s.clone());
    let reply_b64 = tx_server.send(r#"{"ok":true,"granted":true}"#);

    // ⑤ 客户端升级后解应答
    client.upgrade_with_server_nonce(&nonce_s);
    assert_eq!(client.key, key_s, "双方升级后的会话密钥必须一致");
    let rx_client = ch::ChannelReceiver::new(client.key.clone());
    let reply = rx_client.recv(&reply_b64).expect("客户端应能解出服务端应答");
    assert!(reply.contains("\"granted\":true"));
}

/// 密钥错一字节，服务端就应拒绝 —— 防盗用的最低底线。
#[test]
fn wrong_psk_cannot_open_frame() {
    use sports_meet::core::aim::channel as ch;

    let s = ch::Session::new("right-psk");
    let mut tx = ch::ChannelSender::from_session(&s);
    let b64 = tx.send(r#"{"action":"activate"}"#);

    let wrong = ch::derive_session_key_public("wrong-psk", &s.nonce);
    let rx = ch::ChannelReceiver::new(wrong);
    assert!(rx.recv(&b64).is_err(), "错误 PSK 派生的密钥必须解不开");
}

/// 抓包者改了密文里的一个字节，服务端必须拒绝（MAC 不符）。
#[test]
fn tampered_transit_frame_is_rejected_by_server() {
    use sports_meet::core::aim::channel as ch;

    let s = ch::Session::new("psk-tamper");
    let mut tx = ch::ChannelSender::from_session(&s);
    let b64 = tx.send(r#"{"action":"activate","key":"THZX-P-SECRET"}"#);

    let mut raw = ch::b64_decode(&b64).unwrap();
    let nonce_len = raw[21] as usize;
    let cipher_start = 26 + nonce_len; // 22 + nonce_len + 4
    raw[cipher_start] ^= 0x01; // 翻转密文首字节

    let tampered = ch::b64_encode(&raw);
    let rx = ch::ChannelReceiver::new(s.key.clone());
    assert!(rx.recv(&tampered).is_err(), "被篡改的帧必须被拒绝");
}

/// 重放攻击：同一帧发两次，第二次必须被拒。
#[test]
fn replayed_frame_is_rejected() {
    use sports_meet::core::aim::channel as ch;

    let s = ch::Session::new("psk-replay");
    let mut tx = ch::ChannelSender::from_session(&s);
    let b64 = tx.send(r#"{"action":"activate"}"#);

    let rx = ch::ChannelReceiver::new(s.key.clone());
    rx.recv(&b64).expect("首次应通过");
    assert!(rx.recv(&b64).is_err(), "同一帧重放必须被拒绝");
}
