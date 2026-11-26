//! 同和中学校运会积分系统（Rust 版）入口。
//!
//! 架构：核心（core）提供全部领域 API；扩展（extensions）通过
//! `Extension` trait 挂接路由与事件钩子。本文件只做组装与启动。

mod core;
mod extensions;

use crate::core::api::Core;
use crate::core::http::{Router, serve};
use crate::core::license::License;
use crate::core::log::{self, LogLevel};
use crate::core::sync::LockExt;
use std::path::PathBuf;
use std::sync::Arc;

/// 当前版本号（v1.5.1）。
const VERSION: &str = "v1.9.12";

/// 配置文件结构（--config 指定；命令行参数优先级高于配置文件）。
#[derive(Default)]
struct Config {
    port: Option<u16>,
    dir: Option<PathBuf>,
    web: Option<PathBuf>,
    /// v1.2：日志级别（DEBUG/INFO/WARN/ERROR）
    log_level: Option<String>,
    /// v1.2：撤销栈保留步数
    undo_keep: Option<usize>,
    /// v1.4：管理员口令（设置后写接口需要 Authorization）
    password: Option<String>,
    /// v1.5.1：数据文件是否加密落盘（默认 false，保持 v1.5 兼容）
    encrypt_data: Option<bool>,
    /// v1.8.0：服务端授权配置节（host/port/psk/enabled）
    license_server: Option<crate::core::json::Json>,
    /// v1.8.0：无有效授权时是否拦截业务（默认 true）
    aim_enforce: Option<bool>,
}

fn load_config(path: &str) -> Result<Config, String> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| format!("无法读取配置文件 {}：{}", path, e))?;
    let j = crate::core::json::Json::parse(&text)
        .map_err(|e| format!("配置文件 JSON 解析失败：{}", e))?;
    Ok(Config {
        port: j.get("port").and_then(|v| v.as_i64()).map(|v| v as u16),
        dir: j.get_str("dir").map(PathBuf::from),
        web: j.get_str("web").map(PathBuf::from),
        log_level: j.get_str("log_level").map(|s| s.to_string()),
        undo_keep: j
            .get("undo_keep")
            .and_then(|v| v.as_i64())
            .map(|v| v.max(0) as usize),
        password: j.get_str("password").map(|s| s.to_string()),
        encrypt_data: j.get("encrypt_data").and_then(|v| v.as_bool()),
        license_server: j.get("license_server").cloned(),
        aim_enforce: j.get("aim_enforce").and_then(|v| v.as_bool()),
    })
}

const DEFAULT_CONFIG: &str = r#"{
  "port": 8765,
  "dir": "data",
  "web": "web",
  "log_level": "INFO",
  "undo_keep": 10,
  "password": "",
  "encrypt_data": false,
  "aim_enforce": false,
  "license_server": {
    "enabled": false,
    "host": "",
    "port": 8766,
    "psk": "__GENERATED_PSK__"
  }
}
"#;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    // --version / --gen-config 先行处理
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("同和中学校运会积分系统 {}（Rust 核心 + 扩展架构）", VERSION);
        println!("2026届二班 曾令韬 制作");
        return;
    }
    if let Some(pos) = args.iter().position(|a| a == "--gen-config") {
        let out = args.get(pos + 1).cloned().unwrap_or_else(|| "config.json".into());
        // v1.9.1 加固：模板不再携带固定 PSK，生成时随机填入一份
        //（与 license-server 端保持一致即可；泄露后改两侧重发）。
        let psk = crate::core::aim::channel::random_hex(24);
        let body = DEFAULT_CONFIG.replace("__GENERATED_PSK__", &psk);
        match std::fs::write(&out, body) {
            Ok(_) => println!(
                "已生成配置文件模板：{}（内置随机 license_server.psk，可用 --config {} 启用）",
                out, out
            ),
            Err(e) => {
                eprintln!("生成配置失败：{}", e);
                std::process::exit(1);
            }
        }
        return;
    }
    // 1) 配置文件为底层默认 → 2) 命令行参数覆盖
    let cfg = args
        .iter()
        .position(|a| a == "--config")
        .and_then(|p| args.get(p + 1))
        .map(|p| load_config(p).unwrap_or_else(|e| {
            eprintln!("{}", e);
            std::process::exit(1);
        }))
        .unwrap_or_default();
    let mut port: u16 = cfg.port.unwrap_or(8765);
    let mut dir = cfg.dir.clone().unwrap_or_else(|| PathBuf::from("data"));
    let mut web_dir = cfg.web.clone().unwrap_or_else(|| PathBuf::from("web"));
    // v1.2 可配置项
    let mut log_level_str = cfg.log_level.clone().unwrap_or_else(|| "INFO".into());
    let mut undo_keep = cfg.undo_keep.unwrap_or(10);
    // v1.4：管理员口令（空字符串 = 未启用）
    let mut password = cfg.password.clone().unwrap_or_default();
    // v1.5.1：开发者模式密钥 / 风险确认 / 数据加密
    let mut dev_key: Option<String> = None;
    let mut risk_acked = false;
    let mut encrypt_data = cfg.encrypt_data.unwrap_or(false);
    // v1.8.0：服务端授权
    let mut aim_cfg = crate::core::aim::AuthConfig::from_json(
        cfg.license_server.as_ref().unwrap_or(&crate::core::json::Json::Null),
    );
    let mut aim_enforce = cfg.aim_enforce.unwrap_or(false); // 开源版：默认不强制授权门禁
    // v1.9.1：排障逃生门加固 —— 发行构建下必须持解锁码才能关掉强制
    let mut unlock_requested = false;
    let mut unlock_code_arg: Option<String> = None;
    // v1.6.1：数据目录独占锁的逃生开关
    let mut ignore_lock = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" if i + 1 < args.len() => {
                port = args[i + 1].parse().unwrap_or(8765);
                i += 1;
            }
            "--dir" if i + 1 < args.len() => {
                dir = PathBuf::from(&args[i + 1]);
                i += 1;
            }
            "--web" if i + 1 < args.len() => {
                web_dir = PathBuf::from(&args[i + 1]);
                i += 1;
            }
            // v1.2 新增：日志级别
            "--log-level" if i + 1 < args.len() => {
                log_level_str = args[i + 1].clone();
                i += 1;
            }
            // v1.2 新增：撤销栈步数
            "--undo-keep" if i + 1 < args.len() => {
                match args[i + 1].parse::<usize>() {
                    Ok(v) => undo_keep = v,
                    Err(_) => {
                        eprintln!("--undo-keep 需要非负整数，收到：{}", args[i + 1]);
                        std::process::exit(2);
                    }
                }
                i += 1;
            }
            // v1.4 新增：管理员口令（启用后写接口需要 Authorization）
            "--password" if i + 1 < args.len() => {
                password = args[i + 1].clone();
                i += 1;
            }
            // v1.6.1 新增：忽略数据目录锁
            //
            // 用于两种情况：① 上次异常退出留下陈旧锁且 pid 恰好被复用；
            // ② 使用者**明确知道**要两个进程共写同一份数据（如临时对比）。
            //
            // 刻意做成"必须手工加"，而不是"自动清理陈旧锁"：
            // 自动清理会把"两个进程真在同时写"这件事变得更隐蔽 ——
            // 那是静默丢数据的根源，宁可让使用者看到提示再显式选择。
            "--ignore-lock" => {
                ignore_lock = true;
            }
            // v1.5.1 新增：开发者模式密钥
            //
            // 安全设计：这里**不做**任何校验，也不打印"密钥错误"。
            // 明文只是暂存到内存，交给 License 求哈希后比对。校验失败
            // 与"根本没传 --devkey"在外部表现上完全一致 —— 攻击者拿不到
            // 任何可用于爆破的反馈信号。
            "--devkey" if i + 1 < args.len() => {
                dev_key = Some(args[i + 1].clone());
                i += 1;
            }
            // v1.5.1 新增：显式确认已知晓开发者模式的风险（三重条件之一）
            "--i-know-the-risk" => {
                risk_acked = true;
            }
            // v1.5.1 新增：数据文件加密落盘
            "--encrypt-data" => {
                encrypt_data = true;
            }
            // v1.8.0 新增：授权服务地址与端口
            //
            // 设计：授权配置**必须显式给出**，不会默认指向任何地址。
            // 理由：默认指向一个不存在的服务 = 每次启动都等 3 秒超时，
            // 让"未启用授权的实例"也变慢。宁可让使用者多打一行参数。
            "--license-server" if i + 1 < args.len() => {
                aim_cfg.host = args[i + 1].clone();
                aim_cfg.enabled = !aim_cfg.host.is_empty();
                i += 1;
            }
            "--license-port" if i + 1 < args.len() => {
                match args[i + 1].parse::<u16>() {
                    Ok(p) => aim_cfg.port = p,
                    Err(_) => {
                        eprintln!("--license-port 需要端口号（1~65535），收到：{}", args[i + 1]);
                        std::process::exit(2);
                    }
                }
                i += 1;
            }
            "--license-psk" if i + 1 < args.len() => {
                aim_cfg.psk = args[i + 1].clone();
                i += 1;
            }
            // 无有效授权时**不拦截**业务（仅提示）—— 现场排障用。
            //
            // v1.9.1 加固：这个开关原本谁都能用（`strings` 已搜得到），
            // 等于给白嫖留的正门 —— 加个参数就免费。发行构建（release）
            // 现在必须同时给 `--aim-unlock-code`（由主密钥派生，只在
            // 构建机/管理员手里）。debug 构建保留开发豁免。
            "--aim-allow-unlicensed" => {
                if cfg!(debug_assertions) {
                    aim_enforce = false;
                } else {
                    unlock_requested = true;
                }
            }
            "--aim-unlock-code" if i + 1 < args.len() => {
                unlock_code_arg = Some(args[i + 1].clone());
                i += 1;
            }
            // v1.5.1 新增：打印密钥指纹（运维用它核对"装的是不是同一把"）
            "--devkey-fingerprint" if i + 1 < args.len() => {
                let key = &args[i + 1];
                println!(
                    "密钥指纹：{}（KDF_ROUNDS={}）",
                    crate::core::license::fingerprint(key),
                    crate::core::license::KDF_ROUNDS
                );
                println!("把上面的值填入 src/core/license.rs 的 LICENSE_FINGERPRINT 即可启用。");
                return;
            }
            // v1.8.0 新增：打印本机机器指纹（发给管理员做持久授权用）
            //
            // 这是唯一需要人工抄录指纹的入口：老师把这段指纹发给管理员，
            // 管理员在服务端用它预生成持久密钥。后续激活不再需要抄录。
            "--hwid" => {
                let info = crate::core::aim::hwid::collect();
                println!("机器指纹：{}", info.fingerprint());
                println!("短标识：  {}（界面展示用）", info.short_id());
                println!(
                    "采集状态：{}",
                    if info.degraded {
                        "降级（稳定硬件特征不足两项，指纹稳定性较差）"
                    } else {
                        "正常（主板/磁盘/CPU 三项齐备）"
                    }
                );
                if !info.warnings.is_empty() {
                    println!("采集提示：");
                    for w in &info.warnings {
                        println!("  - {}", w);
                    }
                }
                println!();
                println!("请把「机器指纹」提供给管理员，用于生成绑定本机的授权密钥。");
                return;
            }
            // 忽略 --config 及其值（已在上面处理）
            "--config" if i + 1 < args.len() => {
                i += 1;
            }
            other => {
                eprintln!(
                    "未知参数：{}\n\
                     用法：sports-meet [--config config.json] [--port 8765] [--dir data] [--web web]\n\
                     \x20              [--log-level DEBUG|INFO|WARN|ERROR] [--undo-keep 10]\n\
                     \x20              [--password 管理口令] [--encrypt-data] [--ignore-lock]\n\
                     \x20              [--license-server IP] [--license-port 8766] [--license-psk PSK]\n\
                     \x20              [--aim-allow-unlicensed]\n\
                     \x20     sports-meet --devkey <密钥> --i-know-the-risk   启用开发者模式解锁能力\n\
                     \x20     sports-meet --devkey-fingerprint <密钥>         计算并打印密钥指纹\n\
                     \x20     sports-meet --hwid                             打印本机机器指纹\n\
                     \x20     sports-meet --gen-config [文件名]               生成配置模板\n\
                     \x20     sports-meet --version",
                    other
                );
                std::process::exit(2);
            }
        }
        i += 1;
    }

    // --- v1.9.1：排障逃生门的解锁码校验（发行构建）---
    //
    // `--aim-allow-unlicensed` 单独出现时**不再生效**：必须配上由主密钥
    // 派生的解锁码。否则任何人都能用"加个参数"白嫖，而这比逆向二进制
    // 便宜太多。失败一律 exit(2)，不给"差几位"之类的反馈。
    if unlock_requested {
        let ok = unlock_code_arg
            .as_deref()
            .map(crate::core::aim::keyfmt::verify_unlock_code)
            .unwrap_or(false);
        if ok {
            aim_enforce = false;
            println!("  注意：已通过解锁码关闭授权强制（仅排障用，操作会记入审计）");
        } else {
            eprintln!("拒绝启动：--aim-allow-unlicensed 需要配套的 --aim-unlock-code <解锁码>。");
            eprintln!("  解锁码由构建机上的密钥主密钥派生，请联系软件管理员获取。");
            std::process::exit(2);
        }
    }

    // --- v1.6.1：数据目录独占锁 ---
    //
    // 必须在**读数据之前**拿到锁：否则"读入 → 另一进程覆盖 → 我们写回"
    // 这条丢数据链路已经成立了，再拿锁也来不及。
    let _dir_lock = match acquire_data_lock(&dir, ignore_lock) {
        Some(l) => l,
        None => std::process::exit(1),
    };
    // 记一条日志：出问题时（如后来发现数据顺序异常）能回溯
    // "当时是不是真的只有一个进程在写"。
    if _dir_lock.is_disabled() {
        log_warn!("main", "数据目录锁：已跳过（--ignore-lock）");
    } else {
        log_info!(
            "main",
            "数据目录锁：已持有（pid={} / {}）",
            _dir_lock.pid(),
            _dir_lock.path().display()
        );
    }

    // --- v1.5.1：密钥校验与开发者模式初始化 ---
    // 注意此处**不输出任何校验成功/失败的提示**，避免给爆破者反馈信道。
    let license = License::new(dev_key.as_deref(), risk_acked);
    // 明文密钥用完即弃（即使后面不再使用，也显式 drop 以缩短驻留时间）
    drop(dev_key);

    // 数据加密需要有密钥。这里**不急着**把 `encrypt_data` 置假——因为
    // `activate_vault` 会先自动探测磁盘上的密文：只要存在 `.smev`，
    // 就应当进入"尝试解密"流程，这样"忘记带 --encrypt-data"不会导致
    // 数据看起来凭空消失。真正的降级由 `enable_vault` 在无密钥时完成。
    let _ = &license;

    // --- v1.2：日志系统初始化（先于一切业务操作）---
    let level = LogLevel::parse(&log_level_str).unwrap_or_else(|| {
        eprintln!(
            "日志级别「{}」无法识别，已回退为 INFO（可选：DEBUG/INFO/WARN/ERROR）",
            log_level_str
        );
        LogLevel::Info
    });
    log::init(&dir, level);
    // --- v1.5：审计哈希链初始化（在数据目录就绪后、业务操作之前）---
    crate::core::audit::init(&dir);

    log_info!("main", "======== 同和中学校运会积分系统 {} 启动 ========", VERSION);
    log_info!(
        "main",
        "参数：port={} dir={} web={} log_level={} undo_keep={} 口令保护={}",
        port,
        dir.display(),
        web_dir.display(),
        level.tag(),
        undo_keep,
        if password.is_empty() { "未启用" } else { "已启用" }
    );

    let mut core = Core::new(&dir, &web_dir);
    core.undo_keep = undo_keep;
    // v1.4：空口令视为未启用（向后兼容，行为与 v1.3 一致）
    core.password = if password.is_empty() { None } else { Some(password) };
    // v1.5.1：密钥机制与数据加密开关
    core.license = Some(Box::new(license));
    core.encrypt_data = encrypt_data;
    // v1.8.0：服务端授权 —— 构造管理器（采集指纹 + 载入缓存）并做首次判定。
    //
    // 顺序要点：**在 Core 构造之后、服务启动之前**完成判定。
    // 这样第一个业务请求进来时，门禁已有一份确定的结论，
    // 不需要在请求路径上发网络请求（否则断网时每请求等 3 秒）。
    //
    // v1.9.0：管理器**无条件创建**（v1.8.0 的"磁盘有许可文件才建"留下
    // 一个致命缺口：全新安装时三者皆空 → 管理器为 None → 门禁恒放行、
    // 激活接口报"未启用授权管理"——未授权用户永远进不了激活流程，
    // 整个授权制被一台干净安装绕开）。48 位密钥与离线许可的验签能力
    // 已编入二进制，授权判定就该常在；`decide()` 在无任何授权物时走
    // 离线判定返回 Denied，与 `aim_enforce`（默认 true）配合即
    // "放行自助接口 + 静态页，拦截其余业务"。
    //
    // 显式逃生门仍是 `--aim-allow-unlicensed`（只关强制，不停判定）；
    // 老用户若确需 v1.7.0 的完全开放行为，用它并知晓其在审计中的记录。
    let mut mgr = crate::core::aim::AuthManager::new(aim_cfg, &dir);
    let decision = mgr.decide();
    log_info!(
        "main",
        "授权判定：{} / {} / 指纹 {}… / {}",
        decision.state.as_str(),
        decision.kind.as_str(),
        decision.hwid_short,
        decision.message
    );
    core.aim = Some(std::sync::Mutex::new(mgr));
    core.aim_enforce = aim_enforce;
    // 密钥就绪后再武装保险库（先有密钥、才谈得上解密）。
    // 此调用还可能**自动探测**到磁盘上的密文而主动进入加密模式。
    core.activate_vault(&dir);
    let core = Arc::new(core);

    // 注册扩展：扩展的初始化与路由/事件挂接都在这里完成
    let exts = extensions::load_extensions(core.data_dir());
    for e in &exts {
        core.register_extension(Arc::clone(e));
    }
    // v1.2：注册完成后统一初始化（便于健康状态统计与失败隔离）
    core.init_extensions();
    core.publish_info("core_started");

    let addr = format!("127.0.0.1:{}", port);
    let router = Arc::new(Router::new(Arc::clone(&core)));

    println!("同和中学校运会积分系统（Rust 版）{}", VERSION);
    println!("核心已加载，注册扩展：");
    for e in core.extensions.lock_recover().iter() {
        println!("  - {}：{}", e.name(), e.description());
    }
    println!("服务地址：http://{}", addr);
    println!("日志级别：{}（日志目录：{}）", level.tag(), dir.join("logs").display());
    println!("审计目录：{}", dir.join("audit").display());

    // --- v1.5.1：密钥与安全态横幅 ---
    if let Some(lic) = core.license.as_ref() {
        if lic.can_unlock() {
            // 用红色 ANSI 直白提示：这是**已削弱安全边界**的运行实例
            println!(
                "\x1b[31m[开发者模式可用] 密钥校验通过，已具备解锁能力（需在诊断页签手动解锁）。\x1b[0m"
            );
            println!("\x1b[31m  注意：解锁后将跳过危险操作二次确认，所有动作写入审计（actor=devmode）。\x1b[0m");
            println!("\x1b[31m  请勿在面向学生的生产环境中解锁。\x1b[0m");
        } else if license_hint_needed(risk_acked) {
            println!("[密钥机制] 未启用开发者模式（未提供有效密钥或未确认风险）。");
        }
        // v1.5.1：如实报告加密状态 —— 区分"已武装"与"探测到密文但缺密钥"。
        //
        // 指纹前缀只在**本次确实有一把可用密钥**时才打印。
        // 早先的写法无条件打印 `LICENSE_FINGERPRINT[..4]`，有两个毛病：
        //   1) 没提供密钥时也打印一个前缀，看着像"密钥已生效"，实际是误导；
        //   2) 打印的是**编译期内置的演示密钥**指纹，而不是使用者真正传入
        //      的那把密钥的指纹 —— 拿它去核对密钥会得到错误结论。
        // 现在改为：有种子就打印本实例种子的真实指纹，没有就整段省略。
        let vault_state = if core.store.vault_enabled {
            "已启用（.smev）"
        } else if core.store.vault_detected {
            "检测到密文但缺少密钥（请用 --devkey 提供正确密钥）"
        } else {
            "未启用（明文）"
        };
        match core.store.seed.as_deref() {
            Some(seed) => println!(
                "数据加密：{}（本实例密钥指纹前缀 {}）",
                vault_state,
                crate::core::vault::seed_fingerprint(seed).get(..4).unwrap_or("????")
            ),
            None => println!("数据加密：{}", vault_state),
        }

        // --- v1.8.0：服务端授权状态横幅 ---
        if let Some(m) = core.aim.as_ref() {
            let d = m.lock_recover().last_decision().clone();
            if d.state.is_granted() {
                println!(
                    "授权状态：{}（{}，{}）",
                    d.state.as_str(),
                    d.kind.label(),
                    if d.offline { "离线缓存" } else { "在线校验" }
                );
                println!("  {}", d.message);
            } else {
                // 未授权：如实报告 + 给出可执行的恢复步骤
                println!(
                    "\x1b[33m授权状态：{}（临时密钥不可用）\x1b[0m",
                    d.state.as_str()
                );
                println!("  {}", d.message);
                println!("  机器指纹（发给管理员）：{}…", d.hwid_short);
                println!(
                    "  恢复方式：浏览器打开 http://127.0.0.1:{} → 「授权」页 → 粘贴密钥激活",
                    port
                );
                if !core.aim_enforce {
                    println!("  注意：当前为 --aim-allow-unlicensed，业务接口未被拦截（仅排障用）");
                }
            }
        }
    }

    log_info!("main", "HTTP 服务监听 {}", addr);
    if let Err(e) = serve(&addr, router) {
        log_error!("main", "启动失败：{}（端口被占用可换 --port）", e);
        eprintln!("启动失败：{}（端口被占用可换 --port）", e);
        std::process::exit(1);
    }
}

/// 是否值得打印一句"未启用"的提示。
///
/// 只在两种情况下提示，避免"没传 --devkey 也报一句"制造噪音：
/// * 传了 `--i-know-the-risk`（说明使用者**本想**启用，只是密钥不对/漏传）
/// * 传了 `--encrypt-data`（同上，需要密钥才能生效）
///
/// 关键：**不区分**"密钥错误"与"没传密钥" —— 这是刻意的，
/// 任何区分都会成为爆破者的反馈信道。
fn license_hint_needed(risk_acked: bool) -> bool {
    risk_acked
}

/// v1.6.1：获取数据目录独占锁。
///
/// 返回 `Some(lock)` 表示可以继续启动（锁会随返回值存活，
/// 进程退出时由 `Drop` 自动释放）；返回 `None` 表示应终止启动，
/// 本函数已打印原因。
///
/// 为什么放在 `main` 里而不是 `Store`：锁的生命周期必须覆盖
/// "读数据 → 跑服务 → 写数据"全程，绑定在 `Store` 上会随 `Core`
/// 的移动/重建而意外释放。用一个 `let _dir_lock` 绑在 `main` 栈上，
/// 语义最直白：**只要进程活着，锁就在**。
fn acquire_data_lock(dir: &PathBuf, ignore: bool) -> Option<core::dirlock::DirLock> {
    // 逃生开关：显式跳过
    if ignore {
        eprintln!("⚠️  已按 --ignore-lock 跳过数据目录锁：若同时有另一个进程在写，可能丢失数据。");
        crate::log_warn!("main", "按 --ignore-lock 跳过了数据目录锁");
        return Some(core::dirlock::DirLock::disabled());
    }

    // 目录可能还不存在（首次运行）→ 先建出来，否则锁文件无从落脚
    if !dir.exists() {
        if let Err(e) = std::fs::create_dir_all(dir) {
            eprintln!("无法创建数据目录 {}：{}", dir.display(), e);
            return None;
        }
    }

    match core::dirlock::DirLock::acquire(dir) {
        core::dirlock::LockOutcome::Acquired(l) => Some(l),
        core::dirlock::LockOutcome::Busy { pid, since, path } => {
            // 分两种情形给不同提示：真被占用 vs 环境问题（pid = 0）
            if pid == 0 {
                eprintln!("启动失败：{}", since);
                eprintln!("请检查数据目录 {} 是否可写。", dir.display());
            } else {
                eprintln!("启动失败：数据目录已被另一个进程占用。");
                eprintln!("  占用进程 PID：{}", pid);
                if !since.is_empty() {
                    eprintln!("  启动时间：{}", since);
                }
                eprintln!("  锁文件：{}", path.display());
                eprintln!();
                eprintln!("同一份数据被两个进程同时写入会**静默丢失数据**，因此默认拒绝启动。");
                eprintln!("若确认另一个进程已停止，可加 --ignore-lock 跳过检查后重试。");
            }
            crate::log_error!(
                "main",
                "数据目录锁获取失败：dir={} pid={} since={}",
                dir.display(),
                pid,
                since
            );
            None
        }
    }
}
