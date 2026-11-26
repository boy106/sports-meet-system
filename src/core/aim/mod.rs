// 授权模块对外暴露的是一整套**能力契约**（试用查询、反调试重扫、记录清理、
// 策略读取……），由 lib 使用者、集成测试与 API 层按需取用；二进制目标
// （main.rs）只用到其中一部分。故在模块级统一放行未使用项 —— 否则每加一个
// 对外能力都要单独标注，噪音会淹没真实问题。与 server_pkg/src/main.rs 同一姿势。
#![allow(dead_code)]

//! 授权模块（v1.8.0 新增）：机器指纹 + 加密信道 + 服务端授权 + 离线降级。
//!
//! # 模块分层
//!
//! ```text
//!   hwid      → 无依赖（仅 std + 平台命令）     机器指纹采集与哈希
//!   channel   → 无依赖（仅 std）                加密信道、防重放、base64
//!   client    → hwid / channel / json / log    授权管理器、本地缓存、离线判定
//!   obf       → 无依赖（仅 std）                混淆与反调试（v1.8.1）
//!   asym      → 无依赖（SHA-512 + Ed25519）     非对称离线许可（v1.9.0 手段 1）
//!   keyfmt    → asym                            48 位混合字符密钥（v1.9.0）
//!   usage     → keyfmt                          使用次数/时长配额计量（v1.9.0）
//!   integrity → asym                            二进制完整性自校验（v1.9.0 手段 2）
//!   trial     → 无依赖                          内置试用 + 分散冗余记录（v1.8.2）
//!   mod       → 以上全部                        统一出入口 + 诊断 JSON
//! ```
//!
//! 新模块**均不依赖任何其他核心模块**（除 client 用 json 与 log），
//! 因此可被 `api` / `http` / `main` 任意引用而不引入依赖环 ——
//! 与 `license` 模块保持同一姿势（见 `core/mod.rs` 的分层说明）。
//!
//! # v1.9.0 防白嫖三手段（对应 docs/13 第七节）
//!
//! | 手段 | 模块 | 做法 |
//! |---|---|---|
//! | 1 非对称离线许可 | `asym` | Ed25519 私钥签发 / 公钥验证 / 不联网，伪造不了 |
//! | 2 完整性自校验 | `integrity` | 改二进制即段哈希不符，分散 + 交叉校验 |
//! | 3 校验与业务交织 | `client`/`api`/`http` | 无独立 `check()` 可 patch，多处内联 |
//!
//! 48 位混合字符密钥（`keyfmt`）是**便携激活码**形态：数字/字母/符号/汉字
//! 交替共 48 位，内含加密的有效时间、使用时间、使用次数、功能限制。
//! 它与 `asym` 的许可文件在 `client` 中并存，文件许可优先级更高
//! （详见 `keyfmt` 模块顶部的诚实声明）。
//!
//! # 与既有 `license` 模块的关系（重要，别混淆）
//!
//! | 模块 | 用途 | 密钥来源 | 判定方 | 默认状态 |
//! |---|---|---|---|---|
//! | `license`（v1.5.1） | **开发者模式**解锁 | 编译期常量指纹 | 本机（三重条件） | 关闭 |
//! | `aim`（v1.8.0，本模块） | **正式授权**准入 | 服务端签发 | **服务端** | 关闭 |
//!
//! 两者**互不影响**：`license` 管"调试便利"，`aim` 管"商业授权"。
//! 一个实例可以只启用 `aim`（生产，防白嫖），也可以只用 `license`
//! （纯内部，无授权需求）。**关闭 `aim` 时行为与 v1.7.0 完全一致**。
//!
//! # 防白嫖说明（诚实版）
//!
//! 本模块能做到的：
//! * 授权票据由**服务端私钥签名**，客户端只有公钥 → 无法自行签发；
//! * 票据**绑定机器指纹** → 拷给别的机器无效；
//! * 服务端维护**吊销列表** → 泄露的密钥可即时作废；
//! * 离线缓存**有时效** → 不能靠"激活一次后永久断网"白用；
//! * 传输**加密 + 防重放** → 抓包拿不到可用凭证。
//!
//! 做不到的（**不承诺**）：
//! * 挡不住能反编译并修改二进制、直接跳过校验的技术对手；
//! * 挡不住物理接触机器并克隆磁盘指纹的对手；
//! * 挡不住把整个有效环境（含缓存）打包复制 —— 除非叠加硬件绑定
//!   （本项目未采用 TPM）。
//!
//! 结论：**这是"让白嫖变得麻烦且可追溯"的方案，不是"无法破解"的方案。**
//! 与 docs/12 的既有立场一致。

pub mod asym;
pub mod channel;
pub mod client;
pub mod hwid;
pub mod integrity;
pub mod keyfmt;
pub mod obf;
pub mod trial;
pub mod usage;

/// 开源版开关。
///
/// 自己 `cargo build --release` 出来的二进制没有完整性盖章，属于「基线模式」。
/// 发行版把这种情况判为「不可信」并要求盖章；开源版必须关掉这条判定，
/// 否则贡献者编译后所有业务接口都会被 403。
///
/// 如需恢复发行版的盖章校验，把它改成 `false` 并按 docs/12 的流程盖章。
pub const OPEN_SOURCE: bool = true;

use crate::core::json::Json;

// 这些类型是 aim 模块的**对外契约**，由 api.rs / main.rs 按需取用，
// 当前 main 只用到其中一部分，故允许未被引用者存在。
#[allow(unused_imports)]
pub use client::{
    AuthConfig, AuthDecision, AuthManager, AuthState, CachedLicense, LicenseCache,
    LicenseKind,
};

/// 授权状态摘要（供 `/api/aim/status` 与启动横幅使用）。
///
/// **脱敏原则**：本函数产出的 JSON **绝不含**密钥明文、票据原文、
/// PSK、或机器指纹全文 —— 只给"开关状态 + 指纹前缀 + 到期时间"，
/// 与 `license::status_json_fields` 的既有做法保持一致。
pub fn status_json(mgr: Option<&AuthManager>) -> Json {
    let mut o = Json::obj();
    match mgr {
        None => {
            o.set("enabled", Json::Bool(false));
            o.set("state", Json::s(AuthState::NotConfigured.as_str()));
            o.set("message", Json::s("未启用服务端授权校验（v1.7.0 行为）"));
        }
        Some(m) => {
            let d = m.last_decision();
            o.set("enabled", Json::Bool(m.configured()));
            o.set("state", Json::s(d.state.as_str()));
            o.set("offline", Json::Bool(d.offline));
            o.set("kind", Json::s(d.kind.as_str()));
            o.set("kind_label", Json::s(d.kind.label()));
            o.set("expire_at", Json::Int(d.expire_at));
            o.set("days_left", Json::Int(d.days_left));
            o.set("message", Json::s(d.message.clone()));
            // 只给指纹前 8 位（运维核对"是哪台机器"，不足以反推硬件特征）
            o.set("hwid_short", Json::s(m.hwid_info().short_id()));
            o.set("degraded", Json::Bool(m.hwid_info().degraded));
            o.set(
                "hwid_warnings",
                Json::arr(
                    m.hwid_info()
                        .warnings
                        .iter()
                        .map(|w| Json::s(w.clone())),
                ),
            );
            // —— 试用状态（v1.8.2）——
            // 只展示"是否可用 / 剩余时间"，不暴露记录位置（那是混淆资产）。
            let ts = m.trial_status();
            let ts_name = match ts {
                trial::TrialState::Active(_) => "active",
                trial::TrialState::Expired => "expired",
                trial::TrialState::Consumed => "consumed",
                trial::TrialState::NeverUsed => "never_used",
                trial::TrialState::Disabled => "disabled",
            };
            o.set("trial_state", Json::s(ts_name));
            o.set("trial_message", Json::s(ts.message()));
            o.set("trial_granted", Json::Bool(ts.is_granted()));
            if let trial::TrialState::Active(secs) = ts {
                o.set("trial_seconds_left", Json::Int(secs));
            }

            // —— 48 位激活密钥（v1.9.0）——
            // 只给"类型/到期/余量/功能"等展示字段；密钥原文、主密钥、
            // 计量文件内容一律不外泄（脱敏原则同 hwid_short）。
            if let Some(kj) = m.key_fields() {
                o.set("key", kj);
            }

            // —— 完整性自校验（v1.9.0 手段 2）——
            // 只给结论与摘要（"哪几段不符"可外传，不含任何密钥信息）。
            let (iok, ibase, isum) = integrity::status_json_fields();
            let mut ij = Json::obj();
            ij.set("ok", Json::Bool(iok));
            ij.set("baseline", Json::Bool(ibase));
            ij.set("summary", Json::s(isum));
            o.set("integrity", ij);

            // **统一放行位**：正式授权 或 试用进行中，任一成立即放行。
            //
            // 为什么不能只写 `d.state.is_granted()`：`d` 是**授权判定**的结果，
            // 试用激活不重跑授权判定；若只看 `d`，会出现"试用中但 granted=false"
            // 的自相矛盾（前端无法判断到底能不能用）。
            let allowed = d.state.is_granted() || ts.is_granted();
            o.set("granted", Json::Bool(allowed));
            // 保留授权判定自身的结论，供诊断区分"是哪一种放行"
            o.set("license_granted", Json::Bool(d.state.is_granted()));

            // —— 环境检测（反调试）——
            // 只给"等级 + 命中信号名"，不含任何密钥信息，可安全外传。
            let t = m.threat();
            o.set("threat_level", Json::s(t.level.as_str()));
            o.set("threat_score", Json::Int(t.score as i64));
            o.set(
                "threat_signals",
                Json::arr(t.signals.iter().map(|s| Json::s(s.to_string()))),
            );
        }
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn tmp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sm-aim-mod-{}-{}-{}",
            tag,
            std::process::id(),
            channel::now_millis()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn status_json_without_manager() {
        let j = status_json(None);
        assert_eq!(j.get_bool("enabled"), Some(false));
        assert_eq!(j.get_str("state"), Some("not_configured"));
    }

    #[test]
    fn status_json_never_leaks_secrets() {
        let dir = tmp_dir("leak");
        let cfg = AuthConfig {
            host: "10.0.0.1".into(),
            port: 8766,
            psk: "SUPER-SECRET-PSK-VALUE".into(),
            enabled: true,
        };
        let mgr = AuthManager::new(cfg, &dir);
        let text = status_json(Some(&mgr)).to_string();
        assert!(!text.contains("SUPER-SECRET-PSK-VALUE"), "PSK 不得泄漏");
        // 完整机器指纹（16 位）不得出现在状态里，只给前 8 位
        assert!(!text.contains(mgr.hwid()), "完整指纹不得泄漏");
        assert!(text.contains(&mgr.hwid_info().short_id()));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn status_json_reports_degraded_flag() {
        let dir = tmp_dir("degraded");
        let mgr = AuthManager::new(AuthConfig::default(), &dir);
        let j = status_json(Some(&mgr));
        // degraded 字段必须存在且为布尔（避免前端真值判断踩坑）
        assert!(matches!(j.get("degraded"), Some(Json::Bool(_))));
        std::fs::remove_dir_all(&dir).ok();
    }
}
