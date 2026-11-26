//! 密钥使用配额计量（v1.9.0 新增）：使用次数 + 累计使用时长。
//!
//! # 为什么需要它
//!
//! 48 位密钥里带「使用次数上限」与「累计使用时长上限」
//! （见 `keyfmt.rs` 的明文布局）。限额是**签在密钥里的**，
//! 但"已经用了多少"只能在本机计量 —— 这就是本模块的职责。
//!
//! # 防重置设计（以及它的边界）
//!
//! 攻击者最直接的作弊是**删掉计量文件**让计数归零。缓解：
//!
//! 1. **多副本冗余**：同一份计量写 3 个文件（文件名由指纹派生，
//!    不叫 `.usage` 这种一眼能被猜中的名字）；读取时取**各副本的最大值** ——
//!    删一个文件不会让计数倒退；
//! 2. **诱饵文件**：另写 6 个随机内容文件，让"批量删 .sm_*"这类
//!    清理动作连带删掉诱饵（无实质损失，但增加分析成本）；
//! 3. **内容加密 + 绑定指纹**：换机器拿过来的计量文件解不开。
//!
//! # 诚实声明
//!
//! 纯客户端计量**不可能**做到"删了就还能记住"：有能力定位并删光
//! 三个副本的对手，照样能重置。它的真实作用是**挡住顺手清理**
//! （删目录、清数据、重置软件）这类低成本作弊，并把精细化作弊的
//! 成本抬到"不如去要一个试用密钥"。与 `trial.rs` 的分散冗余记录
//! 同一立场，与 `docs/13` 第七节一致。

#![allow(dead_code)]

use std::path::{Path, PathBuf};

use crate::core::aim::asym::sha512;
use crate::core::aim::keyfmt;

/// 计量文件魔数。
const MAGIC: &[u8; 4] = b"SMU1";
/// 计量文件版本。
const VERSION: u8 = 1;
/// 真实副本数（取 max 防重置）。
const COPIES: usize = 3;
/// 诱饵文件数。
const DECOYS: usize = 6;
/// 单次 tick 允许累加的最大秒数（防止改了系统时钟后一次暴涨）。
const MAX_TICK_SECS: i64 = 3600;

/// 计量状态。
#[derive(Debug, Clone, Default)]
pub struct UsageState {
    /// 累计启动次数（每次成功激活后的启动计 1 次）。
    pub launches: u32,
    /// 累计使用秒数。
    pub seconds: u64,
    /// 首次计量时间（Unix 秒）。
    pub first_seen: i64,
    /// 最近一次计量时间（Unix 秒）。
    pub last_seen: i64,
}

impl UsageState {
    /// 合并两个状态（取各项最大值，用于多副本冗余）。
    fn merge(&mut self, other: &UsageState) {
        self.launches = self.launches.max(other.launches);
        self.seconds = self.seconds.max(other.seconds);
        self.first_seen = if self.first_seen == 0 {
            other.first_seen
        } else {
            self.first_seen.min(other.first_seen)
        };
        self.last_seen = self.last_seen.max(other.last_seen);
    }
}

/// 配额检查结论。
#[derive(Debug, Clone)]
pub enum QuotaVerdict {
    /// 未超限（附剩余量描述）。
    Ok {
        launches_left: Option<u32>,
        seconds_left: Option<u64>,
    },
    /// 次数已用尽。
    LaunchesExhausted { used: u32, limit: u16 },
    /// 时长已用尽。
    SecondsExhausted { used: u64, limit: u32 },
}

/// 使用配额计量器（每个数据目录一份）。
pub struct UsageTracker {
    /// 真实副本路径。
    paths: Vec<PathBuf>,
    /// 诱饵文件路径。
    decoy_paths: Vec<PathBuf>,
    /// 计量文件加密密钥（主密钥 + 指纹派生）。
    key: Option<[u8; 32]>,
    hwid: String,
}

impl UsageTracker {
    /// 构造计量器。`secret` 为 `None` 时计量整体停用（返回不限量结论）。
    pub fn new(hwid: &str, data_dir: &Path, secret: Option<&[u8; 32]>) -> UsageTracker {
        let h48 = keyfmt::hwid48(hwid);
        // 文件名由指纹派生：既稳定（重启后还找得到）又不可猜（换台机器名字不同）
        let stem = format!("{:02x}{:02x}{:02x}", h48[0], h48[1], h48[2]);
        let mut paths = Vec::with_capacity(COPIES);
        for i in 0..COPIES {
            paths.push(data_dir.join(format!(".sm{}{}", stem, (b'a' + i as u8) as char)));
        }
        let mut decoy_paths = Vec::with_capacity(DECOYS);
        for i in 0..DECOYS {
            let h = sha512(&{
                let mut v = Vec::with_capacity(6 + 1);
                v.extend_from_slice(&h48);
                v.push(i as u8);
                v
            });
            decoy_paths.push(data_dir.join(format!(
                ".sm{:02x}{:02x}{:02x}",
                h[32], h[33], h[34]
            )));
        }
        let key = secret.map(|s| {
            let mut input = Vec::with_capacity(6 + 32 + 6);
            input.extend_from_slice(b"SM1USG");
            input.extend_from_slice(s);
            input.extend_from_slice(&h48);
            let h = sha512(&input);
            let mut k = [0u8; 32];
            k.copy_from_slice(&h[..32]);
            k
        });
        UsageTracker {
            paths,
            decoy_paths,
            key,
            hwid: hwid.to_string(),
        }
    }

    /// 是否启用（主密钥存在）。
    pub fn enabled(&self) -> bool {
        self.key.is_some()
    }

    /// 读全部副本并合并（取最大值）。无任何副本 → 零状态。
    pub fn load(&self) -> UsageState {
        let Some(key) = &self.key else {
            return UsageState::default();
        };
        let mut st = UsageState::default();
        for p in &self.paths {
            if let Some(s) = read_state(p, key, &self.hwid) {
                st.merge(&s);
            }
        }
        st
    }

    /// 写入全部副本（含首次创建诱饵）。
    fn save(&self, st: &UsageState) {
        let Some(key) = &self.key else { return };
        for p in &self.paths {
            let _ = write_state(p, st, key, &self.hwid);
        }
        self.sow_decoys();
    }

    /// 播种诱饵文件（只写一次，不覆盖）。
    fn sow_decoys(&self) {
        for (i, p) in self.decoy_paths.iter().enumerate() {
            if p.exists() {
                continue;
            }
            let h = sha512(&{
                let mut v = Vec::with_capacity(8);
                v.extend_from_slice(b"decoy");
                v.push(i as u8);
                v.extend_from_slice(self.hwid.as_bytes());
                v
            });
            let mut blob = Vec::with_capacity(47);
            blob.extend_from_slice(b"SMU0"); // 错魔数：真文件是 SMU1
            blob.extend_from_slice(&h[..43]);
            let _ = std::fs::write(p, &blob);
        }
    }

    /// 记录一次启动（次数 +1）。返回合并后的最新状态。
    pub fn record_launch(&self, now: i64) -> UsageState {
        let Some(_) = self.key else {
            return UsageState::default();
        };
        let mut st = self.load();
        st.launches = st.launches.saturating_add(1);
        if st.first_seen == 0 {
            st.first_seen = now;
        }
        st.last_seen = now;
        self.save(&st);
        st
    }

    /// 累计使用时长（惰性心跳：由状态查询/业务请求驱动，无需后台线程）。
    ///
    /// 单次最多累加 [`MAX_TICK_SECS`] —— 既覆盖"程序开着但页面没刷新的
    /// 空闲时间"，也防止改动系统时钟造成的暴涨。
    pub fn tick(&self, now: i64) -> UsageState {
        let Some(_) = self.key else {
            return UsageState::default();
        };
        let mut st = self.load();
        if st.last_seen > 0 && now > st.last_seen {
            let delta = (now - st.last_seen).min(MAX_TICK_SECS).max(0) as u64;
            st.seconds = st.seconds.saturating_add(delta);
        }
        st.last_seen = now;
        if st.first_seen == 0 {
            st.first_seen = now;
        }
        self.save(&st);
        st
    }

    /// 检查配额是否还够用。
    pub fn check(&self, lic: &keyfmt::KeyLicense, now: i64) -> QuotaVerdict {
        if self.key.is_none() {
            // 计量未启用 → 不因计量问题拦截（密钥本身的有效期仍由 keyfmt 管）
            return QuotaVerdict::Ok {
                launches_left: None,
                seconds_left: None,
            };
        }
        let st = self.tick(now);
        if lic.usage_count_limit > 0 && st.launches >= lic.usage_count_limit as u32 {
            return QuotaVerdict::LaunchesExhausted {
                used: st.launches,
                limit: lic.usage_count_limit,
            };
        }
        if lic.usage_seconds_limit > 0 && st.seconds >= lic.usage_seconds_limit as u64 {
            return QuotaVerdict::SecondsExhausted {
                used: st.seconds,
                limit: lic.usage_seconds_limit,
            };
        }
        QuotaVerdict::Ok {
            launches_left: if lic.usage_count_limit > 0 {
                Some(lic.usage_count_limit as u32 - st.launches)
            } else {
                None
            },
            seconds_left: if lic.usage_seconds_limit > 0 {
                Some(lic.usage_seconds_limit as u64 - st.seconds)
            } else {
                None
            },
        }
    }

    /// 当前已用量（只读，不写盘）。
    pub fn usage_snapshot(&self, now: i64) -> UsageState {
        let mut st = self.load();
        if st.last_seen > 0 && now > st.last_seen {
            let delta = (now - st.last_seen).min(MAX_TICK_SECS).max(0) as u64;
            st.seconds = st.seconds.saturating_add(delta);
        }
        st
    }

    /// 清除全部计量文件（停用授权时调用；诱饵一并清掉）。
    pub fn clear_all(&self) {
        for p in self.paths.iter().chain(self.decoy_paths.iter()) {
            let _ = std::fs::remove_file(p);
        }
    }
}

// ---------------------------------------------------------------------------
// 计量文件编解码
// ---------------------------------------------------------------------------

/// 文件布局：`MAGIC(4) ‖ VER(1) ‖ 指纹摘要(6) ‖ 密文(28) ‖ MAC(8)` = 47 字节。
const FILE_LEN: usize = 4 + 1 + 6 + 28 + 8;
const PLAIN_LEN: usize = 28;

fn usage_keystream(key: &[u8; 32], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 64);
    let mut counter: u64 = 0;
    while out.len() < len {
        let mut block = Vec::with_capacity(35);
        block.extend_from_slice(key);
        block.extend_from_slice(b"UK");
        block.extend_from_slice(&counter.to_be_bytes());
        out.extend_from_slice(&sha512(&block));
        counter += 1;
    }
    out.truncate(len);
    out
}

fn pack_plain(st: &UsageState) -> [u8; PLAIN_LEN] {
    let mut b = [0u8; PLAIN_LEN];
    b[0..4].copy_from_slice(&st.launches.to_be_bytes());
    b[4..12].copy_from_slice(&st.seconds.to_be_bytes());
    b[12..20].copy_from_slice(&st.first_seen.to_be_bytes());
    b[20..28].copy_from_slice(&st.last_seen.to_be_bytes());
    b
}

fn unpack_plain(b: &[u8; PLAIN_LEN]) -> UsageState {
    UsageState {
        launches: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        seconds: u64::from_be_bytes([b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11]]),
        first_seen: i64::from_be_bytes([
            b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19],
        ]),
        last_seen: i64::from_be_bytes([
            b[20], b[21], b[22], b[23], b[24], b[25], b[26], b[27],
        ]),
    }
}

fn write_state(path: &Path, st: &UsageState, key: &[u8; 32], hwid: &str) -> std::io::Result<()> {
    let ks = usage_keystream(key, PLAIN_LEN);
    let plain = pack_plain(st);
    let mut cipher = [0u8; PLAIN_LEN];
    for i in 0..PLAIN_LEN {
        cipher[i] = plain[i] ^ ks[i];
    }
    let h48 = keyfmt::hwid48(hwid);
    let mut mac_input = Vec::with_capacity(6 + 4 + PLAIN_LEN + 6);
    mac_input.extend_from_slice(b"SM1USG");
    mac_input.extend_from_slice(&h48);
    mac_input.extend_from_slice(&cipher);
    let m = sha512(&mac_input);

    let mut blob = [0u8; FILE_LEN];
    blob[0..4].copy_from_slice(MAGIC);
    blob[4] = VERSION;
    blob[5..11].copy_from_slice(&h48);
    blob[11..11 + PLAIN_LEN].copy_from_slice(&cipher);
    blob[11 + PLAIN_LEN..].copy_from_slice(&m[..8]);

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &blob)?;
    std::fs::rename(&tmp, path)
}

fn read_state(path: &Path, key: &[u8; 32], hwid: &str) -> Option<UsageState> {
    let blob = std::fs::read(path).ok()?;
    if blob.len() != FILE_LEN || &blob[0..4] != MAGIC || blob[4] != VERSION {
        return None;
    }
    let h48 = keyfmt::hwid48(hwid);
    if blob[5..11] != h48 {
        return None; // 异机文件
    }
    let cipher = &blob[11..11 + PLAIN_LEN];
    let mut mac_input = Vec::with_capacity(6 + 4 + PLAIN_LEN + 6);
    mac_input.extend_from_slice(b"SM1USG");
    mac_input.extend_from_slice(&h48);
    mac_input.extend_from_slice(cipher);
    let m = sha512(&mac_input);
    if blob[11 + PLAIN_LEN..] != m[..8] {
        return None; // 篡改
    }
    let ks = usage_keystream(key, PLAIN_LEN);
    let mut plain = [0u8; PLAIN_LEN];
    for i in 0..PLAIN_LEN {
        plain[i] = cipher[i] ^ ks[i];
    }
    Some(unpack_plain(&plain))
}

// ---------------------------------------------------------------------------
// 测试
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::aim::keyfmt::{KeyKind, DAY_PERPETUAL, FEAT_ALL};

    const SECRET: [u8; 32] = [7u8; 32];
    const HW: &str = "usage-test-hwid";

    fn tmp(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "sm-usage-{}-{}-{}",
            tag,
            std::process::id(),
            crate::core::aim::channel::now_millis()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn lic(count: u16, secs: u32) -> keyfmt::KeyLicense {
        // 直接构造（跳过签发/验签，只测计量逻辑）
        keyfmt::KeyLicense {
            kind: KeyKind::Pro,
            valid_from_day: 0,
            valid_until_day: DAY_PERPETUAL,
            usage_seconds_limit: secs,
            usage_count_limit: count,
            feature_flags: FEAT_ALL,
            key_id: 1,
        }
    }

    #[test]
    fn disabled_without_secret() {
        let dir = tmp("disabled");
        let t = UsageTracker::new(HW, &dir, None);
        assert!(!t.enabled());
        // 未启用 → 不拦截
        let v = t.check(&lic(1, 1), 1_700_000_000);
        assert!(matches!(v, QuotaVerdict::Ok { .. }));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn launch_counting_and_limit() {
        let dir = tmp("launch");
        let t = UsageTracker::new(HW, &dir, Some(&SECRET));
        let now = 1_700_000_000i64;
        assert!(matches!(t.check(&lic(3, 0), now), QuotaVerdict::Ok { .. }));
        t.record_launch(now);
        t.record_launch(now);
        assert!(matches!(t.check(&lic(3, 0), now), QuotaVerdict::Ok { .. }));
        t.record_launch(now);
        // 第 3 次后达到上限
        match t.check(&lic(3, 0), now) {
            QuotaVerdict::LaunchesExhausted { used, limit } => {
                assert_eq!(used, 3);
                assert_eq!(limit, 3);
            }
            _ => panic!("应判定次数用尽"),
        }
        // 不限次数时永不耗尽
        assert!(matches!(t.check(&lic(0, 0), now), QuotaVerdict::Ok { .. }));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn seconds_limit() {
        let dir = tmp("secs");
        let t = UsageTracker::new(HW, &dir, Some(&SECRET));
        let now = 1_700_000_000i64;
        t.record_launch(now);
        // 过 1000 秒再 tick
        t.tick(now + 1000);
        match t.check(&lic(0, 3600), now + 1000) {
            QuotaVerdict::Ok { seconds_left, .. } => {
                assert_eq!(seconds_left, Some(3600 - 1000));
            }
            _ => panic!("应仍有余量"),
        }
        // 超过上限
        t.tick(now + 1000 + 4000);
        match t.check(&lic(0, 3600), now + 5000) {
            QuotaVerdict::SecondsExhausted { .. } => {}
            _ => panic!("应判定时长用尽"),
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn deleting_one_copy_does_not_reset() {
        let dir = tmp("redundant");
        let t = UsageTracker::new(HW, &dir, Some(&SECRET));
        let now = 1_700_000_000i64;
        t.record_launch(now);
        t.record_launch(now);
        // 删掉两个副本，只剩一个
        std::fs::remove_file(&t.paths[0]).ok();
        std::fs::remove_file(&t.paths[1]).ok();
        let st = t.load();
        assert_eq!(st.launches, 2, "删副本不应让计数倒退（取 max）");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn state_file_is_bound_to_machine() {
        let dir = tmp("bound");
        let t = UsageTracker::new(HW, &dir, Some(&SECRET));
        t.record_launch(1_700_000_000);
        // 换机器构造 tracker（同目录同密钥）→ 读不到对方的状态
        let t2 = UsageTracker::new("another-machine", &dir, Some(&SECRET));
        assert_eq!(t2.load().launches, 0, "异机计量文件必须解不开");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn tampered_state_ignored() {
        let dir = tmp("tamper");
        let t = UsageTracker::new(HW, &dir, Some(&SECRET));
        t.record_launch(1_700_000_000);
        // 篡改密文区
        let mut blob = std::fs::read(&t.paths[0]).unwrap();
        blob[20] ^= 0xff;
        std::fs::write(&t.paths[0], &blob).unwrap();
        // 三个副本里两个完好，取 max 仍是 1（不会被篡改值误导）
        assert_eq!(t.load().launches, 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn decoys_sown_once() {
        let dir = tmp("decoy");
        let t = UsageTracker::new(HW, &dir, Some(&SECRET));
        t.record_launch(1_700_000_000);
        let n = t.decoy_paths.iter().filter(|p| p.exists()).count();
        assert_eq!(n, DECOYS, "应播种全部诱饵");
        // 诱饵内容是错魔数，不会被当作真副本读入
        assert_eq!(t.load().launches, 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn file_layout_size() {
        assert_eq!(FILE_LEN, 47);
    }
}
