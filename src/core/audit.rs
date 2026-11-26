//! 审计哈希链（核心模块，v1.5 新增）。
//!
//! # 为什么需要它
//!
//! 校运会成绩涉及评奖与班级荣誉，事后"为什么这个班多算了 2 分"这类质疑
//! 必须有据可查。普通日志（`core/log.rs`）是**平铺文本**，任何人用记事本
//! 改一行都不会被发现。本模块用**哈希链（hash chain）**把审计记录串起来：
//!
//! ```text
//!   记录 i-1                记录 i
//!  ┌──────────────┐      ┌──────────────────────────────┐
//!  │ ts / actor   │      │ ts / actor / action / detail │
//!  │ action       │      │ prev = H(记录 i-1)           │
//!  │ hash = H(…)  │─────►│ hash = H(prev ‖ 本条内容)     │
//!  └──────────────┘      └──────────────────────────────┘
//! ```
//!
//! 每条记录的 `prev_hash` 是前一条的 `hash`，而 `hash` 又是
//! `prev_hash` 与本条内容的摘要。于是：
//!
//! * 改任何一条记录的**内容** → 该条 `hash` 对不上；
//! * 删掉中间任意一条 → 后继记录的 `prev_hash` 对不上；
//! * 调整顺序 → 同样在 `prev_hash` 处断裂。
//!
//! `verify()` 可以精确定位**第一条失配的记录序号**，运维据此判断
//! 是"文件被截断"还是"内容被篡改"。
//!
//! # 哈希函数的选择
//!
//! 本项目坚持**最小依赖**原则（见 docs/04 规则 10），故不引入 `sha2` /
//! `blake3`。这里用 **FNV-1a 64 位**：实现 20 行、无分配、吞吐高，
//! 对"发现笔误/恶意改写"这一目标足够。**但它不是密码学安全哈希**——
//! 能构造碰撞，因此本模块的定位是**防误改与防低级篡改**，
//! 不承诺抵抗有密码学知识的主动攻击者。这一点在文档中不隐瞒。
//!
//! 需要更强保证时，把 `fnv1a64` 换成 `sha2::Sha256` 即可，
//! 其余逻辑（链式结构与校验）完全不用动 —— 见 `docs/03_目标文档.md`。
//!
//! # 落盘位置
//!
//! `<data_dir>/audit/audit-YYYY-MM-DD.jsonl`，JSON Lines 格式：
//! 每行一条独立 JSON，追加写入。相比整体 JSON 的好处是：
//! 1. 追加只 `O_APPEND` 一次写，天然原子；
//! 2. 单行损坏不影响其余记录的解析；
//! 3. 可以直接 `tail` / `grep` 看，也能被外部工具消费。

use crate::core::json::Json;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// 链的创世前驱：第一条记录的 `prev_hash` 固定为该值，
/// 使"整个文件被替换"也能被检出（替换者不知道我们约定的创世值）。
pub const GENESIS: &str = "0000000000000000";

/// FNV-1a 64 位哈希。
///
/// 参数：
/// * `seed` —— 链式前驱摘要，参与运算实现"绑定"效果；
/// * `parts` —— 本条记录的全部字段（时间/操作者/动作/详情）。
///
/// 返回 16 位十六进制小写字符串（定长，便于肉眼比对）。
pub fn fnv1a64(seed: &str, parts: &[&str]) -> String {
    // FNV-1a 64bit 标准参数
    const OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET_BASIS;
    let mut eat = |bytes: &[u8]| {
        for b in bytes {
            h ^= *b as u64;
            h = h.wrapping_mul(PRIME);
        }
    };
    eat(seed.as_bytes());
    // 用 0x1F（单元分隔符）作为字段边界，避免 ("ab","c") 与 ("a","bc")
    // 摘要相同这类拼接歧义。
    for p in parts {
        eat(&[0x1f]);
        eat(p.as_bytes());
    }
    format!("{:016x}", h)
}

/// 一条审计记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditEntry {
    /// 自增序号，从 1 开始（当日文件内）
    pub seq: u64,
    /// 时间戳 `YYYY-MM-DD HH:MM:SS`
    pub time: String,
    /// 操作者标识（v1.5：`anonymous` / `admin` / `token:<id>`）
    pub actor: String,
    /// 动作码，如 `event.delete` / `results.compute`
    pub action: String,
    /// 补充说明（人类可读，可为空）
    pub detail: String,
    /// 前一条记录的摘要
    pub prev_hash: String,
    /// 本条摘要 = H(prev_hash ‖ seq ‖ time ‖ actor ‖ action ‖ detail)
    pub hash: String,
}

impl AuditEntry {
    /// 计算本条摘要。字段顺序一旦固定就不可再改，否则历史链全部失效。
    pub fn compute_hash(&self) -> String {
        let seq = self.seq.to_string();
        fnv1a64(
            &self.prev_hash,
            &[&seq, &self.time, &self.actor, &self.action, &self.detail],
        )
    }

    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("seq", Json::Int(self.seq as i64));
        o.set("time", Json::s(self.time.clone()));
        o.set("actor", Json::s(self.actor.clone()));
        o.set("action", Json::s(self.action.clone()));
        o.set("detail", Json::s(self.detail.clone()));
        o.set("prev", Json::s(self.prev_hash.clone()));
        o.set("hash", Json::s(self.hash.clone()));
        o
    }

    pub fn from_json(j: &Json) -> Option<AuditEntry> {
        Some(AuditEntry {
            seq: j.get_i64("seq")? as u64,
            time: j.get_string("time"),
            actor: j.get_string("actor"),
            action: j.get_string("action"),
            detail: j.get_string("detail"),
            // 兼容手写/旧格式：键名同时接受 prev 与 prev_hash
            prev_hash: j
                .get_str("prev")
                .or_else(|| j.get_str("prev_hash"))
                .unwrap_or(GENESIS)
                .to_string(),
            hash: j.get_string("hash"),
        })
    }

    /// 人类可读的一行（审计面板展示用）。
    pub fn line(&self) -> String {
        let tail = if self.detail.is_empty() {
            String::new()
        } else {
            format!(" · {}", self.detail)
        };
        format!(
            "[{}] #{} {} {}{}",
            self.time, self.seq, self.actor, self.action, tail
        )
    }
}

/// 校验结果。
#[derive(Debug, Clone)]
pub struct VerifyReport {
    /// 检查过的记录数
    pub checked: u64,
    /// 内容摘要失配的记录序号（None 表示全部一致）
    pub bad_hash_at: Option<u64>,
    /// 链式前驱失配的记录序号（说明中间被删除/插入/换序）
    pub bad_link_at: Option<u64>,
    /// 无法解析的行号（1 起，相对文件）——同样视为异常
    pub unparsable_lines: Vec<usize>,
}

impl VerifyReport {
    pub fn ok(&self) -> bool {
        self.bad_hash_at.is_none() && self.bad_link_at.is_none() && self.unparsable_lines.is_empty()
    }

    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("ok", Json::Bool(true));
        o.set("verified", Json::Bool(self.ok()));
        o.set("checked", Json::Int(self.checked as i64));
        o.set(
            "bad_hash_at",
            self.bad_hash_at
                .map(|v| Json::Int(v as i64))
                .unwrap_or(Json::Null),
        );
        o.set(
            "bad_link_at",
            self.bad_link_at
                .map(|v| Json::Int(v as i64))
                .unwrap_or(Json::Null),
        );
        o.set(
            "unparsable_lines",
            Json::arr(
                self.unparsable_lines
                    .iter()
                    .map(|v| Json::Int(*v as i64))
                    .collect::<Vec<_>>(),
            ),
        );
        o.set("message", Json::s(self.summary()));
        o
    }

    pub fn summary(&self) -> String {
        if self.ok() {
            format!("审计链完整，已校验 {} 条记录", self.checked)
        } else if let Some(seq) = self.bad_link_at {
            format!(
                "审计链在 #{} 处断开（前驱摘要不匹配，疑似删除/换序）",
                seq
            )
        } else if let Some(seq) = self.bad_hash_at {
            format!("审计链 #{} 内容被修改（摘要不匹配）", seq)
        } else {
            format!("审计日志存在 {} 行无法解析", self.unparsable_lines.len())
        }
    }
}

/// 校验一组记录（纯函数，便于单测，不碰文件系统）。
pub fn verify_entries(entries: &[AuditEntry]) -> VerifyReport {
    let mut rep = VerifyReport {
        checked: 0,
        bad_hash_at: None,
        bad_link_at: None,
        unparsable_lines: Vec::new(),
    };
    let mut expect_prev = GENESIS.to_string();
    for e in entries {
        rep.checked += 1;
        // 1) 链式链接：本条 prev 应等于前一条的 hash（首条应为创世值）
        if e.prev_hash != expect_prev && rep.bad_link_at.is_none() {
            rep.bad_link_at = Some(e.seq);
        }
        // 2) 内容摘要：重算应与存储值一致
        if e.compute_hash() != e.hash && rep.bad_hash_at.is_none() {
            rep.bad_hash_at = Some(e.seq);
        }
        expect_prev = e.hash.clone();
    }
    rep
}

/// 解析 JSONL 文本为记录列表，同时汇报无法解析的行（1 起编号）。
pub fn parse_jsonl(text: &str) -> (Vec<AuditEntry>, Vec<usize>) {
    let mut out = Vec::new();
    let mut bad = Vec::new();
    for (i, line) in text.lines().enumerate() {
        let t = line.trim();
        if t.is_empty() {
            continue;
        }
        match Json::parse(t).ok().as_ref().and_then(AuditEntry::from_json) {
            Some(e) => out.push(e),
            None => bad.push(i + 1),
        }
    }
    (out, bad)
}

/// 审计器全局状态。
///
/// 可变部分（链头、内存缓存）统一放进 `state` 的 `Mutex` —— 既满足
/// `OnceLock` 只给不可变引用的约束，也保证"读链头 → 写记录 → 推进链头"
/// 在一个临界区内原子完成。不使用任何 `unsafe`。
struct Auditor {
    dir: PathBuf,
    /// 可变状态：链头 + 当日文件名对应的日期 + 最近记录缓存
    state: Mutex<AuditorState>,
}

struct AuditorState {
    /// 当前日文件内最后一条的摘要（链头）
    head_hash: String,
    /// 当前链上最后一条的序号
    head_seq: u64,
    /// 当前日文件对应的日期（YYYY-MM-DD）
    file_date: String,
    /// 内存中保留的最近记录（供前端审计面板快速展示，避免读盘）
    recent: Vec<AuditEntry>,
}

/// 内存中保留的最近条数。
const RECENT_KEEP: usize = 200;

static AUDITOR: OnceLock<Auditor> = OnceLock::new();

/// 初始化审计器。重复调用无副作用（保留首次的目录）。
pub fn init(data_dir: &Path) {
    let dir = data_dir.join("audit");
    let _ = fs::create_dir_all(&dir);
    let date = crate::core::store::now_string()[..10].to_string();
    let mut st = AuditorState {
        head_hash: GENESIS.to_string(),
        head_seq: 0,
        file_date: date,
        recent: Vec::new(),
    };
    // 从今天的文件恢复链头，确保进程重启后链不断裂
    let (hash, seq, recent) = load_tail(&dir, &st.file_date);
    st.head_hash = hash;
    st.head_seq = seq;
    st.recent = recent;
    crate::log_info!(
        "audit",
        "审计链就绪：{}（链头 #{} {}）",
        dir.display(),
        st.head_seq,
        &st.head_hash[..8.min(st.head_hash.len())]
    );
    let a = Auditor {
        dir,
        state: Mutex::new(st),
    };
    let _ = AUDITOR.set(a);
}

/// 读取指定日文件的尾部记录，用于恢复链头与最近缓存。
fn load_tail(dir: &Path, date: &str) -> (String, u64, Vec<AuditEntry>) {
    let path = dir.join(format!("audit-{}.jsonl", date));
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return (GENESIS.to_string(), 0, Vec::new()),
    };
    let (entries, _) = parse_jsonl(&text);
    let head_hash = entries
        .last()
        .map(|e| e.hash.clone())
        .unwrap_or_else(|| GENESIS.to_string());
    let head_seq = entries.last().map(|e| e.seq).unwrap_or(0);
    let skip = entries.len().saturating_sub(RECENT_KEEP);
    let recent = entries.into_iter().skip(skip).collect();
    (head_hash, head_seq, recent)
}

/// 路径构造：`<audit_dir>/audit-YYYY-MM-DD.jsonl`
fn file_for(dir: &Path, date: &str) -> PathBuf {
    dir.join(format!("audit-{}.jsonl", date))
}

/// 追加一条审计记录（线程安全）。
///
/// * `actor` —— 操作者标识；匿名时为 `anonymous`
/// * `action` —— 动作码，建议 `域.动作` 形式，如 `results.compute`
/// * `detail` —— 人类可读补充；无则传 `""`
///
/// 未初始化（如部分单测环境）时静默丢弃，不 panic、不阻断业务。
pub fn record(actor: &str, action: &str, detail: &str) -> Option<AuditEntry> {
    let a = AUDITOR.get()?;
    // 一次加锁完成：跨天判定 → 构造记录 → 追加写 → 推进链头 → 更新缓存
    let mut st = a.state.lock().ok()?;
    let entry = append_locked(&a.dir, &mut st, actor, action, detail)?;
    Some(entry)
}

/// 写入逻辑（调用者已持有 `state` 锁）。
fn append_locked(
    dir: &Path,
    st: &mut AuditorState,
    actor: &str,
    action: &str,
    detail: &str,
) -> Option<AuditEntry> {
    let now = crate::core::store::now_string();
    let date = now[..10].to_string();

    if date != st.file_date {
        // 跨天换文件，但链头**延续**：prev 仍指向上一条（可能是昨天文件里的），
        // 从而跨天不断链。校验时按时间顺序拼接全部文件即可。
        st.file_date = date;
    }

    let mut e = AuditEntry {
        seq: st.head_seq + 1,
        time: now,
        actor: actor.to_string(),
        action: action.to_string(),
        detail: detail.to_string(),
        prev_hash: st.head_hash.clone(),
        hash: String::new(),
    };
    e.hash = e.compute_hash();

    let path = file_for(dir, &st.file_date);
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    // 追加写：JSONL 单行一次 write，配合 O_APPEND 天然原子
    match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(mut f) => {
            if f.write_all(e.to_json().to_string().as_bytes()).is_err()
                || f.write_all(b"\n").is_err()
            {
                // 写盘失败不能阻断业务（与 log.rs 同样的降级策略），
                // 但必须留下 ERROR 痕迹。
                crate::log_error!("audit", "审计记录落盘失败：{}", path.display());
                return None;
            }
        }
        Err(err) => {
            crate::log_error!("audit", "审计文件不可写：{}（{}）", path.display(), err);
            return None;
        }
    }
    // 链头推进 + 缓存
    st.head_hash = e.hash.clone();
    st.head_seq = e.seq;
    st.recent.push(e.clone());
    if st.recent.len() > RECENT_KEEP {
        let excess = st.recent.len() - RECENT_KEEP;
        st.recent.drain(0..excess);
    }
    Some(e)
}

/// 读取审计目录下全部 JSONL（按文件名=日期排序），返回记录与坏行。
fn all_entries(dir: &Path) -> (Vec<AuditEntry>, Vec<usize>) {
    let mut all = Vec::new();
    let mut bad: Vec<usize> = Vec::new();
    let mut files: Vec<PathBuf> = match fs::read_dir(dir) {
        Ok(rd) => rd
            .filter_map(|x| x.ok())
            .map(|x| x.path())
            .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("jsonl"))
            .collect(),
        Err(_) => Vec::new(),
    };
    // 文件名形如 audit-YYYY-MM-DD.jsonl，字典序 = 时间序
    files.sort();
    for f in files.iter() {
        if let Ok(text) = fs::read_to_string(f) {
            let (es, bs) = parse_jsonl(&text);
            if !bs.is_empty() {
                crate::log_warn!(
                    "audit",
                    "审计文件 {} 有 {} 行无法解析（已计入校验报告）",
                    f.display(),
                    bs.len()
                );
                // 用文件名哈希做偏移避免不同文件的坏行号互相混淆
                let base = files
                    .iter()
                    .position(|x| x == f)
                    .map(|i| i * 1_000_000)
                    .unwrap_or(0);
                bad.extend(bs.iter().map(|b| b + base));
            }
            all.extend(es);
        }
    }
    (all, bad)
}

/// 校验全部审计文件。返回报告（含第一条失配位置）。
pub fn verify() -> VerifyReport {
    let a = match AUDITOR.get() {
        Some(a) => a,
        None => {
            return VerifyReport {
                checked: 0,
                bad_hash_at: None,
                bad_link_at: None,
                unparsable_lines: Vec::new(),
            }
        }
    };
    let _g = a.state.lock();
    let (mut entries, bad) = all_entries(&a.dir);
    entries.sort_by_key(|e| e.seq);
    let mut rep = verify_entries(&entries);
    rep.unparsable_lines = bad;
    rep
}

/// 最近 N 条审计记录（新→旧），供面板展示。
pub fn recent(limit: usize) -> Json {
    let limit = limit.min(1000);
    let (items, head_hash, total) = match AUDITOR.get().and_then(|a| a.state.lock().ok()) {
        Some(g) => (g.recent.clone(), g.head_hash.clone(), g.head_seq),
        None => (Vec::new(), GENESIS.to_string(), 0),
    };
    let mut arr: Vec<Json> = Vec::new();
    for e in items.iter().rev().take(limit) {
        let mut o = e.to_json();
        o.set("line", Json::s(e.line()));
        arr.push(o);
    }
    let mut top = Json::obj();
    top.set("ok", Json::Bool(true));
    top.set("count", Json::Int(arr.len() as i64));
    top.set("entries", Json::Arr(arr));
    top.set("head_hash", Json::s(head_hash));
    top.set("total", Json::Int(total as i64));
    top
}

/// 审计目录路径（诊断接口展示用）。
pub fn dir_path() -> Option<PathBuf> {
    AUDITOR.get().map(|a| a.dir.clone())
}

// ---------------------------------------------------------------------------
// 单元测试（v1.5 新增）：哈希链的稳定性与篡改检出能力
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(seq: u64, prev: &str, action: &str, detail: &str) -> AuditEntry {
        let mut e = AuditEntry {
            seq,
            time: format!("2026-09-25 10:00:{:02}", seq % 60),
            actor: "tester".into(),
            action: action.into(),
            detail: detail.into(),
            prev_hash: prev.to_string(),
            hash: String::new(),
        };
        e.hash = e.compute_hash();
        e
    }

    fn chain(n: u64) -> Vec<AuditEntry> {
        let mut out = Vec::new();
        let mut prev = GENESIS.to_string();
        for i in 1..=n {
            let e = mk(i, &prev, "test.action", &format!("第 {} 条", i));
            prev = e.hash.clone();
            out.push(e);
        }
        out
    }

    #[test]
    fn fnv_is_deterministic_and_length_fixed() {
        let a = fnv1a64("00", &["x", "y"]);
        let b = fnv1a64("00", &["x", "y"]);
        assert_eq!(a, b, "同输入必须同输出");
        assert_eq!(a.len(), 16, "固定 16 位十六进制");
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fnv_field_boundary_no_collision_on_concat_ambiguity() {
        // ("ab","c") 与 ("a","bc") 拼接后字节流相同，必须产生不同摘要
        assert_ne!(fnv1a64("s", &["ab", "c"]), fnv1a64("s", &["a", "bc"]));
    }

    #[test]
    fn fnv_seed_matters() {
        assert_ne!(fnv1a64("seed1", &["x"]), fnv1a64("seed2", &["x"]));
    }

    #[test]
    fn intact_chain_verifies() {
        let rep = verify_entries(&chain(5));
        assert!(rep.ok(), "完整链应通过：{:?}", rep);
        assert_eq!(rep.checked, 5);
        assert_eq!(rep.bad_hash_at, None);
        assert_eq!(rep.bad_link_at, None);
    }

    #[test]
    fn empty_chain_is_ok() {
        assert!(verify_entries(&[]).ok());
    }

    #[test]
    fn tampered_detail_detected_at_that_seq() {
        let mut c = chain(5);
        c[2].detail = "被偷偷改成了别的".into();
        let rep = verify_entries(&c);
        assert!(!rep.ok());
        assert_eq!(rep.bad_hash_at, Some(3), "应精确定位到第 3 条");
    }

    #[test]
    fn tampered_hash_detected() {
        let mut c = chain(3);
        c[1].hash = "deadbeefdeadbeef".into();
        let rep = verify_entries(&c);
        assert!(!rep.ok());
        // 第 2 条自身摘要不对 → bad_hash_at=2；
        // 同时第 3 条 prev 指向旧 hash → bad_link_at=3
        assert_eq!(rep.bad_hash_at, Some(2));
        assert_eq!(rep.bad_link_at, Some(3));
    }

    #[test]
    fn deleted_middle_entry_breaks_link() {
        let c = chain(5);
        let mut cut = c.clone();
        cut.remove(2); // 删掉第 3 条
        let rep = verify_entries(&cut);
        assert!(!rep.ok(), "删除中间记录必须被检出");
        assert_eq!(rep.bad_link_at, Some(4), "断点应在原第 4 条");
    }

    #[test]
    fn reordered_entries_break_link() {
        let mut c = chain(4);
        c.swap(1, 2);
        let rep = verify_entries(&c);
        assert!(!rep.ok(), "换序必须被检出");
    }

    #[test]
    fn forged_genesis_detected() {
        // 攻击者用自造内容替换整条链，但 prev 不是约定创世值 → 首条即断
        let e = mk(1, "1111111111111111", "fake", "");
        let rep = verify_entries(&[e]);
        assert_eq!(rep.bad_link_at, Some(1));
    }

    #[test]
    fn roundtrip_json_preserves_hash() {
        let c = chain(3);
        let text = c
            .iter()
            .map(|e| e.to_json().to_string())
            .collect::<Vec<_>>()
            .join("\n");
        let (parsed, bad) = parse_jsonl(&text);
        assert!(bad.is_empty());
        assert_eq!(parsed, c, "JSON 往返后必须逐字段一致");
        assert!(verify_entries(&parsed).ok());
    }

    #[test]
    fn jsonl_tolerates_blank_lines_and_reports_bad_lines() {
        let text = "\n{\"seq\":1}\n不是JSON\n\n";
        let (ok_entries, bad) = parse_jsonl(text);
        // 第一行 {"seq":1} 因缺 time/action 等仍能构造（字段给默认值），
        // 但 seq 存在 → from_json 成功
        assert_eq!(ok_entries.len(), 1);
        assert_eq!(bad, vec![3], "第 3 行无法解析");
    }

    #[test]
    fn report_summary_is_actionable() {
        let mut c = chain(3);
        c[0].action = "changed".into();
        let rep = verify_entries(&c);
        let s = rep.summary();
        assert!(s.contains("#1"), "摘要应指出序号：{}", s);
    }

    #[test]
    fn record_without_init_is_safe_noop() {
        // 未调用 init 时不可 panic（单测并行下的重要保证）
        // 注意：若其他测试已 init 则返回 Some，两种结果都合法
        let _ = record("t", "noop", "");
    }
}
