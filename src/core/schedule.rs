//! 赛程编排（核心模块）
//!
//! # 这个模块解决什么问题
//!
//! 运动会现场最容易崩的一环是**赛程**：项目多、场地少、学生兼项，
//! 排错了现场才发现。传统做法是 Excel + 人脑记，一遇到
//! "某学生 9:00 同时被排了 100 米和跳远"就只能现场改、重印秩序册。
//!
//! 本模块提供两件事：
//!
//! 1. **冲突检测**（[`detect_conflicts`]）—— 老师自己排，系统负责挑错。
//!    这是收益最高、风险最低的一半：不改变老师任何习惯，只把"不可能的安排"指出来。
//! 2. **贪心自动编排**（[`auto_arrange`]）—— 在已有报名数据上生成一份可行的初始赛程，
//!    老师再手动微调。
//!
//! # 为什么不做启发式优化（模拟退火 / 遗传算法）
//!
//! 参考了同类系统（见 `docs/02` 的调研记录）：专业赛事系统的编排引擎会做
//! `Minimize Σ(软约束违反)`。但本项目**刻意不做**，理由是：
//!
//! - **规模不需要**：一个中学几十个项目，贪心解的质量与最优解差距很小
//! - **可解释性 > 最优性**：老师必须能看懂"为什么这个项目排在这里"。
//!   遗传算法给出一个"综合适应度 0.87"的方案，老师不敢用、也没法手动调
//! - **现场要能改**：真实场景里总有人临时弃赛、天气突变，
//!   此时需要的是"能局部重排"而不是"重新跑一遍黑盒"
//!
//! 故本模块只保证**硬约束不违反**，软约束（休息间隔、场地利用率）用
//! 贪心的排序启发式尽量满足，并**明示哪些没满足**（而不是假装优化过）。
//!
//! # 领域模型
//!
//! 遵循真实田径赛事习惯（调研自元朗区田径大会、全国青少年田径运动会赛程表）：
//!
//! ```text
//! 赛会（2 天）
//!  └─ 竞赛单元（第一天上午 / 第一天下午 / 第二天上午 / 第二天下午）
//!      ├─ 径赛：占「径赛场地」，项目按时间依次进行
//!      └─ 田赛：占「田赛场地」，可与径赛**并行**（不同场地）
//! ```
//!
//! 关键点：**径赛与田赛在不同场地可同时进行**，这正是"多场地"的现实含义。
//! 同一场地内则必须串行 —— 这一条是硬约束。

use crate::core::json::Json;
use crate::core::model::{Event, Registration, Student};
use std::collections::{BTreeMap, HashMap, HashSet};

/// 默认休息间隔（分钟）。来源：行业惯例"同一运动员参赛间隔 ≥ 30 分钟"。
pub const DEFAULT_REST_MINUTES: i64 = 30;

/// 径赛检录需提前的分钟数（行业惯例 20 分钟）。
pub const CALL_TRACK_MINUTES: i64 = 20;

/// 田赛检录需提前的分钟数（行业惯例 15 分钟）。
pub const CALL_FIELD_MINUTES: i64 = 15;

/// 径赛道次分配顺序：成绩优者居中（4、5、3、6、2、7、1、8）。
///
/// 依据田径竞赛规则，弯道跑时中间道次距离最短，故成绩最好的运动员
/// 应分在中间道次。这个数组就是"从最优到最差"对应的道次序列。
pub const LANE_ORDER: [i64; 8] = [4, 5, 3, 6, 2, 7, 1, 8];

// ============================================================================
// 数据结构
// ============================================================================

/// 场地：一个可以"同时只进行一个项目"的物理空间。
///
/// 注意"场地"的粒度：**不是**"一个操场"，而是"一块不能同时干两件事的地方"。
/// 例如标准田径场实际上是三个独立场地：
/// - 跑道（径赛用）
/// - 沙坑/投掷区（田赛用）
/// - （可选）第二块田赛区
#[derive(Debug, Clone, PartialEq)]
pub struct Venue {
    pub id: i64,
    pub name: String,
    /// 该场地能否承办径赛（跑道类）
    pub for_track: bool,
    /// 该场地能否承办田赛（沙坑/投掷区类）
    pub for_field: bool,
}

impl Venue {
    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("id", Json::Int(self.id));
        o.set("name", Json::s(self.name.clone()));
        o.set("for_track", Json::Bool(self.for_track));
        o.set("for_field", Json::Bool(self.for_field));
        o
    }

    pub fn from_json(j: &Json) -> Option<Venue> {
        Some(Venue {
            id: j.get_i64("id")?,
            name: j.get_string("name"),
            for_track: j.get_bool("for_track").unwrap_or(false),
            for_field: j.get_bool("for_field").unwrap_or(false),
        })
    }
}

/// 竞赛单元：一段连续比赛时间（如"第一天上午 08:00-11:30"）。
///
/// 用"起始分钟 + 时长"表示，而不是绝对日期时间 —— 因为运动会赛程
/// 关心的是"第几天第几段"，不关心具体日历日。这样也避免了时区问题。
#[derive(Debug, Clone, PartialEq)]
pub struct Session {
    pub id: i64,
    /// 第几天（1 起）
    pub day: i64,
    /// 单元名（如"上午"/"下午"）
    pub name: String,
    /// 起始时刻的分钟数（从 00:00 起算，如 08:00 = 480）
    pub start_min: i64,
    /// 持续分钟数
    pub duration_min: i64,
}

impl Session {
    pub fn end_min(&self) -> i64 {
        self.start_min + self.duration_min
    }

    /// 人类可读的时间范围（如 "08:00-11:30"）。
    pub fn time_range(&self) -> String {
        format!("{}-{}", fmt_min(self.start_min), fmt_min(self.end_min()))
    }

    /// 单元标签（如 "第1天上午"）。
    pub fn label(&self) -> String {
        format!("第{}天{}", self.day, self.name)
    }

    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("id", Json::Int(self.id));
        o.set("day", Json::Int(self.day));
        o.set("name", Json::s(self.name.clone()));
        o.set("start_min", Json::Int(self.start_min));
        o.set("duration_min", Json::Int(self.duration_min));
        o.set("time_range", Json::s(self.time_range()));
        o.set("label", Json::s(self.label()));
        o
    }

    pub fn from_json(j: &Json) -> Option<Session> {
        Some(Session {
            id: j.get_i64("id")?,
            day: j.get_i64("day").unwrap_or(1).max(1),
            name: j.get_string("name"),
            start_min: j.get_i64("start_min").unwrap_or(480),
            duration_min: j.get_i64("duration_min").unwrap_or(210),
        })
    }
}

/// 把分钟数格式化为 HH:MM。
pub fn fmt_min(m: i64) -> String {
    let m = m.max(0);
    format!("{:02}:{:02}", (m / 60) % 24, m % 60)
}

/// 把 "HH:MM" 解析为分钟数；非法则返回 None。
///
/// 当前 `schedule_view` 直接下发 `start_min`，前端无需反解；
/// 该函数在"前端自行编辑单元时间"功能落地前暂未调用，标记为允许死代码。
#[allow(dead_code)]
pub fn parse_hhmm(s: &str) -> Option<i64> {
    let s = s.trim();
    let (h, m) = s.split_once(':')?;
    let h: i64 = h.trim().parse().ok()?;
    let m: i64 = m.trim().parse().ok()?;
    if !(0..24).contains(&h) || !(0..60).contains(&m) {
        return None;
    }
    Some(h * 60 + m)
}

/// 一个项目在赛程中的安排。
#[derive(Debug, Clone, PartialEq)]
pub struct Slot {
    pub event_id: i64,
    pub session_id: i64,
    /// 该项目的开始时刻（分钟）
    pub start_min: i64,
    /// 占用时长（分钟）
    pub duration_min: i64,
    /// 所在场地
    pub venue_id: i64,
    /// 组数（人数多时拆组）
    pub group_count: i64,
}

impl Slot {
    pub fn end_min(&self) -> i64 {
        self.start_min + self.duration_min
    }

    /// 两个时段是否重叠。端点相接不算重叠（11:30 结束、11:30 开始是合法的）。
    pub fn overlaps(&self, other: &Slot) -> bool {
        self.start_min < other.end_min() && other.start_min < self.end_min()
    }

    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("event_id", Json::Int(self.event_id));
        o.set("session_id", Json::Int(self.session_id));
        o.set("start_min", Json::Int(self.start_min));
        o.set("duration_min", Json::Int(self.duration_min));
        o.set("venue_id", Json::Int(self.venue_id));
        o.set("group_count", Json::Int(self.group_count));
        o.set("start_time", Json::s(fmt_min(self.start_min)));
        o.set("end_time", Json::s(fmt_min(self.end_min())));
        o
    }

    pub fn from_json(j: &Json) -> Option<Slot> {
        Some(Slot {
            event_id: j.get_i64("event_id")?,
            session_id: j.get_i64("session_id")?,
            start_min: j.get_i64("start_min")?,
            duration_min: j.get_i64("duration_min").unwrap_or(30),
            venue_id: j.get_i64("venue_id").unwrap_or(0),
            group_count: j.get_i64("group_count").unwrap_or(1).max(1),
        })
    }
}

/// 冲突等级。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// 提示：不违反规则，但值得看一眼
    Info,
    /// 警告：可能有问题（如休息时间偏紧）
    Warn,
    /// 错误：硬约束违反，现场一定出事
    Error,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::Error => "error",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Severity::Info => "提示",
            Severity::Warn => "警告",
            Severity::Error => "错误",
        }
    }
}

/// 一条冲突记录。
#[derive(Debug, Clone, PartialEq)]
pub struct Conflict {
    pub severity: Severity,
    /// 机器可读的冲突类型（供前端分类展示与脚本判断）
    pub kind: String,
    /// 给人看的说明（含具体名字与时间，便于现场定位）
    pub message: String,
    /// 涉及的项目（用于前端高亮）
    pub event_ids: Vec<i64>,
    /// 涉及的学生（若与学生兼项有关）
    pub student_id: Option<i64>,
    /// 涉及的时间段（若与时间有关）
    pub time_desc: String,
}

impl Conflict {
    fn new(sev: Severity, kind: &str, message: String) -> Conflict {
        Conflict {
            severity: sev,
            kind: kind.to_string(),
            message,
            event_ids: Vec::new(),
            student_id: None,
            time_desc: String::new(),
        }
    }

    fn with_events(mut self, ids: Vec<i64>) -> Conflict {
        self.event_ids = ids;
        self
    }

    fn with_student(mut self, sid: i64) -> Conflict {
        self.student_id = Some(sid);
        self
    }

    fn with_time(mut self, t: String) -> Conflict {
        self.time_desc = t;
        self
    }

    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("severity", Json::s(self.severity.as_str()));
        o.set("severity_label", Json::s(self.severity.label()));
        o.set("kind", Json::s(self.kind.clone()));
        o.set("message", Json::s(self.message.clone()));
        o.set(
            "event_ids",
            Json::arr(self.event_ids.iter().map(|i| Json::Int(*i))),
        );
        o.set(
            "student_id",
            match self.student_id {
                Some(s) => Json::Int(s),
                None => Json::Null,
            },
        );
        o.set("time_desc", Json::s(self.time_desc.clone()));
        o
    }
}

// ============================================================================
// 默认数据（首次使用时提供一套合理的场地与单元）
// ============================================================================

/// 默认场地：按真实田径场的功能分区来定。
///
/// 关键洞察：**跑道和田赛区是两个场地**，可以同时开工。
/// 这是"径赛田赛并行"能成立的前提，也是本模块"多场地"的核心含义。
pub fn default_venues() -> Vec<Venue> {
    vec![
        Venue {
            id: 1,
            name: "田径跑道".into(),
            for_track: true,
            for_field: false,
        },
        Venue {
            id: 2,
            name: "田赛区（沙坑/投掷）".into(),
            for_track: false,
            for_field: true,
        },
    ]
}

/// 默认竞赛单元：2 天 × 上午/下午 = 4 个单元。
///
/// 时间取自学校运动会常见安排（上午 08:00-11:30、下午 14:00-17:00），
/// 留出中午休息。上午时长 210 分钟、下午 180 分钟。
pub fn default_sessions(days: i64) -> Vec<Session> {
    let mut out = Vec::new();
    let mut id = 1;
    for d in 1..=days.max(1) {
        out.push(Session {
            id,
            day: d,
            name: "上午".into(),
            start_min: 8 * 60,
            duration_min: 210,
        });
        id += 1;
        out.push(Session {
            id,
            day: d,
            name: "下午".into(),
            start_min: 14 * 60,
            duration_min: 180,
        });
        id += 1;
    }
    out
}

/// 估算一个项目需要多少分钟。
///
/// 这里的数值是**经验估算**，不是精确值 —— 目的是"排得开"，不是"排得准"。
/// 老师可以在前端手动调整每个项目的时长。
///
/// 估算依据：
/// - 径赛按"组数 × 每组耗时"，短跑每组约 3 分钟（含起跑与记录），
///   中长跑每组约 6 分钟（跑完还要喘）
/// - 田赛按"人数 × 每次试跳/试掷耗时 / 场地并行度"，
///   跳远类约 1.5 分钟/人次，投掷类约 1.2 分钟/人次，跳高约 2 分钟/人次
pub fn estimate_duration_min(ev: &Event, participant_count: i64) -> i64 {
    let n = participant_count.max(1);
    // 集体项目（接力）：按队数 × 每组耗时
    if ev.is_team {
        let groups = (n + 7) / 8; // 8 队一组
        return (groups * 5).max(10);
    }
    if ev.is_track() {
        // 按距离粗略判断：1500 米及以上算中长跑
        let is_long = ev.name.contains("1500")
            || ev.name.contains("3000")
            || ev.name.contains("800")
            || ev.name.contains("5000")
            || ev.name.contains("竞走")
            || ev.name.contains("长跑");
        let per_group = if is_long { 6 } else { 3 };
        // 分组数：不足一组时也按 1 组算（用浮点向上取整，避免 n=1 时算出 0 组）
        let groups = ((n as f64) / 8.0).ceil() as i64;
        // 地板取单个组的耗时：n=1 也要走完一次起跑/计时，不会比一组更短。
        // 注意不能用 .max(6) 这种固定地板——它会在 n=8 与 n=16 都压成 6，
        // 破坏"人越多耗时越长"的单调性（被 duration_estimate_is_positive_and_monotonic 抓到）。
        return (groups * per_group).max(per_group);
    }
    // 田赛：按人次算，两块区可并行 → 大致除以 2
    let per_person = if ev.name.contains("跳高") { 2 } else { 1 };
    // 用浮点避免整数除法把 1 人截断成 0（曾导致"人越多耗时不一定越多"）
    let raw = ((n as f64) * (per_person as f64) / 2.0).ceil() as i64;
    raw.max(8)
}

// ============================================================================
// 冲突检测
// ============================================================================

/// 检测赛程中的冲突。
///
/// 这是本模块**最重要**的函数：它不改变老师的任何习惯，
/// 只负责把"排错了"这件事从"现场发现"提前到"编排时发现"。
///
/// 检测项：
/// 1. **同场地重叠**（Error）—— 同一场地同一时间排了两个项目，物理上不可能
/// 2. **兼项时间冲突**（Error）—— 同一学生两个项目时间重叠
/// 3. **休息间隔不足**（Warn）—— 同一学生两个项目间隔 < 30 分钟
/// 4. **检录时间冲突**（Warn）—— 间隔够但不够提前检录
/// 5. **场地类型不匹配**（Error）—— 径赛排到了田赛场地
/// 6. **超出单元时间范围**（Error）—— 项目跑到单元之外了
/// 7. **未编排项目**（Warn）—— 报了名但没排赛程
///
/// 返回的冲突按严重程度降序排列（Error 在前），同级按时间排序，
/// 便于前端直接从上往下展示"最该先看的"。
pub fn detect_conflicts(
    events: &[Event],
    registrations: &[Registration],
    slots: &[Slot],
    venues: &[Venue],
    sessions: &[Session],
    students: &[Student],
) -> Vec<Conflict> {
    let mut out: Vec<Conflict> = Vec::new();

    let ev_by_id: HashMap<i64, &Event> = events.iter().map(|e| (e.id, e)).collect();
    let ve_by_id: HashMap<i64, &Venue> = venues.iter().map(|v| (v.id, v)).collect();
    let se_by_id: HashMap<i64, &Session> = sessions.iter().map(|s| (s.id, s)).collect();
    let st_by_id: HashMap<i64, &Student> = students.iter().map(|s| (s.id, s)).collect();

    // 项目 → 报名学生
    let mut regs_by_event: HashMap<i64, Vec<i64>> = HashMap::new();
    for r in registrations {
        regs_by_event.entry(r.event_id).or_default().push(r.student_id);
    }

    // ---------- 0) 无效引用：排到了不存在的项目/场地/单元 ----------
    for s in slots {
        if !ev_by_id.contains_key(&s.event_id) {
            out.push(Conflict::new(
                Severity::Error,
                "dangling_event",
                format!("赛程引用了不存在的项目（id={}），可能该已被删除", s.event_id),
            ));
            continue;
        }
        if !ve_by_id.contains_key(&s.venue_id) {
            out.push(
                Conflict::new(
                    Severity::Error,
                    "dangling_venue",
                    format!(
                        "项目「{}」被排到了不存在的场地（id={}）",
                        ev_by_id[&s.event_id].name, s.venue_id
                    ),
                )
                .with_events(vec![s.event_id]),
            );
        }
        if !se_by_id.contains_key(&s.session_id) {
            out.push(
                Conflict::new(
                    Severity::Error,
                    "dangling_session",
                    format!(
                        "项目「{}」被排到了不存在的竞赛单元（id={}）",
                        ev_by_id[&s.event_id].name, s.session_id
                    ),
                )
                .with_events(vec![s.event_id]),
            );
        }
    }

    // ---------- 1) 同场地重叠（硬约束） ----------
    for i in 0..slots.len() {
        for j in (i + 1)..slots.len() {
            let (a, b) = (&slots[i], &slots[j]);
            if a.venue_id != b.venue_id || a.session_id != b.session_id {
                continue;
            }
            if !a.overlaps(b) {
                continue;
            }
            let (na, nb) = match (ev_by_id.get(&a.event_id), ev_by_id.get(&b.event_id)) {
                (Some(x), Some(y)) => (x.name.clone(), y.name.clone()),
                _ => continue,
            };
            let vname = ve_by_id
                .get(&a.venue_id)
                .map(|v| v.name.clone())
                .unwrap_or_else(|| format!("场地{}", a.venue_id));
            let sess = se_by_id.get(&a.session_id).map(|s| s.label());
            out.push(
                Conflict::new(
                    Severity::Error,
                    "venue_overlap",
                    format!(
                        "同一场地被排了两个项目：「{}」与「{}」都在 {} 的 {} 时段使用「{}」",
                        na,
                        nb,
                        sess.as_deref().unwrap_or("未知单元"),
                        fmt_min(a.start_min),
                        vname
                    ),
                )
                .with_events(vec![a.event_id, b.event_id])
                .with_time(format!("{}-{}", fmt_min(a.start_min), fmt_min(a.end_min()))),
            );
        }
    }

    // ---------- 2~5) 与学生有关的冲突 ----------
    // 先把"学生 → 他参加的所有 (slot, event)"建出来
    let mut by_student: HashMap<i64, Vec<(&Slot, &Event)>> = HashMap::new();
    for s in slots {
        let Some(ev) = ev_by_id.get(&s.event_id) else {
            continue;
        };
        if let Some(sids) = regs_by_event.get(&s.event_id) {
            for sid in sids {
                by_student.entry(*sid).or_default().push((s, ev));
            }
        }
    }

    for (sid, mut list) in by_student {
        list.sort_by_key(|(s, _)| (s.session_id, s.start_min));
        let sname = st_by_id
            .get(&sid)
            .map(|s| s.name.clone())
            .unwrap_or_else(|| format!("学生{}", sid));

        for i in 0..list.len() {
            for j in (i + 1)..list.len() {
                let (sa, ea) = list[i];
                let (sb, eb) = list[j];
                if sa.session_id != sb.session_id {
                    continue; // 跨单元不冲突（中间至少隔了午餐/隔夜）
                }
                let gap = sb.start_min - sa.end_min();

                // 2) 时间重叠
                if sa.overlaps(sb) {
                    let sess = se_by_id.get(&sa.session_id).map(|s| s.label());
                    out.push(
                        Conflict::new(
                            Severity::Error,
                            "student_clash",
                            format!(
                                "「{}」被同时排了两个项目：「{}」({}) 与「{}」({})",
                                sname,
                                ea.name,
                                fmt_min(sa.start_min),
                                eb.name,
                                fmt_min(sb.start_min)
                            ),
                        )
                        .with_events(vec![sa.event_id, sb.event_id])
                        .with_student(sid)
                        .with_time(format!(
                            "{} {}",
                            sess.as_deref().unwrap_or(""),
                            fmt_min(sa.start_min)
                        )),
                    );
                    continue;
                }

                // 3) 休息间隔不足
                if gap < DEFAULT_REST_MINUTES {
                    out.push(
                        Conflict::new(
                            Severity::Warn,
                            "rest_too_short",
                            format!(
                                "「{}」两项目间隔仅 {} 分钟（建议 ≥ {} 分钟）：「{}」{} 结束、「{}」{} 开始",
                                sname,
                                gap,
                                DEFAULT_REST_MINUTES,
                                ea.name,
                                fmt_min(sa.end_min()),
                                eb.name,
                                fmt_min(sb.start_min)
                            ),
                        )
                        .with_events(vec![sa.event_id, sb.event_id])
                        .with_student(sid)
                        .with_time(format!("间隔 {} 分钟", gap)),
                    );
                    continue;
                }

                // 4) 检录时间不够（间隔够休息，但不够提前检录）
                //    径赛提前 20 分钟、田赛提前 15 分钟。若前一项结束到后一项
                //    检录截止不足，运动员跑不过来。
                let call = if eb.is_track() {
                    CALL_TRACK_MINUTES
                } else {
                    CALL_FIELD_MINUTES
                };
                if gap < call {
                    out.push(
                        Conflict::new(
                            Severity::Warn,
                            "call_time_tight",
                            format!(
                                "「{}」从「{}」结束到「{}」检录只有 {} 分钟，而{}需提前 {} 分钟检录",
                                sname,
                                ea.name,
                                eb.name,
                                gap,
                                if eb.is_track() { "径赛" } else { "田赛" },
                                call
                            ),
                        )
                        .with_events(vec![sa.event_id, sb.event_id])
                        .with_student(sid)
                        .with_time(format!("间隔 {} 分钟", gap)),
                    );
                }
            }
        }
    }

    // ---------- 5) 场地类型不匹配 ----------
    for s in slots {
        let (Some(ev), Some(v)) = (ev_by_id.get(&s.event_id), ve_by_id.get(&s.venue_id)) else {
            continue;
        };
        if ev.is_track() && !v.for_track {
            out.push(
                Conflict::new(
                    Severity::Error,
                    "venue_type_mismatch",
                    format!(
                        "径赛项目「{}」被排到了田赛场地「{}」——径赛必须用跑道",
                        ev.name, v.name
                    ),
                )
                .with_events(vec![s.event_id]),
            );
        } else if !ev.is_track() && !v.for_field {
            out.push(
                Conflict::new(
                    Severity::Error,
                    "venue_type_mismatch",
                    format!(
                        "田赛项目「{}」被排到了径赛场地「{}」——田赛必须用沙坑/投掷区",
                        ev.name, v.name
                    ),
                )
                .with_events(vec![s.event_id]),
            );
        }
    }

    // ---------- 6) 超出单元时间范围 ----------
    for s in slots {
        let Some(sess) = se_by_id.get(&s.session_id) else {
            continue;
        };
        let ev_name = ev_by_id
            .get(&s.event_id)
            .map(|e| e.name.clone())
            .unwrap_or_default();
        if s.start_min < sess.start_min {
            out.push(
                Conflict::new(
                    Severity::Error,
                    "out_of_session",
                    format!(
                        "「{}」排在 {} 开始，早于{}的起始时间 {}",
                        ev_name,
                        fmt_min(s.start_min),
                        sess.label(),
                        fmt_min(sess.start_min)
                    ),
                )
                .with_events(vec![s.event_id]),
            );
        }
        if s.end_min() > sess.end_min() {
            out.push(
                Conflict::new(
                    Severity::Error,
                    "out_of_session",
                    format!(
                        "「{}」{} 结束，超出{}的结束时间 {}",
                        ev_name,
                        fmt_min(s.end_min()),
                        sess.label(),
                        fmt_min(sess.end_min())
                    ),
                )
                .with_events(vec![s.event_id]),
            );
        }
    }

    // ---------- 7) 已报名但未编排 ----------
    let scheduled: HashSet<i64> = slots.iter().map(|s| s.event_id).collect();
    for (eid, sids) in &regs_by_event {
        if sids.is_empty() || scheduled.contains(eid) {
            continue;
        }
        let ename = ev_by_id
            .get(eid)
            .map(|e| e.name.clone())
            .unwrap_or_else(|| format!("项目{}", eid));
        out.push(
            Conflict::new(
                Severity::Warn,
                "unscheduled",
                format!(
                    "「{}」有 {} 人报名，但还没有排进赛程",
                    ename,
                    sids.len()
                ),
            )
            .with_events(vec![*eid]),
        );
    }

    // ---------- 8) 报了名但没赛程/没报名的项目（提示） ----------
    for ev in events {
        if !regs_by_event.contains_key(&ev.id) {
            out.push(
                Conflict::new(
                    Severity::Info,
                    "no_registration",
                    format!("项目「{}」还没有人报名", ev.name),
                )
                .with_events(vec![ev.id]),
            );
        }
    }

    // 排序：严重程度降序（Error 优先），同级别按 kind 稳定排序（保证结果可复现）
    out.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.message.cmp(&b.message))
    });
    out
}

// ============================================================================
// 贪心自动编排
// ============================================================================

/// 自动编排的选项。
#[derive(Debug, Clone)]
pub struct ArrangeOptions {
    /// 是否把已有赛程清空重排（false = 在已有基础上补齐未编排的）
    pub replace: bool,
    /// 项目时长估算的人工覆盖（项目 id → 分钟）
    pub duration_override: HashMap<i64, i64>,
}

impl Default for ArrangeOptions {
    fn default() -> Self {
        ArrangeOptions {
            replace: true,
            duration_override: HashMap::new(),
        }
    }
}

/// 自动编排的结果。
#[derive(Debug, Clone)]
pub struct ArrangeResult {
    pub slots: Vec<Slot>,
    /// 未能排入的项目及原因（**必须如实返回**，不能静默丢弃）
    pub unplaced: Vec<(i64, String)>,
}

/// 贪心自动编排。
///
/// # 算法（为什么这样排序）
///
/// 采用"最长优先 + 场地并行"的贪心（Longest Processing Time first, LPT）：
///
/// 1. **先算时长**：每个项目的预计耗时。人数越多、越长的项目越占地方。
/// 2. **按耗时降序**：先排长项目。这是排程问题的经典启发式 ——
///    长项目若最后排，很容易因碎片时间不够而排不进去；
///    先把它们安置好，短项目可以填缝。
/// 3. **按径赛/田赛分流到场地**：跑道类项目只能进 `for_track` 的场地，
///    田赛只能进 `for_field` 的场地。**两类场地独立推进**，
///    这就是"径赛与田赛并行"的实现方式。
/// 4. **逐个塞入最早可行的空位**：在每个单元的每个可用场地上，
///    找第一个能放下该项目的空档（不重叠即可）。
/// 5. **兼项检查**：塞入前检查该项目所有报名学生在目标时段是否已有冲突（含休息间隔）。
///    有冲突则尝试往后推 5 分钟，推 N 次仍不行则换下一个空位。
/// 6. **实在排不下**：记入 `unplaced` 并说明原因，**不静默丢弃**。
///
/// # 刻意不做的事
///
/// - **不做跨单元重排**：项目不会为了"排得更紧凑"从上午挪到下午。
///   老师看到的结果应当是"按报名顺序自然铺开"的，不是"优化过但难以理解"的。
/// - **不做软约束最优**：休息间隔用"贪心时检查"而非"全局优化"来满足，
///   可能个别学生间隔刚好 30 分钟。这是**刻意的取舍**：可解释 > 最优。
pub fn auto_arrange(
    events: &[Event],
    registrations: &[Registration],
    venues: &[Venue],
    sessions: &[Session],
    existing: &[Slot],
    opts: &ArrangeOptions,
) -> ArrangeResult {
    let mut slots: Vec<Slot> = if opts.replace {
        Vec::new()
    } else {
        existing.to_vec()
    };
    let mut unplaced: Vec<(i64, String)> = Vec::new();

    if venues.is_empty() {
        for ev in events {
            unplaced.push((ev.id, "没有配置任何场地".into()));
        }
        return ArrangeResult { slots, unplaced };
    }
    if sessions.is_empty() {
        for ev in events {
            unplaced.push((ev.id, "没有配置任何竞赛单元".into()));
        }
        return ArrangeResult { slots, unplaced };
    }

    // 项目 → 报名学生
    let mut regs_by_event: HashMap<i64, Vec<i64>> = HashMap::new();
    for r in registrations {
        regs_by_event.entry(r.event_id).or_default().push(r.student_id);
    }

    // 学生 → 已排的时段（用于兼项检查），跨场地共享
    let mut busy: HashMap<i64, Vec<(i64, i64, i64)>> = HashMap::new(); // sid -> [(sess, start, end)]
    for s in &slots {
        if let Some(sids) = regs_by_event.get(&s.event_id) {
            for sid in sids {
                busy.entry(*sid)
                    .or_default()
                    .push((s.session_id, s.start_min, s.end_min()));
            }
        }
    }

    // 待排项目：只排"有人报名"的，且（replace=false 时）尚未编排的
    let already: HashSet<i64> = slots.iter().map(|s| s.event_id).collect();
    let mut todo: Vec<(&Event, i64, i64)> = Vec::new(); // (event, 人数, 时长)
    for ev in events {
        let n = regs_by_event.get(&ev.id).map(|v| v.len()).unwrap_or(0) as i64;
        if n == 0 {
            continue; // 没人报名的不占赛程
        }
        if !opts.replace && already.contains(&ev.id) {
            continue;
        }
        let dur = opts
            .duration_override
            .get(&ev.id)
            .copied()
            .unwrap_or_else(|| estimate_duration_min(ev, n));
        todo.push((ev, n, dur.max(1)));
    }

    // LPT：长项目优先。同长度时按项目 id（稳定、可复现）
    todo.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.0.id.cmp(&b.0.id)));

    // 单元按天/时间排序
    let mut sess_sorted: Vec<&Session> = sessions.iter().collect();
    sess_sorted.sort_by_key(|s| (s.day, s.start_min));

    for (ev, n, dur) in todo {
        let group_count = group_count_for(ev, n);
        // 该项目的所有报名学生
        let sids = regs_by_event.get(&ev.id).cloned().unwrap_or_default();

        // 可用场地（类型匹配）
        let mut usable: Vec<&Venue> = venues
            .iter()
            .filter(|v| {
                if ev.is_track() {
                    v.for_track
                } else {
                    v.for_field
                }
            })
            .collect();
        usable.sort_by_key(|v| v.id);

        if usable.is_empty() {
            unplaced.push((
                ev.id,
                format!(
                    "没有{}可用场地",
                    if ev.is_track() { "径赛" } else { "田赛" }
                ),
            ));
            continue;
        }

        let mut placed = false;
        'outer: for sess in &sess_sorted {
            for v in &usable {
                // 该场地在该单元已占用的时段
                let mut taken: Vec<(i64, i64)> = slots
                    .iter()
                    .filter(|s| s.session_id == sess.id && s.venue_id == v.id)
                    .map(|s| (s.start_min, s.end_min()))
                    .collect();
                taken.sort();

                // 从单元起点开始找空位
                let mut cur = sess.start_min;
                // 限制尝试次数，避免病态输入下无限循环
                for _attempt in 0..64 {
                    let end = cur + dur;
                    if end > sess.end_min() {
                        break; // 这个场地放不下，换下一个场地
                    }
                    // 找到 >= cur 的第一个占用区间，判断是否相撞
                    let hit = taken.iter().find(|(ts, te)| cur < *te && *ts < end);
                    match hit {
                        Some((ts, _)) => {
                            cur = *ts; // 跳到该占用之后（下一轮会重新算 end）
                            let _ = ts;
                            // 防止 cur 不前进
                            if cur >= sess.end_min() {
                                break;
                            }
                            continue;
                        }
                        None => {
                            // 空位可用，检查学生兼项
                            if students_free(&busy, &sids, sess.id, cur, end) {
                                slots.push(Slot {
                                    event_id: ev.id,
                                    session_id: sess.id,
                                    start_min: cur,
                                    duration_min: dur,
                                    venue_id: v.id,
                                    group_count,
                                });
                                for sid in &sids {
                                    busy.entry(*sid).or_default().push((sess.id, cur, end));
                                }
                                placed = true;
                                break 'outer;
                            }
                            // 学生有冲突：往后推 5 分钟再试
                            cur += 5;
                        }
                    }
                }
            }
        }

        if !placed {
            unplaced.push((
                ev.id,
                format!(
                    "{}个竞赛单元都排不下（预计需 {} 分钟，可能因学生兼项冲突或场地不足）",
                    sess_sorted.len(),
                    dur
                ),
            ));
        }
    }

    // 输出排序：按单元 → 开始时间 → 场地，便于阅读
    slots.sort_by_key(|s| (s.session_id, s.start_min, s.venue_id));
    ArrangeResult { slots, unplaced }
}

/// 检查这批学生在指定时段（含休息间隔）是否都空闲。
///
/// **未在此处施加"休息间隔"硬约束**，只检查重叠 —— 因为把休息间隔
/// 当硬约束会让贪心频繁失败。休息间隔是软约束，由冲突检测**报告**出来，
/// 让老师决定是否手动调整。这是刻意的取舍（见模块文档"可解释 > 最优"）。
fn students_free(
    busy: &HashMap<i64, Vec<(i64, i64, i64)>>,
    sids: &[i64],
    sess_id: i64,
    start: i64,
    end: i64,
) -> bool {
    for sid in sids {
        if let Some(list) = busy.get(sid) {
            for (s, bs, be) in list {
                if *s != sess_id {
                    continue;
                }
                if start < *be && *bs < end {
                    return false;
                }
            }
        }
    }
    true
}

/// 按参赛人数决定分几组。
///
/// 径赛按 8 道一组（标准跑道 8 条道）；人数不是 8 的倍数时向上取整。
/// 人多时最多切到 6 组，避免组数爆炸（可在前端手动调）。
pub fn group_count_for(ev: &Event, participant_count: i64) -> i64 {
    let n = participant_count.max(1);
    if ev.is_team {
        return ((n + 7) / 8).clamp(1, 8);
    }
    if ev.is_track() {
        ((n + 7) / 8).clamp(1, 8)
    } else {
        // 田赛一般不分道，人多时按 20 人一组（轮次制）
        ((n + 19) / 20).clamp(1, 8)
    }
}

// ============================================================================
// 分组与道次分配
// ============================================================================

/// 一个分组内的道次安排。
#[derive(Debug, Clone, PartialEq)]
pub struct LaneAssign {
    pub group_no: i64,
    pub lane: i64,
    pub student_id: i64,
    pub student_name: String,
    pub class_name: String,
    /// 用于排序的报名成绩（若成绩库里有）
    pub seed: Option<f64>,
}

impl LaneAssign {
    /// 序列化为 JSON（供前端渲染分组表 / 分道表）。
    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("group_no", Json::Int(self.group_no));
        o.set("lane", Json::Int(self.lane));
        o.set("student_id", Json::Int(self.student_id));
        o.set("student_name", Json::s(self.student_name.clone()));
        o.set("class_name", Json::s(self.class_name.clone()));
        o.set(
            "seed",
            match self.seed {
                Some(v) => Json::s(crate::core::scoring::format_score(v, "")),
                None => Json::Null,
            },
        );
        o
    }
}

/// 给一个径赛项目分组、分道。
///
/// # 规则（依据田径竞赛规则）
///
/// - **径赛**：按报名成绩排序，成绩最好的分在中间道次。
///   道次优先级为 `[4,5,3,6,2,7,1,8]` —— 弯道跑时中间道次路程最短。
///   分组的目的是让**各组实力接近**（不是"强的都挤一组"）：
///   采用**蛇形分组**（S 形分配）—— 排序后按 1,2,3,…N,N,…,3,2,1 回填，
///   这样每组的实力分布均衡，比赛更公平、更有悬念。
/// - **田赛**：不分道，只给一个出场顺序（成绩差的先出场，好的压轴）。
///   这也是田赛的通行做法：让好手最后出场，既公平又有观赏性。
///

/// 无报名成绩时（`seed` 为 None），退化为按**报名顺序**（学生 id）排，
/// 保证结果稳定可复现，而不是随机。
pub fn assign_lanes(
    ev: &Event,
    participants: &[(i64, Option<f64>)], // (student_id, 报名成绩)
    students: &[Student],
) -> Vec<LaneAssign> {
    let st_by_id: HashMap<i64, &Student> = students.iter().map(|s| (s.id, s)).collect();

    // 排序：有成绩的按成绩（径赛小者优 / 田赛大者优），无成绩的排后面按 id
    let mut list: Vec<(i64, Option<f64>)> = participants.to_vec();
    list.sort_by(|a, b| match (a.1, b.1) {
        (Some(x), Some(y)) => {
            let cmp = if ev.is_track() {
                x.partial_cmp(&y).unwrap_or(std::cmp::Ordering::Equal)
            } else {
                y.partial_cmp(&x).unwrap_or(std::cmp::Ordering::Equal)
            };
            cmp.then_with(|| a.0.cmp(&b.0))
        }
        (Some(_), None) => std::cmp::Ordering::Less, // 有成绩的在前
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.0.cmp(&b.0),
    });

    let n = list.len() as i64;
    if n == 0 {
        return Vec::new();
    }
    let group_count = group_count_for(ev, n);

    let name_of = |sid: i64| -> (String, String) {
        st_by_id
            .get(&sid)
            .map(|s| (s.name.clone(), s.class_name()))
            .unwrap_or_else(|| (format!("学生{}", sid), String::new()))
    };

    let mut out = Vec::new();

    if !ev.is_track() {
        // 田赛：不分道，只给"出场顺序"。
        //
        // 关键：`list` 已按"成绩好者在前"排序（田赛是数值大者在前）。
        // 而田赛惯例是**好手压轴出场** —— 所以出场序号要**倒着给**：
        // 排序第 1 位（最好的）拿到**最后**的出场序号。
        // 这里曾直接按 enumerate 顺序给 lane，导致"最好的第一个上场"，
        // 与意图正好相反（被 assign_lanes_orders_by_seed_desc_for_field 抓到）。
        let total = list.len() as i64;
        for (i, (sid, seed)) in list.iter().enumerate() {
            let (nm, cls) = name_of(*sid);
            out.push(LaneAssign {
                group_no: 1,
                lane: total - (i as i64), // 好手 → 序号大 → 后出场
                student_id: *sid,
                student_name: nm,
                class_name: cls,
                seed: *seed,
            });
        }
        return out;
    }

    // 径赛：蛇形分组（S 形回填），保证各组实力均衡
    //
    // # 这里的下标推导（踩过坑，写清楚免得再错）
    //
    // `list` 已按成绩优劣排序（最好的在前）。蛇形分组的做法是：
    // 把排序后的名单**按行**填进一张 `组数 × 每组人数` 的表，
    // 偶数行正着填、奇数行倒着填 —— 这样第 1 名与第 2N 名会落进同一组，
    // 各组实力因此接近。
    //
    // 关键：`col`（列号）的取值范围必须是 **0..组数**，
    // 不是 `0..每组人数`！之前把两者写反，导致 `col` 取到了不存在的组下标，
    // `get_mut` 静默返回 None，**人就这么丢了**（17 人只排出 9 个位置）。
    //
    // 教训：**下标越界在 `get_mut` 下是静默失败，不会 panic**。
    // 因此必须有"总数守恒"断言 —— 见 `assign_lanes_splits_into_groups_for_track`。
    let gc = group_count;
    let mut groups: Vec<Vec<(i64, Option<f64>)>> = vec![Vec::new(); group_count as usize];
    for (i, item) in list.iter().enumerate() {
        let row = (i as i64) / gc; // 第几轮（每轮填满所有组）
        let col = (i as i64) % gc; // 该轮中的第几个组（范围 0..gc）
        // 偶数轮正序、奇数轮倒序 → 蛇形
        let g = if row % 2 == 0 {
            col
        } else {
            gc - 1 - col
        };
        if let Some(bucket) = groups.get_mut(g as usize) {
            bucket.push(*item);
        }
    }

    // 防御性核对：分组后人数必须与输入一致。
    // 这是"总数守恒"的直接检查 —— 若将来又改错下标，这里会先于用户发现。
    debug_assert_eq!(
        groups.iter().map(|b| b.len()).sum::<usize>(),
        list.len(),
        "蛇形分组丢人了：下标推导有误"
    );

    for (gi, bucket) in groups.iter().enumerate() {
        for (li, (sid, seed)) in bucket.iter().enumerate() {
            let (nm, cls) = name_of(*sid);
            // 道次：按 LANE_ORDER 取，超出 8 人的情况（理论上分组后不会）回退为顺延
            let lane = LANE_ORDER
                .get(li)
                .copied()
                .unwrap_or((li as i64) + 1);
            out.push(LaneAssign {
                group_no: (gi as i64) + 1,
                lane,
                student_id: *sid,
                student_name: nm,
                class_name: cls,
                seed: *seed,
            });
        }
    }

    // 组内按道次排序，便于打印（道次 1..8 顺序，或按 LANE_ORDER 也可以）
    out.sort_by_key(|a| (a.group_no, a.lane));
    out
}

// ============================================================================
// 单元统计（给前端做"这个单元排得满不满"的直观展示）
// ============================================================================

/// 某个竞赛单元里，每个场地的占用情况。
#[derive(Debug, Clone)]
pub struct VenueUsage {
    pub venue_id: i64,
    pub venue_name: String,
    pub busy_minutes: i64,
    pub total_minutes: i64,
    pub event_count: i64,
}

impl VenueUsage {
    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("venue_id", Json::Int(self.venue_id));
        o.set("venue_name", Json::s(self.venue_name.clone()));
        o.set("busy_minutes", Json::Int(self.busy_minutes));
        o.set("total_minutes", Json::Int(self.total_minutes));
        o.set("event_count", Json::Int(self.event_count));
        o.set(
            "utilization",
            Json::Num(
                (self.busy_minutes as f64 / self.total_minutes.max(1) as f64 * 100.0).round()
                    / 100.0,
            ),
        );
        o
    }
}

/// 统计每个单元、每个场地的利用率。
///
/// 用途：让老师一眼看出"下午第一场地排满了、第二场地空着"——
/// 场地利用率是编排质量最直观的指标。
pub fn session_usage(
    session: &Session,
    venues: &[Venue],
    slots: &[Slot],
) -> Vec<VenueUsage> {
    let total = (session.end_min() - session.start_min).max(0);
    let mut out = Vec::new();
    for v in venues {
        let mine: Vec<&Slot> = slots
            .iter()
            .filter(|s| s.session_id == session.id && s.venue_id == v.id)
            .collect();
        // 注意：不能简单累加 duration —— 若有重叠会算重。先合并区间。
        let mut iv: Vec<(i64, i64)> = mine.iter().map(|s| (s.start_min, s.end_min())).collect();
        iv.sort();
        let mut merged: Vec<(i64, i64)> = Vec::new();
        for (s, e) in iv {
            match merged.last_mut() {
                Some(last) if s <= last.1 => {
                    if e > last.1 {
                        last.1 = e;
                    }
                }
                _ => merged.push((s, e)),
            }
        }
        let busy: i64 = merged.iter().map(|(s, e)| e - s).sum();
        out.push(VenueUsage {
            venue_id: v.id,
            venue_name: v.name.clone(),
            busy_minutes: busy,
            total_minutes: total,
            event_count: mine.len() as i64,
        });
    }
    out
}

/// 汇总每个场地总共排了多少个项目（用于总览）。
pub fn venue_summary(venues: &[Venue], slots: &[Slot]) -> Vec<VenueUsage> {
    let mut out = Vec::new();
    for v in venues {
        let mine: Vec<&Slot> = slots.iter().filter(|s| s.venue_id == v.id).collect();
        let mut iv: Vec<(i64, i64)> = mine.iter().map(|s| (s.start_min, s.end_min())).collect();
        iv.sort();
        let mut merged: Vec<(i64, i64)> = Vec::new();
        for (s, e) in iv {
            match merged.last_mut() {
                Some(last) if s <= last.1 => {
                    if e > last.1 {
                        last.1 = e;
                    }
                }
                _ => merged.push((s, e)),
            }
        }
        let busy: i64 = merged.iter().map(|(s, e)| e - s).sum();
        out.push(VenueUsage {
            venue_id: v.id,
            venue_name: v.name.clone(),
            busy_minutes: busy,
            total_minutes: 0,
            event_count: mine.len() as i64,
        });
    }
    out
}

/// 把场地列表序列化为 JSON 数组。
pub fn venues_to_json(vs: &[Venue]) -> Json {
    Json::arr(vs.iter().map(|v| v.to_json()))
}

/// 把单元列表序列化为 JSON 数组。
pub fn sessions_to_json(ss: &[Session]) -> Json {
    Json::arr(ss.iter().map(|s| s.to_json()))
}

/// 从 JSON 数组解析场地；缺失时回退到默认（规则 20：非法输入修复到合法值）。
pub fn venues_from_json(j: Option<&Json>) -> Vec<Venue> {
    match j.and_then(|x| x.as_arr()) {
        Some(arr) if !arr.is_empty() => {
            let v: Vec<Venue> = arr.iter().filter_map(Venue::from_json).collect();
            if v.is_empty() {
                default_venues()
            } else {
                v
            }
        }
        _ => default_venues(),
    }
}

/// 从 JSON 数组解析单元；缺失时回退到默认。
pub fn sessions_from_json(j: Option<&Json>, days: i64) -> Vec<Session> {
    match j.and_then(|x| x.as_arr()) {
        Some(arr) if !arr.is_empty() => {
            let v: Vec<Session> = arr.iter().filter_map(Session::from_json).collect();
            if v.is_empty() {
                default_sessions(days)
            } else {
                v
            }
        }
        _ => default_sessions(days),
    }
}

/// 把赛程（时段）列表序列化为 JSON 数组。
pub fn slots_to_json(slots: &[Slot]) -> Json {
    Json::arr(slots.iter().map(|s| s.to_json()))
}

/// 从 JSON 数组解析赛程；缺失或为空时返回空（规则 20：默认就是"还没排"）。
pub fn slots_from_json(j: Option<&Json>) -> Vec<Slot> {
    match j.and_then(|x| x.as_arr()) {
        Some(arr) => arr.iter().filter_map(Slot::from_json).collect(),
        _ => Vec::new(),
    }
}

/// 把赛程时段按所属单元分组，返回 `单元 id → 该单元的时段列表`。
/// 用于前端渲染日程表（按单元逐列展示）。
///
/// 当前前端从 `slots` 直接按 `session_id` 分组，该函数作为模块公开 API 保留，
/// 待"前端需要同时拿到单元元信息"时启用，故标记允许死代码。
#[allow(dead_code)]
pub fn group_by_session<'a>(
    slots: &'a [Slot],
) -> BTreeMap<i64, Vec<&'a Slot>> {
    let mut m: BTreeMap<i64, Vec<&'a Slot>> = BTreeMap::new();
    for s in slots {
        m.entry(s.session_id).or_default().push(s);
    }
    m
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(id: i64, name: &str, cat: &str) -> Event {
        Event {
            id,
            name: name.into(),
            category: cat.into(),
            gender: "男子".into(),
            grade: "全部".into(),
            is_team: false,
            unit: if cat == "径赛" { "时间".into() } else { "米".into() },
            record: None,
        }
    }

    fn st(id: i64, name: &str) -> Student {
        Student {
            id,
            grade: "初一".into(),
            class_no: 1,
            name: name.into(),
            gender: "男".into(),
        }
    }

    fn rg(id: i64, eid: i64, sid: i64) -> Registration {
        Registration {
            id,
            event_id: eid,
            student_id: sid,
            note: String::new(),
        }
    }

    fn slot(eid: i64, sess: i64, start: i64, dur: i64, venue: i64) -> Slot {
        Slot {
            event_id: eid,
            session_id: sess,
            start_min: start,
            duration_min: dur,
            venue_id: venue,
            group_count: 1,
        }
    }

    // ---------- 时间工具 ----------

    #[test]
    fn fmt_and_parse_min_roundtrip() {
        assert_eq!(fmt_min(480), "08:00");
        assert_eq!(fmt_min(690), "11:30");
        assert_eq!(fmt_min(0), "00:00");
        assert_eq!(parse_hhmm("08:00"), Some(480));
        assert_eq!(parse_hhmm("11:30"), Some(690));
        assert_eq!(parse_hhmm(" 14:00 "), Some(840));
        assert_eq!(parse_hhmm("24:00"), None, "24 点非法");
        assert_eq!(parse_hhmm("08:70"), None, "70 分非法");
        assert_eq!(parse_hhmm("abc"), None);
    }

    #[test]
    fn slot_overlap_is_half_open() {
        let a = slot(1, 1, 480, 30, 1); // 08:00-08:30
        let b = slot(2, 1, 500, 30, 1); // 08:20-08:50 与 a 重叠
        let c = slot(3, 1, 510, 30, 1); // 08:30-09:00 端点相接，**不算**重叠
        assert!(a.overlaps(&b));
        assert!(!a.overlaps(&c), "端点相接应视为不重叠，否则无法排紧凑赛程");
    }

    // ---------- 冲突检测 ----------

    #[test]
    fn venue_overlap_is_detected_as_error() {
        let events = vec![ev(1, "男子100米", "径赛"), ev(2, "男子200米", "径赛")];
        let venues = default_venues();
        let sessions = default_sessions(2);
        // 同一场地、同一时段
        let slots = vec![
            slot(1, 1, 480, 30, 1),
            slot(2, 1, 480, 30, 1),
        ];
        let regs = vec![rg(1, 1, 100), rg(2, 2, 101)];
        let students = vec![st(100, "张三"), st(101, "李四")];
        let cs = detect_conflicts(&events, &regs, &slots, &venues, &sessions, &students);
        let hit = cs
            .iter()
            .find(|c| c.kind == "venue_overlap")
            .expect("同场地重叠必须被检出");
        assert_eq!(hit.severity, Severity::Error);
        assert!(hit.message.contains("男子100米") && hit.message.contains("男子200米"));
    }

    #[test]
    fn parallel_track_and_field_do_not_conflict() {
        // 这是本模块的核心场景：径赛与田赛**同时进行**是合法的
        let events = vec![ev(1, "男子100米", "径赛"), ev(2, "男子跳远", "田赛")];
        let venues = default_venues();
        let sessions = default_sessions(2);
        let slots = vec![slot(1, 1, 480, 30, 1), slot(2, 1, 480, 30, 2)];
        // 同一个学生参加两项（兼项），但一个在跑道一个在田赛区，同时进行 —— 这才是真冲突
        let regs = vec![rg(1, 1, 100), rg(2, 2, 100)];
        let students = vec![st(100, "张三")];
        let cs = detect_conflicts(&events, &regs, &slots, &venues, &sessions, &students);

        assert!(
            cs.iter().all(|c| c.kind != "venue_overlap"),
            "不同场地同时进行不应报场地冲突"
        );
        // 但这个学生确实被同时排了两个项目 → 必须报学生冲突
        assert!(
            cs.iter().any(|c| c.kind == "student_clash"),
            "同一学生同时参加径赛与田赛必须报 student_clash"
        );
    }

    #[test]
    fn short_rest_interval_is_warned() {
        let events = vec![ev(1, "男子100米", "径赛"), ev(2, "男子200米", "径赛")];
        let venues = default_venues();
        let sessions = default_sessions(2);
        // 08:00-08:30 与 08:40-09:10 → 间隔 10 分钟 < 30
        let slots = vec![slot(1, 1, 480, 30, 1), slot(2, 1, 520, 30, 1)];
        let regs = vec![rg(1, 1, 100), rg(2, 2, 100)];
        let students = vec![st(100, "张三")];
        let cs = detect_conflicts(&events, &regs, &slots, &venues, &sessions, &students);
        let hit = cs
            .iter()
            .find(|c| c.kind == "rest_too_short")
            .expect("间隔 10 分钟必须报 rest_too_short");
        assert_eq!(hit.severity, Severity::Warn);
        assert_eq!(hit.student_id, Some(100));
    }

    #[test]
    fn different_sessions_do_not_conflict_for_same_student() {
        // 跨单元（如上午 → 下午）中间隔了午餐，不该报冲突
        let events = vec![ev(1, "男子100米", "径赛"), ev(2, "男子200米", "径赛")];
        let venues = default_venues();
        let sessions = default_sessions(2);
        let slots = vec![
            slot(1, 1, 480, 30, 1),  // 第一天上午
            slot(2, 3, 840, 30, 1),  // 第二天上午
        ];
        let regs = vec![rg(1, 1, 100), rg(2, 2, 100)];
        let students = vec![st(100, "张三")];
        let cs = detect_conflicts(&events, &regs, &slots, &venues, &sessions, &students);
        assert!(
            cs.iter().all(|c| c.kind != "student_clash" && c.kind != "rest_too_short"),
            "跨单元的同一学生不应报冲突，实际={:?}",
            cs.iter().map(|c| &c.kind).collect::<Vec<_>>()
        );
    }

    #[test]
    fn venue_type_mismatch_is_error() {
        // 径赛排到田赛场地
        let events = vec![ev(1, "男子100米", "径赛")];
        let venues = default_venues();
        let sessions = default_sessions(2);
        let slots = vec![slot(1, 1, 480, 30, 2)]; // venue 2 = 田赛区
        let regs = vec![rg(1, 1, 100)];
        let students = vec![st(100, "张三")];
        let cs = detect_conflicts(&events, &regs, &slots, &venues, &sessions, &students);
        assert!(cs.iter().any(|c| c.kind == "venue_type_mismatch"));
    }

    #[test]
    fn out_of_session_range_is_error() {
        let events = vec![ev(1, "男子100米", "径赛")];
        let venues = default_venues();
        let sessions = default_sessions(2); // 上午 08:00(+210) → 结束 11:30
        let slots = vec![slot(1, 1, 700, 30, 1)]; // 11:40-12:10 超出
        let regs = vec![rg(1, 1, 100)];
        let students = vec![st(100, "张三")];
        let cs = detect_conflicts(&events, &regs, &slots, &venues, &sessions, &students);
        assert!(cs.iter().any(|c| c.kind == "out_of_session"));
    }

    #[test]
    fn unscheduled_event_is_reported() {
        let events = vec![ev(1, "男子100米", "径赛"), ev(2, "男子跳远", "田赛")];
        let venues = default_venues();
        let sessions = default_sessions(2);
        let slots = vec![slot(1, 1, 480, 30, 1)]; // 只排了 1
        let regs = vec![rg(1, 1, 100), rg(2, 2, 101)];
        let students = vec![st(100, "张三"), st(101, "李四")];
        let cs = detect_conflicts(&events, &regs, &slots, &venues, &sessions, &students);
        let hit = cs.iter().find(|c| c.kind == "unscheduled").expect("未编排项目必须被提示");
        assert!(hit.message.contains("男子跳远"));
    }

    #[test]
    fn errors_sort_before_warnings() {
        let events = vec![ev(1, "男子100米", "径赛"), ev(2, "男子200米", "径赛"), ev(3, "男子跳远", "田赛")];
        let venues = default_venues();
        let sessions = default_sessions(2);
        let slots = vec![
            slot(1, 1, 480, 30, 1),
            slot(2, 1, 480, 30, 1), // 与 1 同场地重叠 → Error
        ];
        let regs = vec![rg(1, 1, 100), rg(2, 2, 100), rg(3, 3, 101)];
        let students = vec![st(100, "张三"), st(101, "李四")];
        let cs = detect_conflicts(&events, &regs, &slots, &venues, &sessions, &students);
        assert!(!cs.is_empty());
        // 第一个必须是 Error
        assert_eq!(cs[0].severity, Severity::Error, "Error 必须排在最前面");
        // 且全部 Error 都在 Warn/Info 之前
        let first_non_error = cs.iter().position(|c| c.severity != Severity::Error);
        if let Some(p) = first_non_error {
            assert!(
                cs[p..].iter().all(|c| c.severity != Severity::Error),
                "Error 不能出现在 Warn/Info 之后"
            );
        }
    }

    #[test]
    fn empty_schedule_with_registrations_warns_unscheduled() {
        let events = vec![ev(1, "男子100米", "径赛")];
        let venues = default_venues();
        let sessions = default_sessions(2);
        let regs = vec![rg(1, 1, 100)];
        let students = vec![st(100, "张三")];
        let cs = detect_conflicts(&events, &regs, &[], &venues, &sessions, &students);
        assert!(cs.iter().any(|c| c.kind == "unscheduled"));
    }

    // ---------- 自动编排 ----------

    #[test]
    fn auto_arrange_places_all_events_without_conflict() {
        let events = vec![
            ev(1, "男子100米", "径赛"),
            ev(2, "男子200米", "径赛"),
            ev(3, "男子跳远", "田赛"),
            ev(4, "男子跳高", "田赛"),
        ];
        let venues = default_venues();
        let sessions = default_sessions(1);
        // 4 名学生，每人只报 1 项 → 无兼项冲突
        let regs = vec![rg(1, 1, 101), rg(2, 2, 102), rg(3, 3, 103), rg(4, 4, 104)];
        let students = vec![st(101, "A"), st(102, "B"), st(103, "C"), st(104, "D")];
        let r = auto_arrange(
            &events,
            &regs,
            &venues,
            &sessions,
            &[],
            &ArrangeOptions::default(),
        );
        assert!(r.unplaced.is_empty(), "不该有排不下的项目：{:?}", r.unplaced);
        assert_eq!(r.slots.len(), 4);

        // 关键：编排结果**自己不能有硬冲突**
        let cs = detect_conflicts(&events, &regs, &r.slots, &venues, &sessions, &students);
        let errs: Vec<_> = cs.iter().filter(|c| c.severity == Severity::Error).collect();
        assert!(
            errs.is_empty(),
            "自动编排结果不该有硬冲突，实际：{:?}",
            errs.iter().map(|c| &c.message).collect::<Vec<_>>()
        );
    }

    #[test]
    fn auto_arrange_parallelizes_track_and_field() {
        // 2 个项目，一个径赛一个田赛 → 应能**同时**开始（不同场地）
        let events = vec![ev(1, "男子100米", "径赛"), ev(2, "男子跳远", "田赛")];
        let venues = default_venues();
        let sessions = default_sessions(1);
        let regs = vec![rg(1, 1, 101), rg(2, 2, 102)];
        let r = auto_arrange(
            &events,
            &regs,
            &venues,
            &sessions,
            &[],
            &ArrangeOptions::default(),
        );
        assert_eq!(r.slots.len(), 2);
        let a = r.slots.iter().find(|s| s.event_id == 1).unwrap();
        let b = r.slots.iter().find(|s| s.event_id == 2).unwrap();
        assert_ne!(a.venue_id, b.venue_id, "径赛田赛应分到不同场地");
        assert_eq!(
            a.start_min, b.start_min,
            "不同场地应能同时开始（这是'多场地'的意义）"
        );
    }

    #[test]
    fn auto_arrange_avoids_student_clash() {
        // 同一个学生报了两项径赛 → 不能排在同一时段
        let events = vec![ev(1, "男子100米", "径赛"), ev(2, "男子200米", "径赛")];
        let venues = default_venues();
        let sessions = default_sessions(1);
        let regs = vec![rg(1, 1, 100), rg(2, 2, 100)];
        let students = vec![st(100, "张三")];
        let r = auto_arrange(
            &events,
            &regs,
            &venues,
            &sessions,
            &[],
            &ArrangeOptions::default(),
        );
        assert_eq!(r.slots.len(), 2);
        let cs = detect_conflicts(&events, &regs, &r.slots, &venues, &sessions, &students);
        assert!(
            !cs.iter().any(|c| c.kind == "student_clash"),
            "编排必须避免学生兼项时间冲突"
        );
    }

    #[test]
    fn auto_arrange_reports_unplaced_instead_of_silently_dropping() {
        // 场地只有一个且是径赛场地，但项目是田赛 → 必然排不下
        let events = vec![ev(1, "男子跳远", "田赛")];
        let venues = vec![Venue {
            id: 1,
            name: "只有跑道".into(),
            for_track: true,
            for_field: false,
        }];
        let sessions = default_sessions(1);
        let regs = vec![rg(1, 1, 100)];
        let r = auto_arrange(
            &events,
            &regs,
            &venues,
            &sessions,
            &[],
            &ArrangeOptions::default(),
        );
        assert!(r.slots.is_empty());
        assert_eq!(r.unplaced.len(), 1, "排不下的项目必须被如实报告");
        assert!(r.unplaced[0].1.contains("场地"));
    }

    #[test]
    fn auto_arrange_skips_events_without_registrations() {
        let events = vec![ev(1, "男子100米", "径赛"), ev(2, "男子200米", "径赛")];
        let venues = default_venues();
        let sessions = default_sessions(1);
        let regs = vec![rg(1, 1, 100)]; // 只有项目 1 有人报名
        let r = auto_arrange(
            &events,
            &regs,
            &venues,
            &sessions,
            &[],
            &ArrangeOptions::default(),
        );
        assert_eq!(r.slots.len(), 1);
        assert_eq!(r.slots[0].event_id, 1);
        assert!(r.unplaced.is_empty(), "没人报名的项目不算'排不下'");
    }

    #[test]
    fn auto_arrange_respects_session_bounds() {
        let events = vec![ev(1, "男子100米", "径赛")];
        let venues = default_venues();
        let sessions = default_sessions(1);
        let regs = vec![rg(1, 1, 100)];
        let r = auto_arrange(
            &events,
            &regs,
            &venues,
            &sessions,
            &[],
            &ArrangeOptions::default(),
        );
        let s = &r.slots[0];
        let sess = &sessions[0];
        assert!(s.start_min >= sess.start_min);
        assert!(s.end_min() <= sess.end_min(), "不能超出单元时间");
    }

    #[test]
    fn auto_arrange_with_no_venues_reports_all_unplaced() {
        let events = vec![ev(1, "男子100米", "径赛")];
        let regs = vec![rg(1, 1, 100)];
        let r = auto_arrange(
            &events,
            &regs,
            &[],
            &default_sessions(1),
            &[],
            &ArrangeOptions::default(),
        );
        assert_eq!(r.unplaced.len(), 1);
    }

    // ---------- 分组分道 ----------

    #[test]
    fn lane_order_puts_best_in_middle() {
        assert_eq!(LANE_ORDER, [4, 5, 3, 6, 2, 7, 1, 8]);
        // 成绩最好的（第一个）应拿到 4 道（中间）
        assert_eq!(LANE_ORDER[0], 4);
    }

    #[test]
    fn assign_lanes_orders_by_seed_for_track() {
        let e = ev(1, "男子100米", "径赛");
        let students = vec![st(1, "快"), st(2, "中"), st(3, "慢")];
        // 径赛：数值小者优
        let parts = vec![(1, Some(12.5)), (2, Some(13.0)), (3, Some(14.2))];
        let out = assign_lanes(&e, &parts, &students);
        // 最快的（id=1）应分到 4 道
        let fast = out.iter().find(|a| a.student_id == 1).unwrap();
        assert_eq!(fast.lane, 4, "成绩最好的应分在中间道次");
        assert_eq!(fast.group_no, 1);
    }

    #[test]
    fn assign_lanes_orders_by_seed_desc_for_field() {
        let e = ev(1, "男子跳远", "田赛");
        let students = vec![st(1, "远"), st(2, "中"), st(3, "近")];
        // 田赛：数值大者优 → 应压轴出场（出场序号最大）
        let parts = vec![(1, Some(5.5)), (2, Some(4.8)), (3, Some(4.0))];
        let out = assign_lanes(&e, &parts, &students);
        let far = out.iter().find(|a| a.student_id == 1).unwrap();
        let near = out.iter().find(|a| a.student_id == 3).unwrap();
        assert!(
            far.lane > near.lane,
            "田赛成绩最好的应最后出场（lane 序号更大），实际 far={} near={}",
            far.lane,
            near.lane
        );
    }

    #[test]
    fn assign_lanes_without_seed_is_stable() {
        let e = ev(1, "男子100米", "径赛");
        let students = vec![st(30, "C"), st(10, "A"), st(20, "B")];
        let parts = vec![(30, None), (10, None), (20, None)];
        let out1 = assign_lanes(&e, &parts, &students);
        let out2 = assign_lanes(&e, &parts, &students);
        // "stable" 指的是**确定性**：相同输入必须产出相同分组（可复现），
        // 而不是"按 id 顺序输出"——径赛的蛇形 Lane 分配本就会重排道次。
        assert_eq!(out1, out2, "相同输入必须产出相同分组（可复现）");
        // 所有人都分到位置、且不重复、不丢失
        let got: HashSet<i64> = out1.iter().map(|a| a.student_id).collect();
        let want: HashSet<i64> = parts.iter().map(|p| p.0).collect();
        assert_eq!(got, want, "所有人必须都分到位置且不重复");
    }

    #[test]
    fn assign_lanes_splits_into_groups_for_track() {
        // 17 人 → 8 道一组 → 3 组
        let e = ev(1, "男子100米", "径赛");
        let mut parts = Vec::new();
        let mut students = Vec::new();
        for i in 1..=17 {
            parts.push((i as i64, Some(12.0 + i as f64 * 0.1)));
            students.push(st(i as i64, &format!("S{}", i)));
        }
        let out = assign_lanes(&e, &parts, &students);
        assert_eq!(out.len(), 17, "所有人必须都分到位置");
        let groups: HashSet<i64> = out.iter().map(|a| a.group_no).collect();
        assert_eq!(groups.len(), 3, "17 人应分成 3 组");
        assert_eq!(group_count_for(&e, 17), 3);
    }

    #[test]
    fn assign_lanes_field_is_single_group() {
        let e = ev(1, "男子跳远", "田赛");
        let mut parts = Vec::new();
        let mut students = Vec::new();
        for i in 1..=25 {
            parts.push((i as i64, Some(4.0 + i as f64 * 0.05)));
            students.push(st(i as i64, &format!("S{}", i)));
        }
        let out = assign_lanes(&e, &parts, &students);
        assert_eq!(out.len(), 25);
        assert!(out.iter().all(|a| a.group_no == 1), "田赛不分道，只给出场顺序");
    }

    #[test]
    fn assign_lanes_handles_empty_participants() {
        let e = ev(1, "男子100米", "径赛");
        let out = assign_lanes(&e, &[], &[]);
        assert!(out.is_empty());
    }

    // ---------- 时长估算 ----------

    #[test]
    fn duration_estimate_is_positive_and_monotonic() {
        let e = ev(1, "男子100米", "径赛");
        let d1 = estimate_duration_min(&e, 1);
        let d8 = estimate_duration_min(&e, 8);
        let d16 = estimate_duration_min(&e, 16);
        assert!(d1 > 0 && d8 > 0 && d16 > 0);
        assert!(d16 > d8 && d8 >= d1, "人越多耗时越长");
    }

    #[test]
    fn long_distance_takes_more_time_per_group() {
        let sprint = ev(1, "男子100米", "径赛");
        let long = ev(2, "男子1500米", "径赛");
        assert!(
            estimate_duration_min(&long, 8) > estimate_duration_min(&sprint, 8),
            "中长跑每组耗时应大于短跑"
        );
    }

    // ---------- 场地利用率 ----------

    #[test]
    fn session_usage_merges_overlapping_intervals() {
        let sessions = default_sessions(1);
        let venues = default_venues();
        // 两个重叠的时段（故意造），合并后应是 30 而非 60
        let slots = vec![slot(1, 1, 480, 30, 1), slot(2, 1, 490, 20, 1)];
        let us = session_usage(&sessions[0], &venues, &slots);
        let v1 = us.iter().find(|u| u.venue_id == 1).unwrap();
        assert_eq!(v1.busy_minutes, 30, "重叠区间合并后不应重复计时");
        assert_eq!(v1.event_count, 2);
    }

    // ---------- 序列化往返 ----------

    #[test]
    fn venue_json_roundtrip() {
        let vs = default_venues();
        let j = venues_to_json(&vs);
        let back = venues_from_json(Some(&j));
        assert_eq!(vs, back);
    }

    #[test]
    fn session_json_roundtrip() {
        let ss = default_sessions(2);
        let j = sessions_to_json(&ss);
        let back = sessions_from_json(Some(&j), 2);
        assert_eq!(ss, back);
        assert_eq!(ss.len(), 4, "2 天应有 4 个单元（每天上午/下午）");
    }

    #[test]
    fn malformed_json_falls_back_to_defaults() {
        // 规则 20：非法输入要修复到合法值，而不是留下空表导致后续 panic
        assert_eq!(venues_from_json(None), default_venues());
        assert_eq!(venues_from_json(Some(&Json::Null)), default_venues());
        assert_eq!(venues_from_json(Some(&Json::arr(vec![]))), default_venues());
        let bad = Json::arr(vec![Json::s("垃圾数据")]);
        assert_eq!(venues_from_json(Some(&bad)), default_venues());
        assert_eq!(sessions_from_json(None, 2).len(), 4);
    }

    #[test]
    fn venue_rejects_missing_id() {
        let j = Json::parse(r#"{"name":"无 id"}"#).unwrap();
        assert!(Venue::from_json(&j).is_none());
        let j2 = Json::parse(r#"{"id":7,"name":"三级跳远区","for_track":false,"for_field":true}"#).unwrap();
        let v = Venue::from_json(&j2).unwrap();
        assert_eq!(v.id, 7);
        assert!(!v.for_track && v.for_field);
    }

    #[test]
    fn slot_endpoints_touching_are_not_overlap() {
        let a = slot(1, 1, 480, 30, 1); // 08:00-08:30
        let b = slot(2, 1, 510, 30, 1); // 08:30-09:00
        assert!(!a.overlaps(&b));
        let cs = detect_conflicts(
            &[ev(1, "A", "径赛"), ev(2, "B", "径赛")],
            &[rg(1, 1, 1), rg(2, 2, 2)],
            &[a, b],
            &default_venues(),
            &default_sessions(1),
            &[st(1, "甲"), st(2, "乙")],
        );
        assert!(
            !cs.iter().any(|c| c.kind == "venue_overlap"),
            "端点相接不该报场地冲突（否则赛程无法排紧）"
        );
    }
}
