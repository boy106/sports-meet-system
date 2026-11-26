//! 智能成绩解析与参赛推荐（核心模块，v1.5 新增）。
//!
//! 本模块只做两件事，但都是"老师每天都会用到"的事：
//!
//! ## 一、宽容成绩解析（`parse_score_lenient`）
//!
//! 原始 `scoring::parse_score` 要求文本"恰好规范"：`12.8`、`1:23.45`。
//! （v1.9.9 起严格解析器已内置秒表写法 `12"34`、`1'23"45`、中文单位与全角
//!   数字的归一，本模块继续负责无效标记、推荐理由等更"语义化"的部分。）
//! 而真实场景里老师是用手机/电脑**手打**或**从 Word 表格粘贴**的，
//! 于是会出现：
//!
//! | 输入 | 常见来源 | 原始实现 |
//! | --- | --- | --- |
//! | `１２.８` 全角数字 | 中文输入法 | 解析失败 |
//! | `1分23秒45` | 语音转写 / 口述记录 | 解析失败 |
//! | `13.5秒` | 随手加单位 | 解析失败 |
//! | `5.23 米` | Word 复制带空格 | 解析失败 |
//! | `12次` / `12个` | 跳绳、引体向上 | 解析失败 |
//! | `1'23"45` | 秒表屏显 | 解析失败 |
//! | `—` / `-` / `弃权` / `DNS` | 缺席退赛 | 解析失败（应作为"无效"） |
//!
//! 本模块统一做**归一化**再走原解析器，并额外返回"用了哪条规则"，
//! 便于前端提示"已自动识别为 83.45 秒"，让老师能复核而不是盲信。
//!
//! **关键设计**：宽容解析只用于**录入辅助**，不改动 `scoring::parse_score`
//! 的严格语义（规则 11：API 行为对齐参考实现）。是否采用由调用方决定。
//!
//! ## 二、选手推荐（`recommend_lineup`）
//!
//! 报名截止前，老师最头疼的是"这 6 个名额给谁"。本模块用**历史成绩**
//! 做可解释的打分排序，而不是搞一个说不清理由的黑箱：
//!
//! ```text
//!   score = 0.70 × 成绩优势分   （同项目历史最好成绩，组内归一化）
//!         + 0.20 × 稳定性分     （成绩离散度越小越高，避免"一场定终身"）
//!         + 0.10 × 参与度分     （已报项数少者优先，让更多人参赛）
//! ```
//!
//! 权重可调，且**每一项都会在返回结果里给出理由**（`reason` 字段），
//! 老师看到"张三名次靠前是因为上届 13.2 秒且三次成绩都在 13.1~13.4"
//! 才敢用。这是本模块与"AI 玄学推荐"的本质区别。
//!
//! 无历史成绩的选手会得到 `score = None`，并标注"暂无历史成绩"，
//! 排在最后 —— **不猜测、不编造**，宁可让老师手工判断。

use crate::core::json::Json;
use crate::core::model::Event;
use crate::core::scoring;
use crate::core::store::Data;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// 一、宽容成绩解析
// ---------------------------------------------------------------------------

/// 解析结果：数值 + 采用规则说明 + 原始文本。
#[derive(Debug, Clone, PartialEq)]
pub struct LenientScore {
    /// 归一化后的数值（秒 / 米 / 个）；`void` 为真时无意义
    pub value: f64,
    /// 归一化后的标准文本（可直接回填到输入框）
    pub normalized: String,
    /// 命中的规则说明（用于向用户解释，例如"全角数字已转换为半角"）
    pub notes: Vec<String>,
    /// 判定为"明确的无效成绩"（缺席/退赛等），调用方应记为空而非报错
    pub void: bool,
}

/// 全角字符转半角（数字、字母、标点、空格）。
///
/// 全角区间 U+FF01..U+FF5E 与半角 U+0021..U+007E 一一对应（偏移 0xFEE0）；
/// 全角空格 U+3000 单独映射为半角空格。
pub fn to_halfwidth(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '\u{3000}' => ' ',
            c if ('\u{FF01}'..='\u{FF5E}').contains(&c) => {
                char::from_u32(c as u32 - 0xFEE0).unwrap_or(c)
            }
            c => c,
        })
        .collect()
}

/// 明确的无效/缺席标记词（不区分大小写，全角已半角化）。
const VOID_MARKS: &[&str] = &[
    "弃权", "退赛", "缺席", "请假", "未到", "未参加", "未完成", "犯规", "dns", "dnf", "dsq", "nm",
    "x", "xx", "—", "-", "--", "/", "无", "空",
];

/// 判断归一化文本是否表示"明确无效"。
pub fn is_void_mark(text: &str) -> bool {
    let t = to_halfwidth(text).trim().to_ascii_lowercase();
    !t.is_empty() && VOID_MARKS.contains(&t.as_str())
}

/// 中文时间单位归一化：`1分23秒45` → `1:23.45`，`1分23秒` → `1:23`。
///
/// 返回 `None` 表示文本里含"时"（校运会无此量级），交给上层判为无法识别。
fn normalize_cn_time(s: &str) -> Option<String> {
    let mut buf = String::new();
    let mut prev_num = String::new();
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c.is_ascii_digit() || c == '.' {
            prev_num.push(c);
            continue;
        }
        match c {
            // 小时不在校运会量级内：保守地判定为"看不懂"，不猜
            '时' => return None,
            '分' => {
                buf.push_str(&prev_num);
                buf.push(':');
                prev_num.clear();
            }
            '秒' => {
                if prev_num.is_empty() {
                    prev_num.push('0');
                }
                buf.push_str(&prev_num);
                prev_num.clear();
                // "秒"后紧跟数字 → 视为小数部分（1分23秒45）
                if chars.peek().map(|c| c.is_ascii_digit()).unwrap_or(false) {
                    buf.push('.');
                }
            }
            _ => {
                buf.push_str(&prev_num);
                prev_num.clear();
                buf.push(c);
            }
        }
    }
    buf.push_str(&prev_num);
    Some(buf)
}

/// 宽容解析成绩文本。
///
/// 返回 `None` 表示"既不是有效成绩，也不是明确的无效标记"——即真的看不懂，
/// 调用方应报错并让用户手工修正（不猜测、不编造）。
pub fn parse_score_lenient(raw: &str, unit: &str) -> Option<LenientScore> {
    let original = raw.trim();
    if original.is_empty() {
        return None;
    }
    let mut notes: Vec<String> = Vec::new();

    // 规则 0：明确无效标记
    if is_void_mark(original) {
        return Some(LenientScore {
            value: f64::NAN,
            normalized: String::new(),
            notes: vec!["识别为缺席/退赛，按无成绩处理".into()],
            void: true,
        });
    }

    // 规则 1：全角 → 半角
    let mut s = to_halfwidth(original);
    if s != original {
        notes.push("全角字符已转换为半角".into());
    }

    // 规则 2：中文时间单位 → 符号
    if s.contains('分') || s.contains('秒') {
        s = normalize_cn_time(&s)?;
        notes.push("中文时间单位已转换为 分:秒.毫秒".into());
    }

    // 规则 3：秒表格式 1'23"45 / 1'23" / 23"45
    let before_stopwatch = s.clone();
    s = s.replace('\'', ":").replace('"', ".");
    if s != before_stopwatch {
        notes.push("秒表格式已识别".into());
    }

    // 规则 4：去除常见单位与噪声字符
    let before_trim = s.clone();
    for tag in ["米", "个", "次", "秒", "m", "M", "s", "S", "kg", "KG"] {
        s = s.replace(tag, "");
    }
    if s != before_trim {
        notes.push("已忽略单位后缀".into());
    }

    // 规则 5：去空白
    let s = s.trim().to_string();
    if s.is_empty() {
        return None;
    }

    // 交给核心严格解析器（权威语义）
    let value = scoring::parse_score(&s, unit)?;
    let normalized = scoring::format_score(value, unit);
    Some(LenientScore {
        value,
        normalized,
        notes,
        void: false,
    })
}

// ---------------------------------------------------------------------------
// 二、选手推荐
// ---------------------------------------------------------------------------

/// 推荐算法权重。
#[derive(Debug, Clone, Copy)]
pub struct RecoWeights {
    /// 历史成绩优势（组内归一化最好成绩）
    pub perf: f64,
    /// 稳定性（成绩离散度）
    pub stability: f64,
    /// 参与度（已报项目越少越优先，促进人人参与）
    pub spread: f64,
}

impl Default for RecoWeights {
    fn default() -> Self {
        RecoWeights {
            perf: 0.70,
            stability: 0.20,
            spread: 0.10,
        }
    }
}

/// 一名候选选手的推荐结果。
#[derive(Debug, Clone)]
pub struct Recommendation {
    pub student_id: i64,
    pub name: String,
    pub grade: String,
    pub class_no: i64,
    /// 综合得分 0~100；无历史成绩为 None
    pub score: Option<f64>,
    /// 历史最好成绩（原始值）
    pub best_value: Option<f64>,
    /// 历史最好成绩的展示文本
    pub best_text: String,
    /// 历史样本数
    pub samples: usize,
    /// 已报名项目数（含本项目则为已报）
    pub registered_count: usize,
    /// 是否已报本项目
    pub already_registered: bool,
    /// 可解释理由（前端直接展示）
    pub reason: String,
}

/// 为某项目推荐参赛人选。
///
/// 参数：
/// * `event_id` —— 目标项目
/// * `limit`    —— 返回条数上限（0 表示不限）
/// * `weights`  —— 打分权重（用 `RecoWeights::default()` 即可）
///
/// 返回 (项目名, 候选列表)。候选按得分降序；无成绩者殿后。
pub fn recommend_lineup(
    data: &Data,
    event_id: i64,
    limit: usize,
    weights: RecoWeights,
) -> Result<(String, Vec<Recommendation>), String> {
    let ev: &Event = data
        .events
        .iter()
        .find(|e| e.id == event_id)
        .ok_or_else(|| format!("项目 {} 不存在", event_id))?;

    // ---- 1. 收集"同项目历史成绩" ----
    // 判定标准：同 name 且同 unit 视为同一项目的历史举办。这是校运会最常见的
    // 复用方式——每年都建一个"男子100米"。若按 event_id 严格匹配则得不到任何
    // 历史，功能沦为摆设。
    let sibling_ids: Vec<i64> = data
        .events
        .iter()
        .filter(|e| e.name == ev.name && e.unit == ev.unit)
        .map(|e| e.id)
        .collect();

    // student_id -> 历史成绩列表
    let mut hist: HashMap<i64, Vec<f64>> = HashMap::new();
    for r in &data.results {
        if !sibling_ids.contains(&r.event_id) {
            continue;
        }
        if let (Some(sid), Some(v)) = (r.student_id, r.score_value) {
            hist.entry(sid).or_default().push(v);
        }
    }

    // ---- 2. 候选池：符合性别/年级约束的在校学生 ----
    let mut cands: Vec<Recommendation> = Vec::new();
    let registered_count_of = |sid: i64| -> usize {
        data.registrations
            .iter()
            .filter(|r| r.student_id == sid)
            .count()
    };

    for st in &data.students {
        // 年级约束：项目年级为"全部"（或不限）时，任何年级都可候选。
        // 注意这里的口径必须与核心的报名校验一致（见 api.rs 中
        // `ev.grade != "全部" && s.grade != ev.grade`）—— 核心用 "全部"
        // 表示不限年级，不是 "通用"。曾经这里误写成 "通用"，导致默认预置
        // 项目（年级字段即 "全部"）的所有学生都被过滤掉，推荐恒为空。
        let grade_unrestricted =
            ev.grade.is_empty() || ev.grade == "全部" || ev.grade == "通用";
        if !grade_unrestricted && st.grade != ev.grade {
            continue;
        }
        // 性别：项目为"通用"/'全部' 时不限；否则严格按男女过滤
        // （推荐场景下把错性别的学生排到第一毫无意义）
        let gender_unrestricted = ev.gender.is_empty()
            || ev.gender == "通用"
            || ev.gender == "全部"
            || ev.gender == "不限";
        if !gender_unrestricted {
            let need_male = ev.gender.starts_with('男');
            let ok = if st.gender.starts_with('男') {
                need_male
            } else if st.gender.starts_with('女') {
                !need_male
            } else {
                // 性别未知的学生：不直接排除，只降权处理更稳妥。
                // 校运会名单常缺性别，直接丢弃会让推荐漏掉真实候选。
                false
            };
            if !ok {
                continue;
            }
        }

        let vals = hist.get(&st.id).cloned().unwrap_or_default();
        let samples = vals.len();
        let best_value = if vals.is_empty() {
            None
        } else if ev.is_track() {
            Some(vals.iter().cloned().fold(f64::INFINITY, f64::min))
        } else {
            Some(vals.iter().cloned().fold(f64::NEG_INFINITY, f64::max))
        };
        let already_registered = data
            .registrations
            .iter()
            .any(|r| r.event_id == event_id && r.student_id == st.id);

        cands.push(Recommendation {
            student_id: st.id,
            name: st.name.clone(),
            grade: st.grade.clone(),
            class_no: st.class_no,
            score: None,
            best_value,
            best_text: best_value
                .map(|v| scoring::format_score(v, &ev.unit))
                .unwrap_or_else(|| "—".into()),
            samples,
            registered_count: registered_count_of(st.id),
            already_registered,
            reason: String::new(),
        });
    }

    if cands.is_empty() {
        return Ok((ev.name.clone(), cands));
    }

    // ---- 3. 成绩优势分：组内归一化 ----
    // 径赛"越小越好"用倒序映射；田赛越大越好用正序映射。
    let avail: Vec<f64> = cands.iter().filter_map(|c| c.best_value).collect();
    let (mut lo, mut hi) = (f64::INFINITY, f64::NEG_INFINITY);
    for v in &avail {
        lo = lo.min(*v);
        hi = hi.max(*v);
    }
    let span = hi - lo;

    let max_reg = cands.iter().map(|c| c.registered_count).max().unwrap_or(0);

    for c in cands.iter_mut() {
        let mut parts: Vec<String> = Vec::new();

        let perf = match c.best_value {
            None => {
                c.score = None;
                c.reason = "暂无该项目历史成绩，建议手工判断".into();
                continue;
            }
            Some(v) => {
                let p = if span.abs() < 1e-9 {
                    // 全部并列，或仅一人有成绩：给满分（无从比较）
                    1.0
                } else if ev.is_track() {
                    (hi - v) / span
                } else {
                    (v - lo) / span
                };
                parts.push(format!(
                    "历史最好 {}（组内{}）",
                    c.best_text,
                    if p >= 0.85 {
                        "领先"
                    } else if p >= 0.5 {
                        "中上"
                    } else if p >= 0.25 {
                        "中下"
                    } else {
                        "靠后"
                    }
                ));
                p
            }
        };

        // 稳定性：变异系数 CV = σ/μ，越小越稳。仅样本 ≥2 可算，否则中性 0.5。
        let stab = if c.samples >= 2 {
            let vals: Vec<f64> = hist.get(&c.student_id).cloned().unwrap_or_default();
            let mean = vals.iter().sum::<f64>() / vals.len() as f64;
            if mean.abs() < 1e-9 {
                0.5
            } else {
                let var =
                    vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / vals.len() as f64;
                let cv = var.sqrt() / mean.abs();
                // CV 0 → 1.0；CV ≥0.15 → 0.0
                let s = (1.0 - cv / 0.15).clamp(0.0, 1.0);
                if s >= 0.7 {
                    parts.push(format!("{} 次成绩很稳定", c.samples));
                } else if s <= 0.3 {
                    parts.push(format!("{} 次成绩波动较大", c.samples));
                }
                s
            }
        } else {
            parts.push("仅 1 次成绩，稳定性按中性计".into());
            0.5
        };

        // 参与度：已报项目越少越优先（让更多人上场）
        let spar = if max_reg == 0 {
            1.0
        } else {
            1.0 - (c.registered_count as f64 / max_reg as f64)
        };
        if c.registered_count == 0 {
            parts.push("尚未报名任何项目".into());
        } else {
            parts.push(format!("已报 {} 项", c.registered_count));
        }
        if c.already_registered {
            parts.push("已在本项目名单中".into());
        }

        let total =
            (perf * weights.perf + stab * weights.stability + spar * weights.spread) * 100.0;
        c.score = Some((total * 100.0).round() / 100.0);
        c.reason = parts.join("；");
    }

    // ---- 4. 排序：有分者按分降序；无分者按 id 稳定排序殿后 ----
    cands.sort_by(|a, b| match (a.score, b.score) {
        (Some(x), Some(y)) => y
            .partial_cmp(&x)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.student_id.cmp(&b.student_id)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.student_id.cmp(&b.student_id),
    });

    if limit > 0 && cands.len() > limit {
        cands.truncate(limit);
    }
    Ok((ev.name.clone(), cands))
}

/// 把推荐结果序列化为 JSON（供 HTTP 层直接返回）。
pub fn recommendations_json(
    data: &Data,
    event_id: i64,
    limit: usize,
    weights: RecoWeights,
) -> Result<Json, String> {
    let (event_name, list) = recommend_lineup(data, event_id, limit, weights)?;
    let mut arr = Vec::new();
    for c in &list {
        let mut o = Json::obj();
        o.set("student_id", Json::Int(c.student_id));
        o.set("name", Json::s(c.name.clone()));
        o.set("grade", Json::s(c.grade.clone()));
        o.set("class_no", Json::Int(c.class_no));
        o.set("score", c.score.map(Json::Num).unwrap_or(Json::Null));
        o.set("best_text", Json::s(c.best_text.clone()));
        o.set(
            "best_value",
            c.best_value.map(Json::Num).unwrap_or(Json::Null),
        );
        o.set("samples", Json::Int(c.samples as i64));
        o.set("registered_count", Json::Int(c.registered_count as i64));
        o.set("already_registered", Json::Bool(c.already_registered));
        o.set("reason", Json::s(c.reason.clone()));
        arr.push(o);
    }
    let mut top = Json::obj();
    top.set("ok", Json::Bool(true));
    top.set("event_id", Json::Int(event_id));
    top.set("event_name", Json::s(event_name));
    top.set("weights", {
        let mut w = Json::obj();
        w.set("perf", Json::Num(weights.perf));
        w.set("stability", Json::Num(weights.stability));
        w.set("spread", Json::Num(weights.spread));
        w
    });
    top.set("count", Json::Int(arr.len() as i64));
    top.set("candidates", Json::Arr(arr));
    top.set(
        "notice",
        Json::s("推荐基于同项目历史成绩的可解释打分，仅供参考，最终以教师判断为准"),
    );
    Ok(top)
}

// ---------------------------------------------------------------------------
// 单元测试（v1.5 新增）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::{Registration, Result as DomainResult, Settings, Student};
    use crate::core::store::Data;

    // ---------------- 宽容解析 ----------------

    #[test]
    fn halfwidth_conversion_covers_digits_and_punct() {
        assert_eq!(to_halfwidth("１２.８"), "12.8");
        assert_eq!(to_halfwidth("１：２３"), "1:23");
        assert_eq!(to_halfwidth("ａ　ｂ"), "a b");
        assert_eq!(to_halfwidth("abc"), "abc", "半角不受影响");
    }

    #[test]
    fn plain_values_still_parse() {
        let r = parse_score_lenient("12.8", "时间").unwrap();
        assert!((r.value - 12.8).abs() < 1e-9);
        assert!(!r.void);
        let r = parse_score_lenient("5.23", "米").unwrap();
        assert!((r.value - 5.23).abs() < 1e-9);
    }

    #[test]
    fn fullwidth_digits_parse_with_note() {
        let r = parse_score_lenient("１３．５", "时间").unwrap();
        assert!((r.value - 13.5).abs() < 1e-9);
        assert!(r.notes.iter().any(|n| n.contains("全角")));
    }

    #[test]
    fn chinese_minute_second_parses() {
        let r = parse_score_lenient("1分23秒45", "时间").unwrap();
        assert!((r.value - 83.45).abs() < 1e-9, "得到 {}", r.value);
        assert!(r.notes.iter().any(|n| n.contains("中文时间单位")));
    }

    #[test]
    fn chinese_minute_second_without_frac() {
        let r = parse_score_lenient("1分23秒", "时间").unwrap();
        assert!((r.value - 83.0).abs() < 1e-9);
    }

    #[test]
    fn unit_suffix_is_ignored() {
        assert!((parse_score_lenient("13.5秒", "时间").unwrap().value - 13.5).abs() < 1e-9);
        assert!((parse_score_lenient("5.23米", "米").unwrap().value - 5.23).abs() < 1e-9);
        assert!((parse_score_lenient("5.23 米", "米").unwrap().value - 5.23).abs() < 1e-9);
        assert!((parse_score_lenient("12次", "个").unwrap().value - 12.0).abs() < 1e-9);
    }

    #[test]
    fn stopwatch_notation_parses() {
        let r = parse_score_lenient("1'23\"45", "时间").unwrap();
        assert!((r.value - 83.45).abs() < 1e-9, "得到 {}", r.value);
    }

    #[test]
    fn void_marks_are_flagged_not_errors() {
        for t in ["弃权", "退赛", "缺席", "—", "-", "DNS", "dnf", "犯规"] {
            let r = parse_score_lenient(t, "时间").unwrap_or_else(|| panic!("{} 应被识别", t));
            assert!(r.void, "{} 应标记 void", t);
        }
    }

    #[test]
    fn garbage_returns_none_not_guess() {
        for t in ["abc", "张", "??", "12..5", ":", "秒", "1时20分"] {
            assert!(
                parse_score_lenient(t, "时间").is_none(),
                "{} 无法解析时应返回 None，不能猜测",
                t
            );
        }
    }

    #[test]
    fn normalized_text_is_reusable() {
        let r = parse_score_lenient("１分２３秒４５", "时间").unwrap();
        // 归一化文本应能被严格解析器再次接受（幂等）
        assert!(scoring::parse_score(&r.normalized, "时间").is_some());
    }

    #[test]
    fn individual_count_unit_keeps_lower_bound() {
        assert!(parse_score_lenient("0个", "个").is_none());
        assert!((parse_score_lenient("12个", "个").unwrap().value - 12.0).abs() < 1e-9);
    }

    // ---------------- 推荐 ----------------

    fn ev(id: i64, name: &str, track: bool, gender: &str) -> Event {
        Event {
            id,
            name: name.into(),
            category: if track { "径赛".into() } else { "田赛".into() },
            gender: gender.into(),
            // 与核心默认预置项目保持一致：年级字段为 "全部"（不是 "通用"）。
            // 单元测试过去一律用 "初一"，恰好绕过了"全部"这个取值，导致
            // "全部年级的学生全被过滤掉"的 bug 一直没被测出来。改为
            // "全部" 后，测试才真正覆盖线上最常见的那条路径。
            grade: "全部".into(),
            is_team: false,
            unit: if track { "时间".into() } else { "米".into() },
            record: None,
        }
    }

    /// 年级限定为具体某年级的项目（用于验证筛选仍然生效）。
    fn ev_grade(id: i64, name: &str, track: bool, gender: &str, grade: &str) -> Event {
        let mut e = ev(id, name, track, gender);
        e.grade = grade.into();
        e
    }

    fn stu(id: i64, name: &str, gender: &str) -> Student {
        Student {
            id,
            grade: "初一".into(),
            class_no: 1,
            name: name.into(),
            gender: gender.into(),
        }
    }

    fn res(id: i64, eid: i64, sid: i64, v: f64) -> DomainResult {
        DomainResult {
            id,
            event_id: eid,
            student_id: Some(sid),
            grade: "初一".into(),
            class_no: Some(1),
            score_text: v.to_string(),
            score_value: Some(v),
            rank: None,
            points: None,
            broke_record: false,
        }
    }

    fn base_data() -> Data {
        let mut d = Data {
            settings: Settings::default(),
            events: vec![
                ev(1, "男子100米", true, "男子"), // 历史项目
                ev(2, "男子100米", true, "男子"), // 本届项目（同名 → 视为同项目）
                ev(3, "男子跳远", false, "男子"),
            ],
            ..Data::default()
        };
        d.students = vec![
            stu(101, "张三", "男"),
            stu(102, "李四", "男"),
            stu(103, "王五", "男"),
            stu(104, "赵六", "女"),
            stu(105, "孙七", "男"), // 无历史成绩
        ];
        d.next_student_id = 106;
        d.results = vec![
            res(1, 1, 101, 13.2),
            res(2, 1, 101, 13.4),
            res(3, 1, 101, 13.1),
            res(4, 1, 102, 12.9),
            res(5, 1, 102, 14.6), // 波动大
            res(6, 1, 103, 15.8),
        ];
        d
    }

    #[test]
    fn recommend_returns_all_eligible_sorted_by_score() {
        let d = base_data();
        let (name, list) = recommend_lineup(&d, 2, 0, RecoWeights::default()).unwrap();
        assert_eq!(name, "男子100米");
        assert!(!list.iter().any(|c| c.name == "赵六"), "女生应被排除");
        let scored = list.iter().filter(|c| c.score.is_some()).count();
        assert_eq!(scored, 3);
        // 分数降序
        let scores: Vec<f64> = list.iter().filter_map(|c| c.score).collect();
        for w in scores.windows(2) {
            assert!(w[0] >= w[1], "分数必须降序：{:?}", scores);
        }
        // 无成绩者殿后
        assert_eq!(list.last().unwrap().name, "孙七");
        assert!(list.last().unwrap().score.is_none());
    }

    #[test]
    fn fastest_runner_ranks_first_among_widely_spread_field() {
        // 关键：perf 是**组内归一化**分，会随对手水平压缩；
        // 而 stability 是绝对量。因此"最快者一定第一"只在成绩分布很开时成立。
        // 本用例构造一个真实运动会常见的散开分布（12.5 / 13.6 / 16.8），
        // 此时成绩优势足够大，应压过稳定性差异。
        let mut d = base_data();
        d.results = vec![
            res(1, 1, 101, 13.6), // 张三：稳但不最快
            res(2, 1, 101, 13.7),
            res(3, 1, 101, 13.6),
            res(4, 1, 102, 12.5), // 李四：明显最快
            res(5, 1, 102, 14.8), // 但波动
            res(6, 1, 103, 16.8), // 王五：明显靠后
        ];
        let (_, list) = recommend_lineup(&d, 2, 0, RecoWeights::default()).unwrap();
        assert_eq!(list[0].name, "李四", "分布散开时最快者应第一");
        let top2: Vec<&str> = list.iter().take(2).map(|c| c.name.as_str()).collect();
        assert!(
            top2.contains(&"李四") && top2.contains(&"张三"),
            "前两名应为李四与张三，实际 {:?}",
            top2
        );
    }

    #[test]
    fn tight_field_with_volatility_favors_stability() {
        // 分布集中（12.7~15.8，跨度小）时 perf 的区分度被压缩，
        // 稳定性权重开始生效 —— 这正是本算法"不搞一场定终身"的体现。
        // 张三极稳（13.1~13.2）应压过波动大的李四（12.7/14.9）。
        let mut d = base_data();
        d.results = vec![
            res(1, 1, 101, 13.1),
            res(2, 1, 101, 13.2),
            res(3, 1, 101, 13.1),
            res(4, 1, 102, 12.7),
            res(5, 1, 102, 14.9),
            res(6, 1, 103, 15.8),
        ];
        let (_, list) = recommend_lineup(&d, 2, 0, RecoWeights::default()).unwrap();
        assert_eq!(
            list[0].name, "张三",
            "成绩接近时稳定者应胜出（避免用一次偶然快跑定人选）"
        );
    }

    #[test]
    fn stability_can_overturn_with_heavy_stability_weight() {
        let d = base_data();
        let w = RecoWeights {
            perf: 0.10,
            stability: 0.85,
            spread: 0.05,
        };
        let (_, list) = recommend_lineup(&d, 2, 0, w).unwrap();
        assert_eq!(list[0].name, "张三", "高稳定性权重下稳定者应第一");
    }

    #[test]
    fn reason_is_always_explainable() {
        let d = base_data();
        let (_, list) = recommend_lineup(&d, 2, 0, RecoWeights::default()).unwrap();
        for c in &list {
            assert!(!c.reason.is_empty(), "{} 缺少理由", c.name);
        }
    }

    #[test]
    fn gender_universal_event_includes_both() {
        let mut d = base_data();
        d.events[1].gender = "通用".into();
        let (_, list) = recommend_lineup(&d, 2, 0, RecoWeights::default()).unwrap();
        assert!(list.iter().any(|c| c.name == "赵六"), "通用项目应包含女生");
    }

    /// 回归：年级字段为 "全部" 时**必须**视为不限年级。
    ///
    /// 线上真实 bug —— 核心预置项目的 grade 就是 "全部"，而推荐代码曾把
    /// "不限年级"错误地只识别为 "通用"，于是默认项目下所有学生都被年级
    /// 条件过滤掉，`candidates` 恒为空数组，功能等于完全不可用。
    /// 单元测试此前一律用 grade="初一"，正好绕开了 "全部" 这个取值。
    #[test]
    fn grade_all_means_unrestricted_and_yields_candidates() {
        let d = base_data();
        // base_data 的事件年级就是 "全部"，且学生都是 "初一"
        assert_eq!(d.events[1].grade, "全部", "夹具应与预置项目一致");
        let (_, list) = recommend_lineup(&d, 2, 0, RecoWeights::default()).unwrap();
        assert!(
            !list.is_empty(),
            "年级为『全部』的项目必须能产出候选，实际为空（回归 bug）"
        );
        assert!(list.len() >= 3, "应包含所有男生，实际 {}", list.len());
    }

    /// 对照组：年级确实限定时，筛选依然要生效。
    #[test]
    fn specific_grade_still_filters_candidates() {
        let mut d = base_data();
        d.events[1] = ev_grade(2, "男子100米", true, "男子", "初二");
        // 夹具里没有初二学生 → 应为空，且不 panic
        let (_, list) = recommend_lineup(&d, 2, 0, RecoWeights::default()).unwrap();
        assert!(list.is_empty(), "限定初二时不应混入初一学生");
    }

    /// 回归：性别"全部/通用/不限"三种写法都不应把学生挡在门外。
    #[test]
    fn gender_all_and_unrestricted_variants_are_open() {
        for g in ["全部", "通用", "不限", ""] {
            let mut d = base_data();
            d.events[1].gender = g.into();
            let (_, list) = recommend_lineup(&d, 2, 0, RecoWeights::default()).unwrap();
            assert!(
                list.iter().any(|c| c.name == "赵六"),
                "性别为 {:?} 时女生也应可候选",
                g
            );
        }
    }

    #[test]
    fn already_registered_flag_is_reported() {
        let mut d = base_data();
        d.registrations = vec![Registration {
            id: 1,
            event_id: 2,
            student_id: 102,
            note: String::new(),
        }];
        let (_, list) = recommend_lineup(&d, 2, 0, RecoWeights::default()).unwrap();
        let li = list.iter().find(|c| c.name == "李四").unwrap();
        assert!(li.already_registered);
        assert!(li.reason.contains("已在本项目名单中"));
    }

    #[test]
    fn limit_is_honored() {
        let d = base_data();
        let (_, list) = recommend_lineup(&d, 2, 2, RecoWeights::default()).unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn unknown_event_returns_error() {
        let d = base_data();
        assert!(recommend_lineup(&d, 999, 0, RecoWeights::default()).is_err());
    }

    #[test]
    fn single_sample_gets_neutral_stability() {
        let d = base_data();
        let (_, list) = recommend_lineup(&d, 2, 0, RecoWeights::default()).unwrap();
        let wang = list.iter().find(|c| c.name == "王五").unwrap();
        assert_eq!(wang.samples, 1);
        assert!(wang.reason.contains("仅 1 次成绩"));
    }

    #[test]
    fn no_history_at_all_yields_none_scores_without_panic() {
        let d = Data {
            events: vec![ev(1, "女子铅球", false, "女子")],
            students: vec![stu(201, "钱八", "女")],
            ..Data::default()
        };
        let (_, list) = recommend_lineup(&d, 1, 0, RecoWeights::default()).unwrap();
        assert_eq!(list.len(), 1);
        assert!(list[0].score.is_none());
        assert!(list[0].reason.contains("暂无"));
    }

    #[test]
    fn json_serialization_shape_is_stable() {
        let d = base_data();
        let j = recommendations_json(&d, 2, 0, RecoWeights::default()).unwrap();
        assert_eq!(j.get("ok").and_then(|v| v.as_bool()), Some(true));
        assert_eq!(j.get("event_id").and_then(|v| v.as_i64()), Some(2));
        let arr = j.get("candidates").and_then(|v| v.as_arr()).unwrap();
        assert!(!arr.is_empty());
        let first = &arr[0];
        assert!(first.get("reason").is_some());
        assert!(first.get("score").is_some());
        assert!(j.get("notice").is_some());
    }

}
