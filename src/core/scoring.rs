//! 核心积分逻辑（与 Python 版 scoring.py 逐行为对齐）：
//! 1. 成绩文本解析（径赛时间 / 田赛距离 / 次数类）；
//! 2. 自动排名与赋分（积分表前 N 名）；
//! 3. 同名次并列顺延；4. 集体项目倍数；5. 破校纪录加分。

use crate::core::json::Json;
use crate::core::model::{Event, Settings};

/// 把老师手写的时间写法归一成 `分:秒.小数`。
///
/// v1.9.9：秒表习惯也要认——`'` 表示分、`"` 表示秒的小数点。
/// - `12"34` → `12.34`、`12"3` → `12.3`、`12"` → `12`
/// - `1'23"45` → `1:23.45`、`1'23` → `1:23`、`1'` → `1:00`
/// - `12秒5` → `12.5`、`1分23秒45` → `1:23.45`
/// - 全角数字/标点、中文引号、逗号小数点一并归一。
fn normalize_time_text(raw: &str) -> String {
    let mut s = String::with_capacity(raw.len());
    for ch in raw.chars() {
        let c = match ch {
            '０'..='９' => char::from_u32('0' as u32 + (ch as u32 - '０' as u32)).unwrap_or(ch),
            '．' | '。' => '.',
            '，' | ',' => '.', // 12,34 也当 12.34（老师口语里常把点读成逗号）
            '：' => ':',
            '＂' | '“' | '”' | '″' | '〃' => '"',
            '＇' | '‘' | '’' | '′' => '\'',
            '\u{3000}' => ' ',
            _ => ch,
        };
        s.push(c);
    }
    let mut s = s
        .replace('分', ":")
        .replace('秒', ".")
        .replace('\'', ":")
        .replace('"', ".");
    s.retain(|c| !c.is_whitespace());
    // `12"` → `12.` 去掉尾点；`1'` → `1:` 补成 `1:00`
    while s.ends_with('.') {
        s.pop();
    }
    if s.ends_with(':') {
        s.push_str("00");
    }
    s
}

/// 解析成绩文本为数值；失败返回 None。
/// - 时间："1:23.45" / "23.45" / `12"34` / `1'23"45` / "12秒5" -> 秒
/// - 米："5.23" / "5.23m" -> 米
/// - 个："12" / "12个" -> 个数（0 视为无效成绩）
pub fn parse_score(text: &str, unit: &str) -> Option<f64> {
    let raw = text.trim();
    if raw.is_empty() {
        return None;
    }
    if unit == "时间" {
        let s = normalize_time_text(raw);
        if s.is_empty() {
            return None;
        }
        if s.contains(':') {
            let parts: Vec<&str> = s.split(':').collect();
            if parts.len() != 2 {
                return None;
            }
            let minutes: f64 = parts[0].parse().ok()?;
            let seconds: f64 = parts[1].parse().ok()?;
            if !(0.0..60.0).contains(&seconds) || minutes < 0.0 {
                return None;
            }
            return Some(minutes * 60.0 + seconds).filter(|v| *v > 0.0);
        }
        return s.parse::<f64>().ok().filter(|v| *v > 0.0);
    }
    let mut s = raw.to_string();
    for tag in ["米", "个", "m", "M"] {
        s = s.replace(tag, "");
    }
    let s = s.trim();
    let value: f64 = s.parse().ok()?;
    if value < 0.0 {
        return None;
    }
    if unit == "个" && value < 1.0 {
        return None; // "个" 数至少为 1
    }
    Some(value)
}

/// 录入校验：返回 (是否通过, 错误消息)。
/// 成绩文本合法性校验（含完整单测覆盖）。
/// v1.4：批量导入链路暂未接入，预留为导入校验的标准入口。
#[allow(dead_code)]
pub fn validate_score_text(text: &str, unit: &str) -> (bool, String) {
    let s = text.trim();
    if s.chars().count() > 12 {
        return (false, "成绩文本过长".into());
    }
    match parse_score(s, unit) {
        Some(_) => (true, String::new()),
        None => (
            false,
            format!("成绩格式不正确（{}）", unit_hint(unit)),
        ),
    }
}

/// 录入框提示语。
pub fn unit_hint(unit: &str) -> &'static str {
    match unit {
        "时间" => "如 12\"34 或 1:23.45（12.8、12秒5 也认）",
        "米" => "如 5.23 米",
        "个" => "如 12 个",
        _ => "数字",
    }
}

/// 数值格式化为展示文本。
pub fn format_score(value: f64, unit: &str) -> String {
    if unit == "时间" {
        let minutes = (value / 60.0).floor() as i64;
        let seconds = value - (minutes as f64) * 60.0;
        if minutes > 0 {
            format!("{}:{:05.2}", minutes, seconds)
        } else {
            format!("{:.2}", seconds)
        }
    } else if unit == "个" {
        format!("{}", (value.round()) as i64)
    } else {
        format!("{:.2}", value)
    }
}

/// 是否破校纪录。
fn is_record_broken(ev: &Event, value: f64) -> bool {
    match ev.record {
        Some(rec) => {
            if ev.is_track() {
                value < rec - 1e-9 // 时间更短
            } else {
                value > rec + 1e-9 // 距离/次数更远
            }
        }
        None => false,
    }
}

/// 一次排名计算的结果。
#[derive(Debug, Clone)]
pub struct Ranked {
    pub entry_index: usize, // 调用方列表中的下标
    pub rank: i64,
    pub points: f64,
    pub broke_record: bool,
}

/// 对某项目的有效成绩排名赋分（与 Python rank_entries 对齐）。
/// `values[i]` 为第 i 个参赛者的成绩；None 表示无效，不参与排名。
pub fn rank_entries(values: &[Option<f64>], ev: &Event, st: &Settings) -> Vec<Ranked> {
    let mut valid: Vec<(usize, f64)> = values
        .iter()
        .enumerate()
        .filter_map(|(i, v)| v.map(|x| (i, x)))
        .collect();
    // 径赛升序（时间短者优先），田赛降序
    if ev.is_track() {
        valid.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
    } else {
        valid.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    }

    let mult = if ev.is_team { st.team_multiplier } else { 1.0 };
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < valid.len() {
        let mut j = i;
        while j + 1 < valid.len() && (valid[j + 1].1 - valid[i].1).abs() < 1e-9 {
            j += 1;
        }
        let rank = (i + 1) as i64;
        let base = if rank as usize <= st.points_table.len() {
            st.points_table[(rank - 1) as usize]
        } else {
            0.0
        };
        let points = base * mult;
        // v1.4：切片迭代替代索引循环（clippy needless_range_loop）
        for &(idx, value) in &valid[i..=j] {
            let broke = is_record_broken(ev, value);
            let pts = if broke { points + st.record_bonus } else { points };
            out.push(Ranked { entry_index: idx, rank, points: pts, broke_record: broke });
        }
        i = j + 1;
    }
    out
}

/// 年级总成绩表：各班总分排名（并列同名次）。
pub fn grade_total_table(data: &crate::core::store::Data, grade: &str) -> Vec<Json> {
    use std::collections::BTreeMap;
    let mut totals: BTreeMap<(String, i64), (f64, i64)> = BTreeMap::new();
    for r in &data.results {
        if r.grade == grade {
            if let Some(p) = r.points {
                let key = (r.grade.clone(), r.class_no.unwrap_or(0));
                let e = totals.entry(key).or_insert((0.0, 0));
                e.0 += p;
                if r.broke_record {
                    e.1 += 1;
                }
            }
        }
    }
    let mut rows: Vec<(String, i64, f64, i64)> = totals
        .into_iter()
        .map(|((g, c), (t, recs))| (g, c, t, recs))
        .collect();
    rows.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap_or(std::cmp::Ordering::Equal));
    let mut table = Vec::new();
    let mut last_total: Option<f64> = None;
    let mut last_rank = 0i64;
    for (idx, (g, c, total, recs)) in rows.iter().enumerate() {
        let rank = if let Some(lt) = last_total {
            if (total - lt).abs() < 1e-9 {
                last_rank
            } else {
                last_rank = (idx + 1) as i64;
                last_rank
            }
        } else {
            last_rank = (idx + 1) as i64;
            last_rank
        };
        last_total = Some(*total);
        let mut o = Json::obj();
        o.set("class", Json::s(format!("{}{}班", g, c)));
        o.set("total", Json::Num((total * 10.0).round() / 10.0));
        o.set("records", Json::Int(*recs));
        o.set("rank", Json::Int(rank));
        table.push(o);
    }
    table
}

// ---------------------------------------------------------------------------
// 单元测试（v1.2 新增）
//
// scoring 是系统的命脉：排名赋分、并列顺延、破纪录判定、集体倍数、年级总表。
// 这些函数是纯函数、无副作用、易测，因此优先补齐覆盖率。
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::{Event, Result as DomainResult, Settings};
    // v1.4：仅测试使用（--fix 误删了主 use 中的引用，在测试域内补齐）
    use crate::core::store::Data;

    /// 构造一个测试用项目。`category` 决定"越小越好"还是"越大越好"。
    fn ev(name: &str, category: &str, is_team: bool, unit: &str, record: Option<f64>) -> Event {
        Event {
            id: 1,
            name: name.into(),
            category: category.into(),
            gender: "通用".into(),
            grade: "全部".into(),
            is_team,
            unit: unit.into(),
            record,
        }
    }

    /// 默认设置：积分表 [7,5,4,3,2,1]，破纪录 +7，集体 ×2。
    fn st() -> Settings {
        Settings::default()
    }

    // ---------------- 成绩解析 ----------------

    #[test]
    fn parse_score_seconds() {
        assert_eq!(parse_score("12.5", "时间"), Some(12.5));
        assert_eq!(parse_score("  13  ", "时间"), Some(13.0));
        // 时间必须为正
        assert_eq!(parse_score("0", "时间"), None);
        assert_eq!(parse_score("-1", "时间"), None);
    }

    #[test]
    fn parse_score_minute_second() {
        // 1 分 23.45 秒 -> 83.45 秒
        assert_eq!(parse_score("1:23.45", "时间"), Some(83.45));
        assert_eq!(parse_score("0:59.9", "时间"), Some(59.9));
        // 秒数必须 < 60
        assert_eq!(parse_score("1:60", "时间"), None);
        assert_eq!(parse_score("1:75", "时间"), None);
        // 分钟不能为负
        assert_eq!(parse_score("-1:30", "时间"), None);
        // 分段数必须为 2
        assert_eq!(parse_score("1:2:3", "时间"), None);
    }

    #[test]
    fn parse_score_distance_and_count() {
        assert_eq!(parse_score("5.23", "米"), Some(5.23));
        assert_eq!(parse_score("5.23m", "米"), Some(5.23));
        assert_eq!(parse_score("5.23米", "米"), Some(5.23));
        assert_eq!(parse_score("12", "个"), Some(12.0));
        assert_eq!(parse_score("12个", "个"), Some(12.0));
        // 米/个 不能为负
        assert_eq!(parse_score("-0.1", "米"), None);
        // "个" 至少为 1（0 视为无效）
        assert_eq!(parse_score("0", "个"), None);
        assert_eq!(parse_score("0.5", "个"), None);
        assert_eq!(parse_score("1", "个"), Some(1.0));
    }

    #[test]
    fn parse_score_stopwatch_marks() {
        // v1.9.9：秒表习惯 "'" 表示分、`"` 表示秒的小数点
        assert_eq!(parse_score("12\"34", "时间"), Some(12.34));
        assert_eq!(parse_score("12\"3", "时间"), Some(12.3));
        assert_eq!(parse_score("12\"", "时间"), Some(12.0));
        assert_eq!(parse_score("23\"45", "时间"), Some(23.45));
        assert_eq!(parse_score("1'23\"45", "时间"), Some(83.45));
        assert_eq!(parse_score("1'23", "时间"), Some(83.0));
        assert_eq!(parse_score("1'", "时间"), Some(60.0));
        // 中文单位与全角/中文标点
        assert_eq!(parse_score("12秒5", "时间"), Some(12.5));
        assert_eq!(parse_score("1分23秒45", "时间"), Some(83.45));
        assert_eq!(parse_score("１２．５", "时间"), Some(12.5));
        assert_eq!(parse_score("12”34", "时间"), Some(12.34));
        assert_eq!(parse_score("1′23″45", "时间"), Some(83.45));
        // 逗号当小数点
        assert_eq!(parse_score("12,34", "时间"), Some(12.34));
        // 秒数仍必须 < 60
        assert_eq!(parse_score("1'75\"", "时间"), None);
    }

    #[test]
    fn parse_score_invalid() {
        assert_eq!(parse_score("", "时间"), None);
        assert_eq!(parse_score("   ", "米"), None);
        assert_eq!(parse_score("abc", "米"), None);
        assert_eq!(parse_score("12秒", "时间"), Some(12.0)); // v1.9.9 起"秒"可剥离
        assert_eq!(parse_score("--5", "米"), None);
    }

    // ---------------- 录入校验 ----------------

    #[test]
    fn validate_score_text_rules() {
        assert!(validate_score_text("12.5", "时间").0);
        assert!(validate_score_text("1:23.45", "时间").0);
        assert!(!validate_score_text("abc", "时间").0);
        // 超过 12 字符拒绝
        assert!(!validate_score_text("1234567890123", "米").0);
        // 恰好 12 字符通过（数值合法）
        assert!(validate_score_text("1234567890.5", "米").0);
        // 错误消息非空
        let (ok, msg) = validate_score_text("xx", "米");
        assert!(!ok);
        assert!(!msg.is_empty());
    }

    // ---------------- 展示格式化 ----------------

    #[test]
    fn format_score_rules() {
        assert_eq!(format_score(12.345, "时间"), "12.35"); // 不足 1 分不带分号
        assert_eq!(format_score(83.45, "时间"), "1:23.45"); // 1 分 23.45 秒
        assert_eq!(format_score(60.0, "时间"), "1:00.00");
        assert_eq!(format_score(12.0, "个"), "12");
        assert_eq!(format_score(12.6, "个"), "13"); // 四舍五入
        assert_eq!(format_score(5.234, "米"), "5.23");
    }

    #[test]
    fn format_score_roundtrip_with_parse() {
        // 格式化后再解析应还原（时间/米两类）
        let v = 83.45;
        let text = format_score(v, "时间");
        assert!((parse_score(&text, "时间").unwrap() - v).abs() < 1e-9);
    }

    // ---------------- 排名：径赛（越小越好） ----------------

    #[test]
    fn rank_track_ascending() {
        let e = ev("男子100米", "径赛", false, "时间", None);
        let values = vec![Some(12.5), Some(11.8), Some(13.2)];
        let r = rank_entries(&values, &e, &st());
        // 11.8 最快 -> 第1（7分）；12.5 -> 第2（5分）；13.2 -> 第3（4分）
        let by_idx = |i: usize| r.iter().find(|x| x.entry_index == i).unwrap().clone();
        assert_eq!(by_idx(1).rank, 1);
        assert_eq!(by_idx(1).points, 7.0);
        assert_eq!(by_idx(0).rank, 2);
        assert_eq!(by_idx(0).points, 5.0);
        assert_eq!(by_idx(2).rank, 3);
        assert_eq!(by_idx(2).points, 4.0);
    }

    // ---------------- 排名：田赛（越大越好） ----------------

    #[test]
    fn rank_field_descending() {
        let e = ev("跳远", "田赛", false, "米", None);
        let values = vec![Some(4.5), Some(5.2), Some(3.9)];
        let r = rank_entries(&values, &e, &st());
        let by_idx = |i: usize| r.iter().find(|x| x.entry_index == i).unwrap().clone();
        assert_eq!(by_idx(1).rank, 1); // 5.2 最远
        assert_eq!(by_idx(1).points, 7.0);
        assert_eq!(by_idx(0).rank, 2);
        assert_eq!(by_idx(2).rank, 3);
    }

    // ---------------- 并列顺延（关键规则） ----------------

    #[test]
    fn rank_ties_skip_next() {
        // 两人并列第 1 时，下一名应为第 3（顺延），且两人都拿第 1 名的分
        let e = ev("跳远", "田赛", false, "米", None);
        let values = vec![Some(5.0), Some(5.0), Some(4.0)];
        let r = rank_entries(&values, &e, &st());
        let by_idx = |i: usize| r.iter().find(|x| x.entry_index == i).unwrap().clone();
        assert_eq!(by_idx(0).rank, 1);
        assert_eq!(by_idx(0).points, 7.0);
        assert_eq!(by_idx(1).rank, 1);
        assert_eq!(by_idx(1).points, 7.0);
        assert_eq!(by_idx(2).rank, 3); // 顺延，跳过第 2
        assert_eq!(by_idx(2).points, 4.0); // 第 3 名对应积分表 [2] = 4.0
    }

    #[test]
    fn rank_three_way_tie() {
        // 三人并列第 1 -> 后续名次顺延到第 4
        let e = ev("铅球", "田赛", false, "米", None);
        let values = vec![Some(8.0), Some(8.0), Some(8.0), Some(5.0)];
        let r = rank_entries(&values, &e, &st());
        let by_idx = |i: usize| r.iter().find(|x| x.entry_index == i).unwrap().clone();
        for i in 0..3 {
            assert_eq!(by_idx(i).rank, 1);
            assert_eq!(by_idx(i).points, 7.0);
        }
        assert_eq!(by_idx(3).rank, 4);
        assert_eq!(by_idx(3).points, 3.0); // 积分表 [3] = 3.0
    }

    #[test]
    fn rank_tie_tolerance() {
        // 差异小于 1e-9 视为并列
        let e = ev("跳远", "田赛", false, "米", None);
        let values = vec![Some(5.0), Some(5.0 + 1e-12)];
        let r = rank_entries(&values, &e, &st());
        assert!(r.iter().all(|x| x.rank == 1), "容差内应判为并列");
        // 差异超过容差则为不同名次
        let values2 = vec![Some(5.0), Some(5.1)];
        let r2 = rank_entries(&values2, &e, &st());
        assert_eq!(r2.iter().filter(|x| x.rank == 1).count(), 1);
    }

    // ---------------- 无效成绩不参与排名 ----------------

    #[test]
    fn rank_skips_none_values() {
        let e = ev("男子100米", "径赛", false, "时间", None);
        let values = vec![Some(12.5), None, Some(11.8)];
        let r = rank_entries(&values, &e, &st());
        // None 不应出现在结果中
        assert!(r.iter().all(|x| x.entry_index != 1));
        assert_eq!(r.len(), 2);
        // 名次仍连续（1、2），不因缺失而跳号
        assert!(!r.iter().any(|x| x.entry_index == 1));
        let ranks: Vec<i64> = {
            let mut v: Vec<(usize, i64)> = r.iter().map(|x| (x.entry_index, x.rank)).collect();
            v.sort();
            v.into_iter().map(|(_, rk)| rk).collect()
        };
        assert_eq!(ranks, vec![2, 1]);
    }

    #[test]
    fn rank_all_none_returns_empty() {
        let e = ev("跳远", "田赛", false, "米", None);
        let r = rank_entries(&[None, None], &e, &st());
        assert!(r.is_empty());
    }

    // ---------------- 超出积分表名次不计分 ----------------

    #[test]
    fn rank_beyond_points_table_scores_zero() {
        let e = ev("跳远", "田赛", false, "米", None);
        // 7 人参赛，积分表仅 6 项 -> 第 7 名 0 分
        let values: Vec<Option<f64>> =
            (0..7).map(|i| Some(10.0 - i as f64)).collect();
        let r = rank_entries(&values, &e, &st());
        let last = r.iter().find(|x| x.rank == 7).unwrap();
        assert_eq!(last.points, 0.0);
        // 第 6 名仍为 1.0 分
        let sixth = r.iter().find(|x| x.rank == 6).unwrap();
        assert_eq!(sixth.points, 1.0);
    }

    // ---------------- 集体项目倍数 ----------------

    #[test]
    fn rank_team_multiplier_applied() {
        let e = ev("4×100米接力", "径赛", true, "时间", None);
        let values = vec![Some(55.0), Some(56.0)];
        let r = rank_entries(&values, &e, &st());
        let first = r.iter().find(|x| x.rank == 1).unwrap();
        // 7.0 * 2.0 = 14.0
        assert_eq!(first.points, 14.0);
        let second = r.iter().find(|x| x.rank == 2).unwrap();
        assert_eq!(second.points, 10.0); // 5.0 * 2.0
    }

    #[test]
    fn rank_team_multiplier_not_applied_to_individual() {
        let e = ev("男子100米", "径赛", false, "时间", None);
        let r = rank_entries(&[Some(12.0)], &e, &st());
        assert_eq!(r[0].points, 7.0); // 不加倍
    }

    // ---------------- 破纪录判定 ----------------

    #[test]
    fn record_broken_track() {
        // 径赛：时间更短才算破
        let e = ev("男子100米", "径赛", false, "时间", Some(12.0));
        let values = vec![Some(11.5), Some(12.0), Some(12.5)];
        let r = rank_entries(&values, &e, &st());
        let by_idx = |i: usize| r.iter().find(|x| x.entry_index == i).unwrap().clone();
        assert!(by_idx(0).broke_record, "11.5 < 12.0 应破纪录");
        assert!(!by_idx(1).broke_record, "等于纪录不算破");
        assert!(!by_idx(2).broke_record, "慢于纪录不算破");
        // 破纪录者额外 +7
        assert_eq!(by_idx(0).points, 7.0 + 7.0);
    }

    #[test]
    fn record_broken_field() {
        // 田赛：数值更大才算破
        let e = ev("跳远", "田赛", false, "米", Some(5.0));
        let values = vec![Some(5.5), Some(5.0), Some(4.5)];
        let r = rank_entries(&values, &e, &st());
        let by_idx = |i: usize| r.iter().find(|x| x.entry_index == i).unwrap().clone();
        assert!(by_idx(0).broke_record, "5.5 > 5.0 应破纪录");
        assert!(!by_idx(1).broke_record, "等于纪录不算破");
        assert!(!by_idx(2).broke_record);
        assert_eq!(by_idx(0).points, 14.0);
    }

    #[test]
    fn record_broken_within_tolerance_not_counted() {
        // 差异在 1e-9 容差内不算破纪录（浮点抖动不应误判）
        let e = ev("男子100米", "径赛", false, "时间", Some(12.0));
        let r = rank_entries(&[Some(12.0 - 1e-12)], &e, &st());
        assert!(!r[0].broke_record, "容差内的差异不判破纪录");
    }

    #[test]
    fn record_none_never_broken() {
        let e = ev("男子200米", "径赛", false, "时间", None);
        let r = rank_entries(&[Some(1.0)], &e, &st());
        assert!(!r[0].broke_record, "无校纪录时永不判破");
        assert_eq!(r[0].points, 7.0);
    }

    #[test]
    fn record_bonus_plus_team_multiplier() {
        // 集体项目破纪录：先乘倍数再加破纪录分
        let e = ev("4×100米接力", "径赛", true, "时间", Some(55.0));
        let r = rank_entries(&[Some(54.0)], &e, &st());
        assert!(r[0].broke_record);
        // 7.0 * 2.0 + 7.0 = 21.0
        assert_eq!(r[0].points, 21.0);
    }

    // ---------------- 年级总表 ----------------

    /// 构造一条已赋分成绩。
    fn mk_result(grade: &str, class_no: i64, points: f64, broke: bool) -> DomainResult {
        DomainResult {
            id: 0,
            event_id: 1,
            student_id: Some(1),
            grade: grade.into(),
            class_no: Some(class_no),
            score_text: String::new(),
            score_value: Some(1.0),
            rank: Some(1),
            points: Some(points),
            broke_record: broke,
        }
    }

    #[test]
    fn grade_total_aggregates_and_ranks() {
        let data = Data {
            results: vec![
                mk_result("初一", 1, 7.0, false),
                mk_result("初一", 1, 5.0, false), // 一班共 12.0
                mk_result("初一", 2, 7.0, true),  // 二班 7.0 + 1 次破纪录
                mk_result("初二", 1, 99.0, false), // 其他年级不应混入
            ],
            ..Default::default()
        };
        let table = grade_total_table(&data, "初一");
        assert_eq!(table.len(), 2);
        // 一班总分高，应排第 1
        assert_eq!(table[0].get_str("class").unwrap(), "初一1班");
        assert_eq!(table[0].get_i64("total").unwrap(), 12);
        assert_eq!(table[0].get_i64("rank").unwrap(), 1);
        assert_eq!(table[1].get_str("class").unwrap(), "初一2班");
        assert_eq!(table[1].get_i64("rank").unwrap(), 2);
        assert_eq!(table[1].get_i64("records").unwrap(), 1); // 破纪录计数
    }

    #[test]
    fn grade_total_tie_same_rank() {
        let data = Data {
            results: vec![
                mk_result("初一", 1, 10.0, false),
                mk_result("初一", 2, 10.0, false),
                mk_result("初一", 3, 5.0, false),
            ],
            ..Default::default()
        };
        let table = grade_total_table(&data, "初一");
        // 前两名并列第 1，第三名顺延为第 3
        assert_eq!(table[0].get_i64("rank").unwrap(), 1);
        assert_eq!(table[1].get_i64("rank").unwrap(), 1);
        assert_eq!(table[2].get_i64("rank").unwrap(), 3);
    }

    #[test]
    fn grade_total_ignores_unscored() {
        let mut data = Data::default();
        let mut r = mk_result("初一", 1, 0.0, false);
        r.points = None; // 未赋分
        data.results = vec![r, mk_result("初一", 2, 3.0, false)];
        let table = grade_total_table(&data, "初一");
        assert_eq!(table.len(), 1, "未赋分记录不应出现在总表");
        assert_eq!(table[0].get_str("class").unwrap(), "初一2班");
    }

    #[test]
    fn grade_total_empty_grade() {
        let data = Data::default();
        assert!(grade_total_table(&data, "初三").is_empty());
    }
}
