//! v1.9.10：团体总分表（与学校《校运会得分表》最后一页同版式）。
//!
//! 老师手上的《2026 学年八年级校运会得分表》最后一页是一张矩阵：
//!
//! ```text
//!              初二级团体总分表                  ← 合并居中
//!   项目     初二1 初二2 初二3 … 初二15
//!   100米      12    9     7   …
//!   …
//!   摸高        5    2     4   …
//!   合计       86   74    69   …
//!   名次        1    2     3   …
//! ```
//!
//! 本模块把系统里已算好的 `results.points` 按「项目行 × 班级列」聚合，
//! 直接产出同构表格与 xlsx —— 老师不必再手工把分数抄进 Excel。
//!
//! 两条硬约定：
//!
//! 1. **分数只认 `points`**。未算分的项目 `points` 是 None，这里不猜、
//!    不按名次现算（现算会与系统的破纪录加分/集体倍数脱节），而是把
//!    这些项目回报给调用方，由界面提示「先去算分」。
//! 2. **行顺序照抄学校原表**，不按项目 id 排。老师拿到的表要和原来那张
//!    对得上，行序变了会被当成两张表。原表没有的项目（铅球、跳高、
//!    三级跳远等）只在确有成绩时追加在末尾，不凭空多出空行。

use crate::core::store::Data;
use rust_xlsxwriter::{Color, Format, FormatAlign, FormatBorder, Workbook};
use std::collections::BTreeMap;

/// 学校得分表最后一页的项目行（顺序即原表顺序）。
///
/// `keys` 命中任一即归入本行；`avoid` 命中则排除 —— 「三级跳远」含
/// 「跳远」，不排除就会被算进跳远行。
struct RowDef {
    label: &'static str,
    keys: &'static [&'static str],
    avoid: &'static [&'static str],
}

const ROWS: &[RowDef] = &[
    // 「4×100米接力」也含「100米」，靠 avoid 归到接力行，否则会被算成 100 米
    RowDef { label: "100米", keys: &["100米"], avoid: &["1000", "接力"] },
    RowDef { label: "200米", keys: &["200米"], avoid: &[] },
    RowDef { label: "400米", keys: &["400米"], avoid: &[] },
    RowDef { label: "800米", keys: &["800米"], avoid: &[] },
    RowDef { label: "1000米", keys: &["1000米"], avoid: &[] },
    RowDef {
        label: "4*100米接力",
        keys: &["4×100", "4*100", "4x100", "4X100", "4乘100"],
        avoid: &[],
    },
    RowDef { label: "跳远", keys: &["跳远"], avoid: &["三级"] },
    RowDef { label: "立定三级蛙跳", keys: &["蛙跳"], avoid: &[] },
    RowDef { label: "单手推实心球", keys: &["实心球"], avoid: &[] },
    RowDef { label: "跳绳", keys: &["跳绳"], avoid: &[] },
    RowDef { label: "引体向上", keys: &["引体"], avoid: &[] },
    RowDef { label: "一分钟仰卧起坐", keys: &["仰卧"], avoid: &[] },
    RowDef { label: "毽球", keys: &["毽", "沙包"], avoid: &[] },
    RowDef { label: "摸高", keys: &["摸高"], avoid: &[] },
];

/// 项目短名：去掉「男子/女子/男/女」前缀，用于追加行与合并同名。
fn short_name(name: &str) -> String {
    name.trim()
        .trim_start_matches("男子")
        .trim_start_matches("女子")
        .trim_start_matches(['男', '女'])
        .trim()
        .to_string()
}

/// 项目名 → 行下标（`ROWS` 顺序）；不属原表 14 行时返回 None。
pub fn row_index(event_name: &str) -> Option<usize> {
    let n = event_name;
    for (i, def) in ROWS.iter().enumerate() {
        if def.avoid.iter().any(|a| n.contains(a)) {
            continue;
        }
        if def.keys.iter().any(|k| n.contains(k)) {
            return Some(i);
        }
    }
    None
}

/// 一行（一个项目）的横向得分。
pub struct TableRow {
    pub label: String,
    /// 与 `classes` 等长；None 表示该项目该班无成绩
    pub cells: Vec<Option<f64>>,
}

/// 团体总分表。
pub struct TotalTable {
    pub grade: String,
    /// 标题，与学校原表一致：「初二级团体总分表」
    pub title: String,
    /// 班级号（升序），表头显示为「初二1」
    pub classes: Vec<i64>,
    pub rows: Vec<TableRow>,
    /// 各班合计（与 classes 等长）
    pub totals: Vec<f64>,
    /// 各班名次（并列同名次）
    pub ranks: Vec<i64>,
    /// 有成绩但还没算分的项目名（`points` 为 None）
    pub pending: Vec<String>,
    /// 没有成绩的项目名（表里该行全空，用于提示「这项还没录」）
    pub empty_rows: Vec<String>,
    /// 班级列的来源：`data`（名单/成绩里出现的班）或 `settings`（还没有名单，
    /// 按设置里的班级数铺满）。后者要在界面上说明，否则老师会以为多出来的空列是 bug。
    pub class_source: &'static str,
}

impl TotalTable {
    pub fn class_label(&self, no: i64) -> String {
        format!("{}{}", self.grade, no)
    }
}

/// 该年级出现在数据里的班号（学生 / 报名 / 成绩任一处有即算）。
///
/// 不直接用 `settings.class_count`：学校表只列有比赛的班（初二 15 个），
/// 按设置里的 20 生成会多出 5 个空列，与原表对不上。
fn classes_of(d: &Data, grade: &str) -> (Vec<i64>, &'static str) {
    let mut set: BTreeMap<i64, ()> = BTreeMap::new();
    for s in &d.students {
        if s.grade == grade {
            set.insert(s.class_no, ());
        }
    }
    for r in &d.results {
        if r.grade == grade {
            if let Some(c) = r.class_no {
                set.insert(c, ());
            }
        }
    }
    if set.is_empty() {
        // 完全没有数据的新库：按设置里的班级数铺满，让老师能先看版式
        for c in 1..=d.settings.class_count.max(1) {
            set.insert(c, ());
        }
        return (set.into_keys().collect(), "settings");
    }
    (set.into_keys().collect(), "data")
}

/// 构造某年级的团体总分表。
pub fn build(d: &Data, grade: &str) -> TotalTable {
    let (classes, class_source) = classes_of(d, grade);
    let col_of = |no: i64| classes.iter().position(|c| *c == no);

    // 项目 → 行下标。原表 14 行之外的，按短名追加在末尾。
    let mut extra: Vec<String> = Vec::new();
    let mut ev_row: BTreeMap<i64, usize> = BTreeMap::new();
    for ev in &d.events {
        if let Some(i) = row_index(&ev.name) {
            ev_row.insert(ev.id, i);
        } else {
            let label = short_name(&ev.name);
            // 只给「确实有成绩」的额外项目开行，避免空行污染版式
            if !has_score(d, ev.id) {
                continue;
            }
            let idx = match extra.iter().position(|x| *x == label) {
                Some(i) => i,
                None => {
                    extra.push(label);
                    extra.len() - 1
                }
            };
            ev_row.insert(ev.id, ROWS.len() + idx);
        }
    }

    let total_rows = ROWS.len() + extra.len();
    let mut labels: Vec<String> = ROWS.iter().map(|r| r.label.to_string()).collect();
    labels.extend(extra.iter().cloned());

    // (行, 列) → 得分；同一行同一班可能有多人（最多 2 人）或多个项目（男女）
    let mut acc: BTreeMap<(usize, usize), f64> = BTreeMap::new();
    let mut pending: Vec<String> = Vec::new();
    for r in &d.results {
        if r.grade != grade {
            continue;
        }
        let Some(&ri) = ev_row.get(&r.event_id) else {
            continue;
        };
        let Some(c) = r.class_no else { continue };
        let Some(ci) = col_of(c) else { continue };
        match r.points {
            Some(p) => *acc.entry((ri, ci)).or_insert(0.0) += p,
            None => {
                let name = d
                    .events
                    .iter()
                    .find(|e| e.id == r.event_id)
                    .map(|e| e.name.clone())
                    .unwrap_or_else(|| format!("项目{}", r.event_id));
                if !pending.contains(&name) {
                    pending.push(name);
                }
            }
        }
    }

    let rows: Vec<TableRow> = (0..total_rows)
        .map(|ri| TableRow {
            label: labels[ri].clone(),
            cells: (0..classes.len()).map(|ci| acc.get(&(ri, ci)).copied()).collect(),
        })
        .collect();

    let empty_rows: Vec<String> = rows
        .iter()
        .filter(|r| r.cells.iter().all(|c| c.is_none()))
        .map(|r| r.label.clone())
        .collect();

    let totals: Vec<f64> = (0..classes.len())
        .map(|ci| rows.iter().filter_map(|r| r.cells[ci]).sum())
        .collect();

    // 名次：按合计降序，并列同名次（与年级总成绩表同口径）
    let mut order: Vec<usize> = (0..classes.len()).collect();
    order.sort_by(|a, b| totals[*b].partial_cmp(&totals[*a]).unwrap_or(std::cmp::Ordering::Equal));
    let mut ranks = vec![0i64; classes.len()];
    let mut last_total: Option<f64> = None;
    let mut last_rank = 0i64;
    for (pos, ci) in order.iter().enumerate() {
        let rank = match last_total {
            Some(t) if (totals[*ci] - t).abs() < 1e-9 => last_rank,
            _ => {
                last_rank = (pos + 1) as i64;
                last_rank
            }
        };
        last_total = Some(totals[*ci]);
        ranks[*ci] = rank;
    }

    // 学校原表写法是「初二级团体总分表」，年级名 + 级
    TotalTable {
        grade: grade.to_string(),
        title: format!("{}级团体总分表", grade),
        classes,
        rows,
        totals,
        ranks,
        pending,
        empty_rows,
        class_source,
    }
}

fn has_score(d: &Data, event_id: i64) -> bool {
    d.results
        .iter()
        .any(|r| r.event_id == event_id && r.score_value.is_some())
}

/// 数值写单元格：整数值写成整数，避免「7.0」这种别扭显示。
fn write_num(sheet: &mut rust_xlsxwriter::Worksheet, row: u32, col: u16, v: f64, f: &Format) {
    if (v - v.round()).abs() < 1e-9 {
        sheet.write_number_with_format(row, col, v.round(), f).ok();
    } else {
        sheet.write_number_with_format(row, col, v, f).ok();
    }
}

/// 渲染 xlsx：一张 sheet，版式照抄学校得分表最后一页。
pub fn to_xlsx(t: &TotalTable) -> Vec<u8> {
    let mut wb = Workbook::new();
    let sheet = wb.add_worksheet();
    sheet.set_name(&t.grade).ok();

    let last_col = t.classes.len() as u16; // 0 列是「项目」

    let title_fmt = Format::new()
        .set_bold()
        .set_font_size(16)
        .set_align(FormatAlign::Center)
        .set_align(FormatAlign::VerticalCenter);
    let head_fmt = Format::new()
        .set_bold()
        .set_align(FormatAlign::Center)
        .set_align(FormatAlign::VerticalCenter)
        .set_border(FormatBorder::Thin)
        .set_background_color(Color::RGB(0xD9_E1_F2));
    let name_fmt = Format::new()
        .set_align(FormatAlign::Left)
        .set_align(FormatAlign::VerticalCenter)
        .set_border(FormatBorder::Thin);
    let cell_fmt = Format::new()
        .set_align(FormatAlign::Center)
        .set_align(FormatAlign::VerticalCenter)
        .set_border(FormatBorder::Thin);
    let sum_fmt = Format::new()
        .set_bold()
        .set_align(FormatAlign::Center)
        .set_border(FormatBorder::Thin)
        .set_background_color(Color::RGB(0xFF_F2_CC));
    let rank_fmt = Format::new()
        .set_bold()
        .set_align(FormatAlign::Center)
        .set_border(FormatBorder::Thin)
        .set_background_color(Color::RGB(0xE2_EF_DA));

    // 标题
    sheet.merge_range(0, 0, 0, last_col, &t.title, &title_fmt).ok();
    sheet.set_row_height(0, 30).ok();

    // 表头
    sheet.write_string_with_format(1, 0, "项目", &head_fmt).ok();
    for (i, c) in t.classes.iter().enumerate() {
        sheet
            .write_string_with_format(1, i as u16 + 1, &t.class_label(*c), &head_fmt)
            .ok();
    }

    // 项目行
    for (ri, row) in t.rows.iter().enumerate() {
        let r = ri as u32 + 2;
        sheet.write_string_with_format(r, 0, &row.label, &name_fmt).ok();
        for (ci, cell) in row.cells.iter().enumerate() {
            if let Some(v) = cell {
                write_num(sheet, r, ci as u16 + 1, *v, &cell_fmt);
            } else {
                sheet.write_blank(r, ci as u16 + 1, &cell_fmt).ok();
            }
        }
    }

    // 合计、名次
    let tr = t.rows.len() as u32 + 2;
    sheet.write_string_with_format(tr, 0, "合计", &sum_fmt).ok();
    for (i, v) in t.totals.iter().enumerate() {
        write_num(sheet, tr, i as u16 + 1, *v, &sum_fmt);
    }
    sheet.write_string_with_format(tr + 1, 0, "名次", &rank_fmt).ok();
    for (i, v) in t.ranks.iter().enumerate() {
        sheet
            .write_number_with_format(tr + 1, i as u16 + 1, *v as f64, &rank_fmt)
            .ok();
    }

    // 列宽：项目列宽一点，班级列等宽
    sheet.set_column_width(0, 18).ok();
    for i in 0..=t.classes.len() as u16 {
        sheet.set_column_width(i + 1, 8).ok();
    }
    sheet.set_freeze_panes(2, 1).ok();

    wb.save_to_buffer().unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::model::{Event, Result as DomainResult, Student};

    fn ev(id: i64, name: &str, gender: &str) -> Event {
        Event {
            id,
            name: name.into(),
            category: "径赛".into(),
            gender: gender.into(),
            grade: "全部".into(),
            is_team: false,
            unit: "时间".into(),
            record: None,
        }
    }

    fn data() -> Data {
        let mut d = Data::default();
        d.events = vec![
            ev(1, "男子100米", "男子"),
            ev(2, "女子100米", "女子"),
            ev(3, "男子跳远", "男子"),
            ev(4, "男子三级跳远", "男子"),
            ev(5, "摸高", "男子"),
        ];
        d.students = (1..=4)
            .map(|i| Student {
                id: i,
                grade: "初二".into(),
                class_no: if i <= 2 { 1 } else { 2 },
                name: format!("学生{}", i),
                gender: "男".into(),
            })
            .collect();
        d
    }

    fn push(d: &mut Data, ev_id: i64, class: i64, points: Option<f64>, has_score: bool) {
        let id = d.next_result_id;
        d.next_result_id += 1;
        d.results.push(DomainResult {
            id,
            event_id: ev_id,
            student_id: None,
            grade: "初二".into(),
            class_no: Some(class),
            score_text: "12.0".into(),
            score_value: if has_score { Some(12.0) } else { None },
            rank: None,
            points,
            broke_record: false,
        });
    }

    #[test]
    fn row_order_follows_school_sheet() {
        assert_eq!(row_index("男子100米"), Some(0));
        assert_eq!(row_index("女子1000米"), Some(4));
        assert_eq!(row_index("男子4×100米接力"), Some(5));
        assert_eq!(row_index("女子跳远"), Some(6));
        // 三级跳远不能算进跳远行
        assert_eq!(row_index("男子三级跳远"), None);
        assert_eq!(row_index("立定三级蛙跳"), Some(7));
        assert_eq!(row_index("女子立定三级蛙跳"), Some(7));
        assert_eq!(row_index("男子实心球"), Some(8));
        assert_eq!(row_index("投掷沙包"), Some(12));
        assert_eq!(row_index("一分钟仰卧起坐"), Some(11));
        assert_eq!(row_index("女子摸高"), Some(13));
    }

    #[test]
    fn sums_points_by_class_and_project() {
        let mut d = data();
        push(&mut d, 1, 1, Some(7.0), true);
        push(&mut d, 2, 1, Some(5.0), true); // 同一行两个项目
        push(&mut d, 1, 2, Some(4.0), true);
        push(&mut d, 5, 2, Some(3.0), true);
        let t = build(&d, "初二");
        assert_eq!(t.classes, vec![1, 2]);
        let r100 = &t.rows[0];
        assert_eq!(r100.label, "100米");
        assert_eq!(r100.cells, vec![Some(12.0), Some(4.0)]);
        let rmo = &t.rows[13];
        assert_eq!(rmo.label, "摸高");
        assert_eq!(rmo.cells, vec![None, Some(3.0)]);
        assert_eq!(t.totals, vec![12.0, 7.0]);
        assert_eq!(t.ranks, vec![1, 2]);
    }

    #[test]
    fn unscored_events_are_reported_not_guessed() {
        let mut d = data();
        push(&mut d, 1, 1, None, true); // 有成绩未算分
        let t = build(&d, "初二");
        assert_eq!(t.pending, vec!["男子100米"]);
        assert_eq!(t.totals, vec![0.0, 0.0]);
        assert!(t.ranks.iter().all(|r| *r == 1)); // 全 0 并列
    }

    #[test]
    fn extra_projects_appear_only_when_scored() {
        let mut d = data();
        push(&mut d, 4, 1, Some(2.0), true); // 三级跳远：原表没有
        let t = build(&d, "初二");
        assert_eq!(t.rows.len(), ROWS.len() + 1);
        assert_eq!(t.rows.last().unwrap().label, "三级跳远");
        assert_eq!(t.totals, vec![2.0, 0.0]);
    }

    #[test]
    fn xlsx_is_valid_zip() {
        let mut d = data();
        push(&mut d, 1, 1, Some(7.0), true);
        let t = build(&d, "初二");
        let bytes = to_xlsx(&t);
        assert!(bytes.starts_with(b"PK\x03\x04"));
        assert!(bytes.len() > 2000);
    }
}
