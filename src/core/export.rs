//! v1.1 导出模块（核心模块）：把数据导出为多种文件格式。
//!
//! 支持格式：csv / tsv / md(Markdown) / html / xlsx / json
//! 数据类型：results(项目成绩) / registrations(报名) / students(学生) / all(全部)
//!
//! 设计：`table_*` 系列函数产出统一二维表（含表头行），各格式渲染器
//! 均以二维表为输入，新增格式只需新增一个渲染函数。

use crate::core::model::{Event, Registration};
use crate::core::store::Data;
use rust_xlsxwriter::Workbook;

/// 导出结果：(文件名, 字节流, Content-Type)
pub struct Exported {
    pub filename: String,
    pub bytes: Vec<u8>,
    pub content_type: &'static str,
}

// ---------------------------------------------------------------------------
// 二维表数据（列顺序即导出列顺序）
// ---------------------------------------------------------------------------

pub fn table_students(d: &Data) -> Vec<Vec<String>> {
    let mut t = vec![vec![
        "年级".into(),
        "班级".into(),
        "姓名".into(),
        "性别".into(),
    ]];
    for s in &d.students {
        t.push(vec![
            s.grade.clone(),
            s.class_no.to_string(),
            s.name.clone(),
            s.gender.clone(),
        ]);
    }
    t
}

pub fn table_registrations(d: &Data) -> Vec<Vec<String>> {
    let mut t = vec![vec![
        "项目".into(),
        "年级".into(),
        "班级".into(),
        "姓名".into(),
        "备注".into(),
    ]];
    let mut regs: Vec<&Registration> = d.registrations.iter().collect();
    regs.sort_by_key(|r| (r.event_id, r.student_id));
    for r in regs {
        let ev = d.events.iter().find(|e| e.id == r.event_id);
        let s = d.students.iter().find(|s| s.id == r.student_id);
        t.push(vec![
            ev.map(|e| e.name.clone()).unwrap_or_default(),
            s.map(|s| s.grade.clone()).unwrap_or_default(),
            s.map(|s| s.class_no.to_string()).unwrap_or_default(),
            s.map(|s| s.name.clone()).unwrap_or_default(),
            r.note.clone(),
        ]);
    }
    t
}

pub fn table_results(d: &Data) -> Vec<Vec<String>> {
    let mut t = vec![vec![
        "项目".into(),
        "参赛者".into(),
        "成绩".into(),
        "名次".into(),
        "得分".into(),
        "破纪录".into(),
    ]];
    for r in &d.results {
        let ev = d.events.iter().find(|e| e.id == r.event_id);
        let label = if let Some(sid) = r.student_id {
            d.students
                .iter()
                .find(|s| s.id == sid)
                .map(|s| format!("{}（{}）", s.name, s.class_name()))
                .unwrap_or_else(|| format!("ID {}", sid))
        } else {
            format!("{}{}班", r.grade, r.class_no.unwrap_or(0))
        };
        t.push(vec![
            ev.map(|e| e.name.clone()).unwrap_or_default(),
            label,
            r.score_text.clone(),
            r.rank.map(|x| x.to_string()).unwrap_or_default(),
            r.points.map(|x| x.to_string()).unwrap_or_default(),
            if r.broke_record { "是".into() } else { String::new() },
        ]);
    }
    t
}

fn table_by_type(d: &Data, typ: &str) -> Option<(String, Vec<Vec<String>>)> {
    match typ {
        "students" => Some(("学生名单".into(), table_students(d))),
        "registrations" => Some(("报名表".into(), table_registrations(d))),
        "results" => Some(("成绩表".into(), table_results(d))),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// 文本格式渲染（csv 由 store.rs 既有函数提供，这里补 tsv / md / html）
// ---------------------------------------------------------------------------

fn join_cells(cells: &[String], sep: &str) -> String {
    cells
        .iter()
        .map(|c| c.replace(sep, " "))
        .collect::<Vec<_>>()
        .join(sep)
}

pub fn render_tsv(table: &[Vec<String>]) -> String {
    let mut lines: Vec<String> = Vec::new();
    for row in table {
        lines.push(join_cells(row, "\t"));
    }
    lines.join("\n") + "\n"
}

pub fn render_md(table: &[Vec<String>]) -> String {
    if table.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    out.push_str(&format!("| {} |\n", join_cells(&table[0], " | ")));
    let sep: String = table[0].iter().map(|_| " --- |").collect();
    out.push_str(&format!("|{}\n", sep));
    for row in &table[1..] {
        out.push_str(&format!("| {} |\n", join_cells(row, " | ")));
    }
    out
}

fn esc_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn render_html(title: &str, table: &[Vec<String>]) -> String {
    let mut out = String::new();
    out.push_str("<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"UTF-8\">");
    out.push_str("<title>");
    out.push_str(&esc_html(title));
    out.push_str("</title><style>body{font-family:\"Microsoft YaHei\",sans-serif;");
    out.push_str("margin:40px;color:#0f172a}table{border-collapse:collapse;width:100%}");
    out.push_str("th,td{border:1px solid #e2e8f0;padding:8px 12px;font-size:14px;text-align:left}");
    out.push_str("th{background:#eff6ff}tr:nth-child(even){background:#f8fafc}");
    out.push_str("h2{color:#1e3a8a}</style></head><body>");
    out.push_str("<h2>");
    out.push_str(&esc_html(title));
    out.push_str("</h2><table>");
    for (i, row) in table.iter().enumerate() {
        let tag = if i == 0 { "th" } else { "td" };
        out.push_str("<tr>");
        for c in row {
            out.push_str(&format!("<{t}>{}</{t}>", esc_html(c), t = tag));
        }
        out.push_str("</tr>");
    }
    out.push_str("</table><p style=\"color:#64748b;font-size:12px;margin-top:16px;\">同和中学校运会积分系统 v1.1 导出 · 2026届二班 曾令韬 制作</p></body></html>");
    out
}

// ---------------------------------------------------------------------------
// xlsx 渲染（单表或 all 三张表）
// ---------------------------------------------------------------------------

fn write_sheet(wb: &mut Workbook, name: &str, table: &[Vec<String>]) {
    let sheet = wb.add_worksheet();
    sheet.set_name(name).ok();
    // 表头加粗
    let bold = rust_xlsxwriter::Format::new().set_bold();
    for (col, cell) in table.first().map(|h| h.as_slice()).unwrap_or(&[]).iter().enumerate() {
        sheet.write_with_format(0, col as u16, cell, &bold).ok();
    }
    for (ri, row) in table.iter().enumerate().skip(1) {
        for (ci, cell) in row.iter().enumerate() {
            sheet.write(ri as u32, ci as u16, cell).ok();
        }
    }
    sheet.autofit();
}

pub fn render_xlsx(d: &Data, typ: &str) -> Vec<u8> {
    let mut wb = Workbook::new();
    if typ == "all" {
        write_sheet(&mut wb, "成绩表", &table_results(d));
        write_sheet(&mut wb, "报名表", &table_registrations(d));
        write_sheet(&mut wb, "学生名单", &table_students(d));
    } else if let Some((name, table)) = table_by_type(d, typ) {
        write_sheet(&mut wb, &name, &table);
    }
    wb.save_to_buffer().unwrap_or_default()
}

// ---------------------------------------------------------------------------
// v1.9.3：报名表模板（下载 → 用 Excel 填写 → 直接上传导入）
//
// 之所以还要在程序里生成模板：v1.9.0 的导入链路依赖源码包里的
// Python 脚本把 xlsx 转 JSON，而发行包里没有任何脚本 —— 老师拿到 exe
// 后其实用不了「导入」。这里补上闭环：模板由系统按当前项目列表生成，
// 表头列就是系统里真实存在的项目，填完的同一个文件可直接回传。
//
// 版式沿用学校现成的报名表：一张表里男女两节，项目列打勾。
// 这样老师手头已有的旧报名表也能直接上传，不必先照新格式重抄一遍。
// ---------------------------------------------------------------------------

/// 项目列显示名：去掉性别前缀，贴合学校原表的「100米」写法。
fn bm_short(name: &str) -> String {
    name.trim_start_matches("男子")
        .trim_start_matches("女子")
        .trim_start_matches(['男', '女'])
        .to_string()
}

/// 某一节的项目列：先放本节专属项目，再放通用项目，重名只留一次。
fn bm_cols(events: &[Event], group: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for e in events.iter().filter(|e| e.gender == group) {
        let s = bm_short(&e.name);
        if !out.contains(&s) {
            out.push(s);
        }
    }
    for e in events
        .iter()
        .filter(|e| e.gender != "男子" && e.gender != "女子")
    {
        let s = bm_short(&e.name);
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

fn bm_blank_row(seq: i64, width: usize) -> Vec<String> {
    let mut r = vec![seq.to_string()];
    r.resize(width, String::new());
    r
}

/// 报名表二维表（Sheet1）。表头行以「姓名」开头，解析器据此分节。
pub fn baoming_template_rows(events: &[Event]) -> Vec<Vec<String>> {
    let male = bm_cols(events, "男子");
    let female = bm_cols(events, "女子");
    let mut rows: Vec<Vec<String>> = Vec::new();
    rows.push(vec![
        "同和中学校运会 · 运动员报名表（下载后填写，保存即可上传导入）".into(),
    ]);

    let section = |rows: &mut Vec<Vec<String>>, title: &str, cols: &[String], seq_end: i64| {
        let mut head = vec!["序号".into(), format!("姓名（{}）", title), "班别".into()];
        head.extend(cols.iter().cloned());
        head.push("备注".into());
        let width = head.len();
        rows.push(head);
        // 示例行：姓名含「示例」，导入时自动跳过。
        let mut ex = vec![
            "1".into(),
            format!("{}（示例）", if title == "男" { "张三" } else { "李四" }),
            "初一1".into(),
        ];
        ex.extend((0..cols.len()).map(|i| if i == 0 { "√".into() } else { String::new() }));
        ex.push("示例行，导入时自动跳过；可删除或改写成真实学生".into());
        rows.push(ex);
        for i in 2..=seq_end {
            rows.push(bm_blank_row(i, width));
        }
        rows.push(bm_blank_row(0, width));
    };
    section(&mut rows, "男", &male, 11);
    section(&mut rows, "女", &female, 11);
    rows.push(vec![
        "填写说明：项目列打 √ 表示报名；每人最多 2 个项目；班别写「初一1」或「初一（1）班」；不要改表头文字。".into(),
    ]);
    rows
}

/// 「填写说明」二维表（Sheet2）：规则 + 当前系统项目对照，避免列名歧义。
pub fn baoming_template_notes(events: &[Event]) -> Vec<Vec<String>> {
    let mut t = vec![vec!["填写说明".into(), String::new()]];
    for (k, v) in [
        ("怎么填", "下载本文件 → 用 Excel 打开 → 在「报名表」页按男女分节填姓名、班别，在要报的项目列打 √ → 保存 → 回到系统「报名表导入」上传这个文件。"),
        ("班别写法", "初一1 / 初一（1）班 / 初一1班 / 奥创七7 均可；年级与班号必须能分开，写不清的行会在导入报告里列出，不会瞎猜。"),
        ("勾选标记", "√ ✓ ✔ ● ○ Y y 是 1 或「报名/参加/参赛」都算报名；× 不算（表示划掉）。"),
        ("示例行", "姓名里带「示例」的行自动跳过，可以直接删掉。"),
        ("重复导入", "增量语义：已存在的学生和报名会跳过并列出，不会翻倍，也不会覆盖已有数据。"),
        ("清空重来", "报名页新增「清空报名」，可按全部/项目/年级/班级清空，且一次撤销即可全部恢复。"),
        ("每人限额", "学校规则：每名同学最多报 2 个项目；超限的会被跳过并在报告里说明。"),
        ("旧表兼容", "手头已有的旧报名表（男女分节、项目列打勾）可直接上传，不用照本模板重抄。"),
    ] {
        t.push(vec![k.into(), v.into()]);
    }
    t.push(vec!["— 当前系统项目对照 —".into(), String::new()]);
    t.push(vec!["分组".into(), "系统项目名".into()]);
    for e in events {
        t.push(vec![e.gender.clone(), e.name.clone()]);
    }
    t
}

pub fn baoming_template_xlsx(events: &[Event]) -> Vec<u8> {
    let mut wb = Workbook::new();
    write_sheet(&mut wb, "报名表", &baoming_template_rows(events));
    write_sheet(&mut wb, "填写说明", &baoming_template_notes(events));
    wb.save_to_buffer().unwrap_or_default()
}

fn bm_csv_escape(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

/// CSV 版模板：与 xlsx 同版式，带 UTF-8 BOM 保证 Excel 双击不乱码。
pub fn baoming_template_csv(events: &[Event]) -> Vec<u8> {
    let mut out = vec![0xEF, 0xBB, 0xBF];
    for row in baoming_template_rows(events) {
        let line = row
            .iter()
            .map(|c| bm_csv_escape(c))
            .collect::<Vec<_>>()
            .join(",");
        out.extend_from_slice(line.as_bytes());
        out.push(b'\n');
    }
    out
}

// ---------------------------------------------------------------------------
// v1.9.7：名单模板（只导人选，项目稍后在「报名」页选）
//
// 学校实际流程常常是「先拿到各班名单，再一项一项定项目」——
// 原来的报名表要求一次把项目勾完，名单和项目绑死在一起。
// 这里单独给一份纯名单模板：姓名 / 年级 / 班级 / 性别 / 学号，
// 不含任何项目列，导入后学生进入名单，再在报名页慢慢选。
// ---------------------------------------------------------------------------

pub fn roster_template_rows() -> Vec<Vec<String>> {
    let width = 5;
    let mut rows: Vec<Vec<String>> = Vec::new();
    rows.push(vec![
        "同和中学校运会 · 参赛名单（只导人选；项目请在系统「报名」页选）".into(),
    ]);
    rows.push(vec![
        "姓名".into(),
        "年级".into(),
        "班级".into(),
        "性别".into(),
        "学号".into(),
    ]);
    // 示例行：姓名含「示例」，导入时自动跳过。
    rows.push(vec![
        "张三（示例）".into(),
        "初一".into(),
        "1".into(),
        "男".into(),
        "2601".into(),
    ]);
    for _ in 0..15 {
        rows.push(vec![String::new(); width]);
    }
    // 说明行刻意放在第二列：第一列留空，解析器按「姓名为空」直接跳过，
    // 不会把说明文字当成一名学生。
    rows.push(vec![
        String::new(),
        "填写说明：姓名必填；年级写「初一」、班级写「1」（或班级直接写「初一1」也可）；\
         性别不填时报名阶段需人工确认；示例行导入时自动跳过；已存在的学生会自动跳过，不会覆盖。"
            .into(),
        String::new(),
        String::new(),
        String::new(),
    ]);
    rows
}

pub fn roster_template_xlsx() -> Vec<u8> {
    let mut wb = Workbook::new();
    write_sheet(&mut wb, "名单", &roster_template_rows());
    wb.save_to_buffer().unwrap_or_default()
}

pub fn roster_template_csv() -> Vec<u8> {
    let mut out = vec![0xEF, 0xBB, 0xBF];
    for row in roster_template_rows() {
        let line = row
            .iter()
            .map(|c| bm_csv_escape(c))
            .collect::<Vec<_>>()
            .join(",");
        out.extend_from_slice(line.as_bytes());
        out.push(b'\n');
    }
    out
}

// ---------------------------------------------------------------------------
// 统一入口
// ---------------------------------------------------------------------------

/// 支持的格式列表（供 /api/meta 或文档展示）。
pub const SUPPORTED_FORMATS: &[&str] = &["csv", "tsv", "md", "html", "xlsx", "json"];

pub fn export(d: &Data, fmt: &str, typ: &str) -> Result<Exported, String> {
    let typ = if typ.is_empty() { "results" } else { typ };
    match fmt {
        "csv" => {
            let body = match typ {
                "students" => crate::core::api::csv_students_pub(d),
                "registrations" => crate::core::api::csv_registrations_pub(d),
                "results" => crate::core::api::csv_results_pub(d),
                _ => return Err("type 仅支持 students/registrations/results".into()),
            };
            Ok(Exported {
                filename: format!("{}.csv", typ),
                bytes: body.into_bytes(),
                content_type: "text/csv; charset=utf-8",
            })
        }
        "tsv" => {
            let (_name, table) = table_by_type(d, typ)
                .ok_or("type 仅支持 students/registrations/results")?;
            Ok(Exported {
                filename: format!("{}.tsv", typ),
                bytes: render_tsv(&table).into_bytes(),
                content_type: "text/tab-separated-values; charset=utf-8",
            })
        }
        "md" => {
            let (_name, table) = table_by_type(d, typ)
                .ok_or("type 仅支持 students/registrations/results")?;
            Ok(Exported {
                filename: format!("{}.md", typ),
                bytes: render_md(&table).into_bytes(),
                content_type: "text/markdown; charset=utf-8",
            })
        }
        "html" => {
            let (name, table) = table_by_type(d, typ)
                .ok_or("type 仅支持 students/registrations/results")?;
            Ok(Exported {
                filename: format!("{}.html", typ),
                bytes: render_html(&name, &table).into_bytes(),
                content_type: "text/html; charset=utf-8",
            })
        }
        "xlsx" => Ok(Exported {
            filename: if typ == "all" {
                "运动会导出.xlsx".to_string()
            } else {
                format!("{}.xlsx", typ)
            },
            bytes: render_xlsx(d, typ),
            content_type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        }),
        "json" => {
            let j = crate::core::store::export_all_json(d);
            Ok(Exported {
                filename: "运动会全量备份.json".into(),
                bytes: j.to_string().into_bytes(),
                content_type: "application/json; charset=utf-8",
            })
        }
        other => Err(format!(
            "不支持的导出格式 {}（支持：{}）",
            other,
            SUPPORTED_FORMATS.join("/")
        )),
    }
}

/// 表头别名映射：在表头行里找别名列表对应的列号。
pub fn header_index(headers: &[&str], aliases: &[&str]) -> Option<usize> {
    for (i, h) in headers.iter().enumerate() {
        let h = h.trim().to_lowercase();
        if aliases.iter().any(|a| h == *a || h.contains(a)) {
            return Some(i);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_index_aliases() {
        let headers = vec!["序号", "名字", "得分", "备注"];
        assert_eq!(header_index(&headers, &["姓名", "名字"]), Some(1));
        assert_eq!(header_index(&headers, &["成绩", "分数", "得分"]), Some(2));
        assert_eq!(header_index(&headers, &["成绩", "score"]), None);
    }

    #[test]
    fn test_md_render() {
        let t = vec![vec!["姓名".into(), "成绩".into()], vec!["张三".into(), "12.8".into()]];
        let md = render_md(&t);
        assert!(md.contains("| 姓名 | 成绩 |"));
        assert!(md.contains("| --- | --- |"));
        assert!(md.contains("| 张三 | 12.8 |"));
    }

    #[test]
    fn test_html_render() {
        let t = vec![vec!["姓名".into()], vec!["张三".into()]];
        let h = render_html("测试表", &t);
        assert!(h.contains("<th>姓名</th>"));
        assert!(h.contains("<td>张三</td>"));
    }

    #[test]
    fn test_xlsx_bytes_valid_zip() {
        // xlsx 本质是 zip，魔数 PK\x03\x04
        let t = vec![vec!["A".into(), "B".into()], vec![1.to_string(), 2.to_string()]];
        let mut wb = Workbook::new();
        write_sheet(&mut wb, "Sheet1", &t);
        let bytes = wb.save_to_buffer().unwrap_or_default();
        assert_eq!(&bytes[0..2], b"PK");
    }
}
