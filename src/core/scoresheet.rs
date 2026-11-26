//! v1.9.8：成绩公布表（每项目一个 sheet）→ 批量成绩导入。
//!
//! 学校现用的《校运会成绩公布表》版式：
//!
//! ```text
//!   A1  同和中学学校运动会成绩公布表
//!   A2  组别：  B2 八年级组   D2 项目：  E2 男子100米
//!   A3  名次    B3 班级      C3 姓名    D3 成绩   E3 备注
//!   A4  1       B4 初二3     C4 张三    D4 12.8
//! ```
//!
//! 一张工作簿里每个项目一个 sheet，名次与得分往往预先印好，老师只填
//! 班级/姓名/成绩。本模块只做「版式 → 中性行」，项目与学生的匹配放在
//! API 层（那里才拿得到 Event/Student 列表）。
//!
//! 刻意不做的事：不猜没有写姓名的个人项目行、不把备注当成绩。
//! 拿不准的行原样进报告，让老师自己看，避免把成绩写错人。

use crate::core::api::ApiErr;
use crate::core::baoming::{b64_decode, xlsx_sheets};

/// 从表格里读出的一行（尚未匹配项目与学生）。
#[derive(Debug, Clone)]
pub struct RawRow {
    pub sheet: String,
    /// 工作表名（老师建表时按项目命名，最可信）
    pub project: String,
    /// 表内「项目：」右侧的文字。学校现用表里有复制错误
    /// （「女子立定三级蛙跳」的表头写成「女子跳远」），只能当备用。
    pub project_hint: String,
    /// 表内声明的组别（「八年级组」等），用于纯数字班号时补年级
    pub group: String,
    pub class_raw: String,
    pub name: String,
    pub score_text: String,
    pub rank_in_sheet: Option<i64>,
}

fn cell(row: &[String], i: Option<usize>) -> String {
    i.and_then(|i| row.get(i))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn find_col(header: &[String], names: &[&str]) -> Option<usize> {
    header.iter().position(|c| {
        let t = c.trim().trim_start_matches(['*', '＊']).trim();
        names.iter().any(|n| t == *n || t.starts_with(n))
    })
}

/// 表头行判定：同一行里既有「姓名」又有「成绩」。
/// 比报名表宽松（报名表靠项目列打勾，成绩表靠姓名+成绩两列）。
fn header_at(rows: &[Vec<String>]) -> Option<(usize, usize, Option<usize>, Option<usize>, usize, Option<usize>)> {
    for (ri, row) in rows.iter().take(20).enumerate() {
        let name = find_col(row, &["姓名", "参赛者", "运动员"]);
        let score = find_col(row, &["成绩", "分数", "用时"]);
        if let (Some(n), Some(s)) = (name, score) {
            let class = find_col(row, &["班级", "班别", "班"]);
            let rank = find_col(row, &["名次", "排名"]);
            return Some((ri, n, class, rank, s, find_col(row, &["备注"])));
        }
    }
    None
}

/// 从表头行上方找「项目：」「组别：」右侧的值。
fn header_value(rows: &[Vec<String>], upto: usize, label: &str) -> String {
    for row in rows.iter().take(upto.min(8)) {
        for (i, c) in row.iter().enumerate() {
            let t = c.trim();
            if t == label || t == format!("{}：", label) || t == format!("{}:", label) {
                // 值可能在同一行的下一格
                for j in i + 1..row.len() {
                    let v = row[j].trim();
                    if !v.is_empty() {
                        return v.to_string();
                    }
                }
            }
            // 「项目：男子100米」写在同一格
            for sep in ["：", ":"] {
                if let Some(rest) = t.strip_prefix(&format!("{}{}", label, sep)) {
                    let v = rest.trim();
                    if !v.is_empty() {
                        return v.to_string();
                    }
                }
            }
        }
    }
    String::new()
}

pub(crate) fn parse_class_hint(group: &str) -> Option<String> {
    // 「八年级组」→「初二」；只在设置里确实有该年级时才会被采用（API 层判断）
    let g = group.trim().trim_end_matches('组');
    let n = g
        .trim_start_matches('初')
        .trim_start_matches('高')
        .chars()
        .find(|c| c.is_ascii_digit())?;
    let grade = match n {
        '7' => "初一",
        '8' => "初二",
        '9' => "初三",
        _ => return None,
    };
    Some(grade.to_string())
}

/// 解析一整本成绩公布表。返回中性行；项目/学生匹配由调用方完成。
pub fn parse_workbook(bytes: &[u8]) -> Result<Vec<RawRow>, ApiErr> {
    if bytes.is_empty() {
        return Err(ApiErr::new("文件内容为空"));
    }
    if !bytes.starts_with(b"PK\x03\x04") {
        return Err(ApiErr::new(
            "成绩公布表需要 .xlsx 格式（Excel 工作簿）。若手头是 .xls，请用 Excel「另存为」xlsx 后再传",
        ));
    }
    let sheets = xlsx_sheets(bytes)?;
    let mut out = Vec::new();
    for (sheet_name, rows) in &sheets {
        let Some((hri, ncol, ccol, rcol, scol, note_col)) = header_at(rows) else {
            continue;
        };
        let project_hint = header_value(rows, hri, "项目");
        let group = header_value(rows, hri, "组别");
        let grade_hint = parse_class_hint(&group);
        for row in rows.iter().skip(hri + 1) {
            let score = cell(row, Some(scol));
            let name = cell(row, Some(ncol));
            let class_raw = cell(row, ccol);
            if score.is_empty() {
                continue;
            }
            // 名次/备注/说明行不是成绩行
            if score.contains("成绩") || score.contains("名次") || score.contains("说明") {
                continue;
            }
            if name.is_empty() && class_raw.is_empty() {
                continue;
            }
            // 接力表常把姓名写成 "/" 或 "—"，视为集体项目
            let name = if matches!(name.as_str(), "/" | "—" | "-" | "／") {
                String::new()
            } else {
                name
            };
            let _ = note_col;
            let rank_in_sheet = cell(row, rcol).parse::<i64>().ok();
            out.push(RawRow {
                sheet: sheet_name.clone(),
                project: sheet_name.clone(),
                project_hint: project_hint.clone(),
                group: grade_hint.clone().unwrap_or_default(),
                class_raw,
                name,
                score_text: score,
                rank_in_sheet,
            });
        }
    }
    if out.is_empty() {
        return Err(ApiErr::new(
            "没读到任何成绩行：请确认每个项目的工作表里都有「姓名 / 成绩」表头，且成绩列已填",
        ));
    }
    Ok(out)
}

/// 供 API 层解码上传载荷（xlsx 走 base64）。
pub fn decode_upload(b64: &str) -> Result<Vec<u8>, ApiErr> {
    b64_decode(b64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_publish_table() {
        let rows = vec![
            vec!["同和中学学校运动会成绩公布表".to_string()],
            vec![
                "组别：".into(),
                "八年级组".into(),
                "".into(),
                "项目：".into(),
                "男子100米".into(),
            ],
            vec!["名次".into(), "班级".into(), "姓名".into(), "成绩".into(), "备注".into()],
            vec!["1".into(), "初二3".into(), "张三".into(), "12.8".into(), "7".into()],
            vec!["2".into(), "初二1".into(), "李四".into(), "13.1".into(), "5".into()],
            vec!["".into(), "".into(), "".into(), "".into(), "".into()],
        ];
        let Some((hri, n, c, r, s, _)) = header_at(&rows) else {
            panic!("表头未识别");
        };
        assert_eq!((hri, n, c, r, s), (2, 2, Some(1), Some(0), 3));
        assert_eq!(header_value(&rows, hri, "项目"), "男子100米");
        assert_eq!(header_value(&rows, hri, "组别"), "八年级组");
    }

    #[test]
    fn empty_score_rows_are_skipped() {
        let rows = vec![
            vec!["名次".into(), "班级".into(), "姓名".into(), "成绩".into()],
            vec!["1".into(), "初二3".into(), "张三".into(), "".into()],
            vec!["2".into(), "初二3".into(), "李四".into(), "13.0".into()],
        ];
        let Some((hri, ncol, ccol, rcol, scol, _)) = header_at(&rows) else {
            panic!()
        };
        let mut n = 0;
        for row in rows.iter().skip(hri + 1) {
            if !cell(row, Some(scol)).is_empty() {
                n += 1;
            }
            let _ = (ncol, ccol, rcol);
        }
        assert_eq!(n, 1);
    }
}
