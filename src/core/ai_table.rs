//! v1.9.10：把「AI 整理好的成绩表」文本直接导入。
//!
//! 场景：老师手上有纸质记录或拍照的原始成绩，不想一条条敲。
//! 把材料丢给 AI（系统内置的助手，或任何聊天 AI），让 AI 按四列整理，
//! 再把结果粘回系统即可：
//!
//! ```text
//! 项目	班级	姓名	成绩
//! 男子100米	初二3	张三	12"34
//! 男子100米	初二1	李四	11"98
//! 女子跳远	初二2	王五	4.32
//! ```
//!
//! 只要第一行带「项目 / 班级 / 姓名 / 成绩」四个词，下面怎么排都行 ——
//! Markdown 表格（`| a | b |`）、Excel 复制出来的制表符、逗号 CSV、
//! 甚至空格分隔，都能读。列的顺序也不固定，按表头找。
//!
//! 本模块只把文本切成「中性行」（与 `scoresheet::RawRow` 同一结构），
//! 项目与学生的匹配、班级解析、落盘全部复用成绩公布表那条链路 ——
//! 两条导入入口共用一个判定，不会出现「xlsx 能对上、粘贴对不上」。

use crate::core::api::ApiErr;
use crate::core::scoresheet::RawRow;

/// 一行切成若干列。
fn split_line(line: &str) -> Vec<String> {
    let t = line.trim();
    if t.is_empty() {
        return Vec::new();
    }
    // Markdown 表格：| a | b | c |
    if t.contains('|') {
        let inner = t.trim_start_matches('|').trim_end_matches('|');
        return inner.split('|').map(|s| s.trim().to_string()).collect();
    }
    // Excel 复制 / AI 按列输出：制表符
    if t.contains('\t') {
        return t.split('\t').map(|s| s.trim().to_string()).collect();
    }
    // 逗号 CSV（支持 "..." 包裹，允许字段里带逗号）
    if t.contains(',') || t.contains('，') {
        let mut out = Vec::new();
        let mut cur = String::new();
        let mut quoted = false;
        for ch in t.chars() {
            match ch {
                '"' | '“' if !quoted => quoted = true,
                '"' | '”' if quoted => quoted = false,
                ',' | '，' if !quoted => {
                    out.push(cur.trim().to_string());
                    cur.clear();
                }
                _ => cur.push(ch),
            }
        }
        out.push(cur.trim().to_string());
        return out;
    }
    // 空格分隔：先按 2 个以上空格切，切不开再按单个空格
    let wide: Vec<String> = t
        .split("  ")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if wide.len() >= 3 {
        return wide;
    }
    t.split_whitespace().map(|s| s.to_string()).collect()
}

/// Markdown 的分隔行（| --- | :--: |）不是数据。
fn is_separator(cells: &[String]) -> bool {
    !cells.is_empty()
        && cells.iter().all(|c| {
            !c.is_empty()
                && c.chars()
                    .all(|ch| ch == '-' || ch == ':' || ch == '=' || ch == ' ')
        })
}

fn find_col(header: &[String], names: &[&str]) -> Option<usize> {
    header.iter().position(|c| {
        let t = c.trim().trim_start_matches(['*', '＊']).trim();
        names.iter().any(|n| t == *n || t.starts_with(n) || t.contains(n))
    })
}

/// 表头行：既有「项目」类列，又有「姓名」或「成绩」列。
fn header_at(rows: &[Vec<String>]) -> Option<usize> {
    for (i, row) in rows.iter().enumerate().take(30) {
        let proj = find_col(row, &["项目", "比赛项目"]);
        let name = find_col(row, &["姓名", "参赛者", "运动员"]);
        let score = find_col(row, &["成绩", "分数", "用时", "结果"]);
        if proj.is_some() && (name.is_some() || score.is_some()) {
            return Some(i);
        }
    }
    None
}

/// 表头上方的「组别：初二组」之类，用于纯数字班号补年级。
fn group_hint(rows: &[Vec<String>], upto: usize) -> String {
    for row in rows.iter().take(upto.min(6)) {
        for c in row {
            let t = c.trim();
            for sep in ["：", ":"] {
                if let Some(rest) = t.strip_prefix(&format!("组别{}", sep)) {
                    let v = rest.trim().trim_end_matches('组');
                    if !v.is_empty() {
                        return normalize_group(v);
                    }
                }
            }
            if t.starts_with("组别") && t.len() > 2 {
                let v = t[2..].trim_start_matches(['：', ':']).trim().trim_end_matches('组');
                if !v.is_empty() {
                    return normalize_group(v);
                }
            }
        }
    }
    String::new()
}

/// 「八年级」→「初二」；已经是「初二」的原样返回（学校表两种写法都有）。
fn normalize_group(raw: &str) -> String {
    crate::core::scoresheet::parse_class_hint(raw).unwrap_or_else(|| raw.trim().to_string())
}

/// 解析粘贴文本。失败时给出「错在哪一行」的人话提示。
pub fn parse_text(text: &str) -> Result<Vec<RawRow>, ApiErr> {
    let text = text.trim_start_matches('\u{feff}');
    if text.trim().is_empty() {
        return Err(ApiErr::new("粘贴框是空的：把 AI 整理好的表格粘进来"));
    }
    let rows: Vec<Vec<String>> = text
        .lines()
        .map(split_line)
        .filter(|r| !r.is_empty() && !is_separator(r))
        .collect();
    if rows.is_empty() {
        return Err(ApiErr::new("没读到任何一行内容"));
    }
    let Some(hri) = header_at(&rows) else {
        return Err(ApiErr::new(
            "第一行要写表头，至少包含「项目」和「姓名」（或「成绩」）两个词，例如：项目 班级 姓名 成绩",
        ));
    };
    let header = &rows[hri];
    let pcol = find_col(header, &["项目", "比赛项目"]);
    let ccol = find_col(header, &["班级", "班别", "班"]);
    let ncol = find_col(header, &["姓名", "参赛者", "运动员"]);
    let scol = find_col(header, &["成绩", "分数", "用时", "结果"]);
    let rcol = find_col(header, &["名次", "排名"]);
    let group = group_hint(&rows, hri);

    let mut out = Vec::new();
    for (i, row) in rows.iter().enumerate().skip(hri + 1) {
        let get = |c: Option<usize>| c.and_then(|c| row.get(c)).map(|s| s.trim().to_string()).unwrap_or_default();
        let project = get(pcol);
        let class_raw = get(ccol);
        let name = get(ncol);
        let score = get(scol);
        // 空行、说明行
        if project.is_empty() && class_raw.is_empty() && name.is_empty() {
            continue;
        }
        if score.is_empty() {
            continue;
        }
        if score.contains("成绩") || score.contains("名次") || score.contains("说明") {
            continue;
        }
        if project.is_empty() {
            // 没有项目列值时，整行无法归属，报出行号而不是瞎猜
            return Err(ApiErr::new(format!(
                "第 {} 行没写项目名：每行都要能看出是哪个项目",
                i + 1
            )));
        }
        let name = if matches!(name.as_str(), "/" | "—" | "-" | "／" | "无") {
            String::new()
        } else {
            name
        };
        out.push(RawRow {
            sheet: project.clone(),
            project,
            project_hint: String::new(),
            group: group.clone(),
            class_raw,
            name,
            score_text: score,
            rank_in_sheet: get(rcol).parse::<i64>().ok(),
        });
    }
    if out.is_empty() {
        return Err(ApiErr::new(
            "表头认出来了，但下面没有一行填了成绩：确认成绩列已填，且每行都有项目名",
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_tab_separated() {
        let t = "项目\t班级\t姓名\t成绩\n男子100米\t初二3\t张三\t12\"34\n男子100米\t初二1\t李四\t11\"98\n";
        let rows = parse_text(t).unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].project, "男子100米");
        assert_eq!(rows[0].class_raw, "初二3");
        assert_eq!(rows[0].name, "张三");
        assert_eq!(rows[0].score_text, "12\"34");
    }

    #[test]
    fn parses_markdown_table_with_padding() {
        let t = "| 项目 | 班级 | 姓名 | 成绩 |\n|---|---|---|---|\n| 女子跳远 | 初二2 | 王五 | 4.32 |\n";
        let rows = parse_text(t).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].project, "女子跳远");
        assert_eq!(rows[0].score_text, "4.32");
    }

    #[test]
    fn column_order_can_change() {
        let t = "姓名,成绩,班级,项目\n张三,12.8,初二3,男子100米\n";
        let rows = parse_text(t).unwrap();
        assert_eq!(rows[0].name, "张三");
        assert_eq!(rows[0].project, "男子100米");
        assert_eq!(rows[0].class_raw, "初二3");
    }

    #[test]
    fn group_hint_fills_grade() {
        let t = "组别：初二组\n项目 班级 姓名 成绩\n男子100米 3 张三 12.8\n";
        let rows = parse_text(t).unwrap();
        assert_eq!(rows[0].group, "初二");
        assert_eq!(rows[0].class_raw, "3");
    }

    #[test]
    fn missing_header_is_explained() {
        let e = parse_text("张三 12.8\n李四 13.1").unwrap_err();
        assert!(e.message.contains("表头"));
    }

    #[test]
    fn rows_without_score_are_skipped() {
        let t = "项目,班级,姓名,成绩\n男子100米,初二3,张三,\n男子100米,初二1,李四,12.9\n";
        assert_eq!(parse_text(t).unwrap().len(), 1);
    }

    #[test]
    fn empty_text_is_rejected() {
        assert!(parse_text("   ").is_err());
    }
}
