//! v1.9.3：报名表文件解析（xlsx / csv）→ `/api/import/baoming` 的 payload。
//!
//! v1.9.0 的导入链路要求先用源码包里的 Python 脚本把 xlsx 转成 JSON，
//! 但发行包里不含任何脚本 —— 老师拿到 exe 之后「导入」实际上不可用。
//! 这里把解析搬进程序本体：
//!
//! ```text
//! 下载模板(xlsx/csv) ──Excel 填写──▶ 上传同一个文件 ──本模块──▶ payload
//!                                                    └─▶ Core::import_baoming
//! ```
//!
//! 刻意**不引入 XML 解析库**：xlsx 里我们只关心 sharedStrings 与第一个
//! worksheet 的单元格，用有界的字符串扫描即可，避免为一个导入功能拖进
//! 一整套 DOM 依赖。zip 读取复用 rust_xlsxwriter 已在依赖树里的 `zip`。
//!
//! 版式判定沿用 Python 脚本的口径：任何含「姓名」且非空列 ≥3 的行都是
//! 一节表头，节与节之间各自识别列布局 —— 学校现成的男女分节旧表因此
//! 可以直接上传，不需要照新模板重抄。

use crate::core::api::ApiErr;
use crate::core::json::Json;
use crate::core::model::Event;

// ---------------------------------------------------------------------------
// base64（前端上传二进制文件用；标准库没有，手写 30 行比拉依赖划算）
// ---------------------------------------------------------------------------

/// 供测试构造上传载荷用（生产侧只需 decode）。
#[allow(dead_code)]
pub fn b64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { T[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { T[n as usize & 63] as char } else { '=' });
    }
    out
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, ApiErr> {
    let mut out = Vec::new();
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for ch in s.bytes() {
        let v = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a' + 26,
            b'0'..=b'9' => ch - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b'\r' | b'\n' | b' ' => continue,
            _ => return Err(ApiErr::new("文件内容不是合法的 base64 编码")),
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1u32 << bits) - 1;
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// xlsx → 二维表
// ---------------------------------------------------------------------------

fn xml_unescape(s: &str) -> String {
    let t = s
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&apos;", "'");
    // 数字实体（Excel 保存特殊字符时偶见），只处理十进制/十六进制两种。
    let mut out = String::with_capacity(t.len());
    let mut rest = t.as_str();
    while let Some(p) = rest.find("&#") {
        out.push_str(&rest[..p]);
        let tail = &rest[p + 2..];
        if let Some(end) = tail.find(';') {
            let code = &tail[..end];
            let val = if let Some(hex) = code.strip_prefix('x').or_else(|| code.strip_prefix('X')) {
                u32::from_str_radix(hex, 16).ok()
            } else {
                code.parse::<u32>().ok()
            };
            if let Some(c) = val.and_then(char::from_u32) {
                out.push(c);
                rest = &tail[end + 1..];
                continue;
            }
        }
        out.push_str("&#");
        rest = tail;
    }
    out.push_str(rest);
    // &amp; 必须最后展开，否则 "&amp;lt;" 会被二次解成 "<"。
    out.replace("&amp;", "&")
}

/// 收集一个 XML 片段里所有 `<tag ...>文本</tag>`（富文本会有多个 `<t>`）。
fn collect_tag_text(block: &str, tag: &str) -> String {
    let open = format!("<{}", tag);
    let close = format!("</{}>", tag);
    let mut out = String::new();
    let mut rest = block;
    while let Some(p) = rest.find(&open) {
        let after = &rest[p + open.len()..];
        // 跳过属性，直到 '>'
        let Some(gt) = after.find('>') else { break };
        if after[..gt].trim_end().ends_with("/>") {
            rest = &after[gt + 1..];
            continue;
        }
        let body = &after[gt + 1..];
        let Some(e) = body.find(&close) else { break };
        out.push_str(&xml_unescape(&body[..e]));
        rest = &body[e + close.len()..];
    }
    out
}

fn attr(tag: &str, name: &str) -> Option<String> {
    let needle = format!(" {}=\"", name);
    let p = tag.find(&needle)? + needle.len();
    let e = tag[p..].find('"')? + p;
    Some(tag[p..e].to_string())
}

/// "A1" → (行, 列)，均 0 基。
fn cell_ref(r: &str) -> (usize, usize) {
    let mut col: usize = 0;
    let mut i = 0usize;
    for b in r.bytes() {
        if b.is_ascii_uppercase() {
            col = col * 26 + (b - b'A' + 1) as usize;
            i += 1;
        } else {
            break;
        }
    }
    let row: usize = r[i..].parse().unwrap_or(1);
    (row.saturating_sub(1), col.saturating_sub(1))
}

fn parse_shared_strings(xml: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = xml;
    loop {
        let Some(p) = rest.find("<si") else { break };
        let after = &rest[p..];
        let Some(e) = after.find("</si>") else { break };
        out.push(collect_tag_text(&after[..e], "t"));
        rest = &after[e + 5..];
    }
    out
}

fn parse_sheet(xml: &str, shared: &[String]) -> Vec<Vec<String>> {
    let mut rows: Vec<Vec<(usize, String)>> = Vec::new();
    let mut rest = xml;
    loop {
        // `<c ` 或 `<c>`；`</c>` 不会误命中，因为它以 "</" 开头。
        let Some(rel) = rest.find("<c ").or_else(|| rest.find("<c>")) else {
            break;
        };
        let start = rel;
        let after = &rest[start..];
        let Some(gt_rel) = after.find('>') else { break };
        let tag = &after[..=gt_rel];
        let inner_start = gt_rel + 1;
        let (inner, consumed) = if tag.trim_end().ends_with("/>") {
            ("", inner_start)
        } else if let Some(e) = after[inner_start..].find("</c>") {
            let e2 = inner_start + e;
            (&after[inner_start..e2], e2 + 4)
        } else {
            ("", inner_start)
        };
        let r = attr(tag, "r").unwrap_or_default();
        let (ri, ci) = cell_ref(&r);
        let typ = attr(tag, "t").unwrap_or_default();
        let value = match typ.as_str() {
            "s" => {
                let idx = collect_tag_text(inner, "v").trim().parse::<usize>().ok();
                idx.and_then(|i| shared.get(i)).cloned().unwrap_or_default()
            }
            "inlineStr" => collect_tag_text(inner, "t"),
            "b" => String::new(), // 布尔单元格不是勾选标记
            _ => collect_tag_text(inner, "v"),
        };
        if rows.len() <= ri {
            rows.resize(ri + 1, Vec::new());
        }
        rows[ri].push((ci, value));
        rest = &after[consumed..];
    }
    rows
        .into_iter()
        .map(|cells| {
            let width = cells.iter().map(|c| c.0 + 1).max().unwrap_or(0);
            let mut row = vec![String::new(); width];
            for (ci, v) in cells {
                row[ci] = v;
            }
            row
        })
        .collect()
}

/// v1.9.8：读取**全部**工作表（成绩公布表每个项目一个 sheet）。
///
/// 返回 `(工作表名, 行数据)`，顺序与工作簿标签页一致。仅依赖
/// `workbook.xml` + `workbook.xml.rels` 里的 sheet 名与文件映射，
/// 不解析样式、公式 —— 成绩表只需要单元格文本。
pub fn xlsx_sheets(bytes: &[u8]) -> Result<Vec<(String, Vec<Vec<String>>)>, ApiErr> {
    use std::io::{Cursor, Read};
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|_| ApiErr::new("打不开 xlsx：文件不是有效的 Excel 工作簿"))?;
    let mut shared = Vec::new();
    if let Ok(mut f) = zip.by_name("xl/sharedStrings.xml") {
        let mut s = String::new();
        f.read_to_string(&mut s).ok();
        shared = parse_shared_strings(&s);
    }
    let mut wb = String::new();
    if let Ok(mut f) = zip.by_name("xl/workbook.xml") {
        f.read_to_string(&mut wb).ok();
    }
    let mut rels = String::new();
    if let Ok(mut f) = zip.by_name("xl/_rels/workbook.xml.rels") {
        f.read_to_string(&mut rels).ok();
    }
    // rId → 工作表文件路径
    let mut targets: Vec<(String, String)> = Vec::new();
    let mut rest = rels.as_str();
    while let Some(p) = rest.find("<Relationship") {
        let after = &rest[p..];
        let Some(gt) = after.find('>') else { break };
        let tag = &after[..gt];
        if let (Some(id), Some(t)) = (attr(tag, "Id"), attr(tag, "Target")) {
            targets.push((id, t));
        }
        rest = &after[gt + 1..];
    }
    let mut out: Vec<(String, Vec<Vec<String>>)> = Vec::new();
    let mut rest = wb.as_str();
    while let Some(p) = rest.find("<sheet ") {
        let after = &rest[p..];
        let Some(gt) = after.find('>') else { break };
        let tag = &after[..gt];
        let name = attr(tag, "name").unwrap_or_default();
        let rid = attr(tag, "r:id").unwrap_or_default();
        rest = &after[gt + 1..];
        let Some(target) = targets.iter().find(|(id, _)| *id == rid).map(|(_, t)| t.clone()) else {
            continue;
        };
        let path = if let Some(t) = target.strip_prefix('/') {
            t.to_string()
        } else {
            format!("xl/{}", target.trim_start_matches("./"))
        };
        let mut xml = String::new();
        match zip.by_name(&path) {
            Ok(mut f) => {
                if f.read_to_string(&mut xml).is_err() {
                    continue;
                }
            }
            Err(_) => continue,
        }
        out.push((name, parse_sheet(&xml, &shared)));
    }
    if out.is_empty() {
        // 退化：workbook.xml 缺失或结构异常时，按 zip 内文件顺序读全部工作表。
        let names: Vec<String> = (0..zip.len())
            .filter_map(|i| zip.by_index(i).ok().map(|f| f.name().to_string()))
            .filter(|n| n.starts_with("xl/worksheets/") && n.ends_with(".xml"))
            .collect();
        for (i, n) in names.iter().enumerate() {
            let mut xml = String::new();
            if let Ok(mut f) = zip.by_name(n) {
                f.read_to_string(&mut xml).ok();
            }
            out.push((format!("Sheet{}", i + 1), parse_sheet(&xml, &shared)));
        }
    }
    if out.is_empty() {
        return Err(ApiErr::new("xlsx 里找不到任何工作表"));
    }
    Ok(out)
}

pub fn xlsx_rows(bytes: &[u8]) -> Result<Vec<Vec<String>>, ApiErr> {
    use std::io::{Cursor, Read};
    let mut zip = zip::ZipArchive::new(Cursor::new(bytes))
        .map_err(|_| ApiErr::new("打不开 xlsx：文件不是有效的 Excel 工作簿"))?;
    let mut shared = Vec::new();
    if let Ok(mut f) = zip.by_name("xl/sharedStrings.xml") {
        let mut s = String::new();
        f.read_to_string(&mut s).ok();
        shared = parse_shared_strings(&s);
    }
    // 工作表路径不总是 sheet1.xml（Excel 删过表后会重编号），按名字筛第一个。
    let mut sheet_name: Option<String> = None;
    for i in 0..zip.len() {
        if let Ok(f) = zip.by_index(i) {
            let n = f.name().to_string();
            if n.starts_with("xl/worksheets/") && n.ends_with(".xml") {
                sheet_name = Some(n);
                break;
            }
        }
    }
    let name = sheet_name.ok_or_else(|| ApiErr::new("xlsx 里找不到工作表"))?;
    let mut xml = String::new();
    zip.by_name(&name)
        .map_err(|_| ApiErr::new("读取工作表失败"))?
        .read_to_string(&mut xml)
        .map_err(|_| ApiErr::new("工作表不是有效的 UTF-8 XML"))?;
    Ok(parse_sheet(&xml, &shared))
}

// ---------------------------------------------------------------------------
// CSV → 二维表
// ---------------------------------------------------------------------------

fn csv_rows(text: &str) -> Vec<Vec<String>> {
    let t = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut quoted = false;
    let mut it = t.chars().peekable();
    while let Some(c) = it.next() {
        if quoted {
            if c == '"' {
                if it.peek() == Some(&'"') {
                    it.next();
                    field.push('"');
                } else {
                    quoted = false;
                }
            } else {
                field.push(c);
            }
        } else {
            match c {
                '"' if field.is_empty() => quoted = true,
                ',' => {
                    row.push(std::mem::take(&mut field));
                }
                '\n' => {
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                }
                '\r' => {}
                _ => field.push(c),
            }
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    rows
}

// ---------------------------------------------------------------------------
// 二维表 → import_baoming payload
// ---------------------------------------------------------------------------

fn norm_event(s: &str) -> String {
    let t: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let t = t
        .trim_start_matches("男子")
        .trim_start_matches("女子")
        .trim_start_matches(['男', '女'])
        .replace('×', "x")
        .replace('X', "x");
    t.trim_end_matches("接力").to_string()
}

/// 列名 → 项目 id。多候选时按本节性别优选，避免"100米"全落到男子项。
fn match_event(col: &str, gender: &str, events: &[Event]) -> Option<i64> {
    let want = norm_event(col);
    if want.is_empty() {
        return None;
    }
    let mut cands: Vec<&Event> = events
        .iter()
        .filter(|e| norm_event(&e.name) == want)
        .collect();
    if cands.is_empty() {
        // 再试一次：列名可能根本没带"接力"而系统项目带了（或反之）。
        cands = events
            .iter()
            .filter(|e| norm_event(&e.name).trim_end_matches("接力") == want.trim_end_matches("接力"))
            .collect();
    }
    let rank = |g: &str| -> u8 {
        match (gender, g) {
            ("男", "男子") | ("女", "女子") => 0,
            (_, "通用") | (_, "") => 1,
            ("男", "女子") | ("女", "男子") => 3,
            _ => 2,
        }
    };
    cands.sort_by_key(|e| rank(&e.gender));
    cands.first().map(|e| e.id)
}

/// "奥创七7" / "初一（7）班" / "初一7班" → (年级, 班号)。不猜，失败返回 None。
pub(crate) fn parse_class(raw: &str) -> Option<(String, i64)> {
    let t = raw.trim().trim_end_matches('班').trim();
    if t.is_empty() {
        return None;
    }
    let cs: Vec<char> = t.chars().collect();
    if let Some(l) = cs.iter().position(|c| *c == '（' || *c == '(') {
        if let Some(r) = cs.iter().position(|c| *c == '）' || *c == ')') {
            if r > l + 1 {
                let grade: String = cs[..l].iter().collect::<String>().trim().to_string();
                let num: String = cs[l + 1..r].iter().collect::<String>().trim().to_string();
                if !grade.is_empty() {
                    if let Ok(n) = num.parse::<i64>() {
                        if n > 0 {
                            return Some((grade, n));
                        }
                    }
                }
            }
        }
    }
    let mut k = cs.len();
    while k > 0 && cs[k - 1].is_ascii_digit() {
        k -= 1;
    }
    if k > 0 && k < cs.len() {
        let grade: String = cs[..k].iter().collect::<String>().trim().to_string();
        let num: String = cs[k..].iter().collect();
        if !grade.is_empty() {
            if let Ok(n) = num.parse::<i64>() {
                if n > 0 {
                    return Some((grade, n));
                }
            }
        }
    }
    None
}

fn is_mark(v: &str) -> bool {
    matches!(
        v.trim(),
        "√" | "✓" | "✔" | "●" | "○" | "Y" | "y" | "是" | "1" | "报名" | "参加" | "参赛"
    )
}

fn is_header(row: &[String]) -> bool {
    // v1.9.7：放宽到 2 列 —— 「姓名 + 班别」这种极简名单也要能识别。
    // 标题行通常只有 1 列，不会误判。
    row.iter().any(|c| c.trim().starts_with("姓名"))
        && row.iter().filter(|c| !c.trim().is_empty()).count() >= 2
}

fn header_gender(h: &str) -> String {
    // "姓名（男）" / "姓名(女）" → 男 / 女
    let cs: Vec<char> = h.chars().collect();
    for (i, c) in cs.iter().enumerate() {
        if *c == '男' || *c == '女' {
            if i > 0 && (cs[i - 1] == '（' || cs[i - 1] == '(') {
                return c.to_string();
            }
        }
    }
    String::new()
}

struct Columns {
    name: usize,
    class: Option<usize>,
    /// v1.9.7：单独的「年级」列。名单里常见「年级 | 班级 | 姓名」，
    /// 此时班级列只有数字，需要和年级拼成 (年级, 班号)。
    grade: Option<usize>,
    gender: Option<usize>,
    note: Option<usize>,
    events: Vec<(usize, String)>,
}

fn classify_columns(header: &[String]) -> Result<Columns, ApiErr> {
    let mut c = Columns {
        name: usize::MAX,
        class: None,
        grade: None,
        gender: None,
        note: None,
        events: Vec::new(),
    };
    for (i, h) in header.iter().enumerate() {
        let t = h.trim();
        if t.is_empty() {
            continue;
        }
        if t.starts_with("姓名") {
            c.name = i;
        } else if matches!(t, "班别" | "班级" | "班") {
            c.class = Some(i);
        } else if matches!(t, "年级") {
            c.grade = Some(i);
        } else if t == "性别" {
            c.gender = Some(i);
        } else if matches!(t, "备注" | "说明") {
            c.note = Some(i);
        } else if matches!(
            t.to_ascii_lowercase().as_str(),
            "序号" | "no" | "no." | "编号" | "学号" | "考号" | "考籍号"
        ) {
            // 序号 / 学号列不参与业务
        } else {
            c.events.push((i, t.to_string()));
        }
    }
    if c.name == usize::MAX {
        return Err(ApiErr::new("表头里没有「姓名」列"));
    }
    Ok(c)
}

/// 把一行的班别翻译成 (年级, 班号)。
///
/// 支持三种写法：
///   · 完整写法「初一1」「初一（1）班」——由 `parse_class` 解析；
///   · 「年级」「班级」分列（年级列=初一，班级列=1）；
///   · 只有班级列且是纯数字 → 无法判断年级，返回 None（进 bad_class 报告）。
fn resolve_class(raw: &str, grade: Option<&str>) -> Option<(String, i64)> {
    let raw = raw.trim();
    if let Some(v) = parse_class(raw) {
        return Some(v);
    }
    let g = grade?.trim();
    if g.is_empty() || raw.is_empty() {
        return None;
    }
    // 完整写法已在上一步尝试过；这里只接受纯数字班号。
    let num = raw.trim_end_matches('班').trim();
    num.parse::<i64>().ok().filter(|n| *n > 0).map(|n| (g.to_string(), n))
}

/// 通用解析：`events = Some(..)` 时解析项目勾选（报名表）；
/// `None` 时只收学生名单，表里的项目列一律忽略（v1.9.7 新增）。
fn parse_rows(rows: &[Vec<String>], events: Option<&[Event]>) -> Result<(Json, Json), ApiErr> {
    let sections: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| is_header(r))
        .map(|(i, _)| i)
        .collect();
    if sections.is_empty() {
        return Err(ApiErr::new(
            "找不到表头行：需要有一行包含「姓名」，且至少 2 列有内容",
        ));
    }
    let mut students: Vec<Json> = Vec::new();
    let mut registrations: Vec<Json> = Vec::new();
    let mut seen_students: Vec<(String, i64, String)> = Vec::new();
    let mut grades: Vec<String> = Vec::new();
    let mut bad_class: Vec<Json> = Vec::new();
    let mut unmatched: Vec<String> = Vec::new();
    let mut example_skipped = 0usize;
    let roster_only = events.is_none();

    for (si, &hi) in sections.iter().enumerate() {
        let end = sections.get(si + 1).copied().unwrap_or(rows.len());
        let cols = classify_columns(&rows[hi])?;
        if !roster_only && cols.events.is_empty() {
            return Err(ApiErr::new(
                "表头里没有识别出任何项目列——若只想导入名单，请用「导入名单」",
            ));
        }
        let sec_gender = header_gender(&rows[hi][cols.name]);
        for row in &rows[hi + 1..end] {
            let get = |i: usize| row.get(i).map(|s| s.trim()).unwrap_or("");
            let name = get(cols.name).to_string();
            if name.is_empty() {
                continue;
            }
            if name.contains("示例") {
                example_skipped += 1;
                continue;
            }
            // 表尾说明行：模板和手工表都常在最后写一行「填写说明：…」。
            // 这类行不是学生，必须跳过，否则会被当成一个名字极长的人。
            if name.starts_with("填写说明")
                || name.starts_with("说明")
                || name.starts_with("注：")
                || name.starts_with("注:")
            {
                continue;
            }
            let gender = if !sec_gender.is_empty() {
                sec_gender.clone()
            } else if let Some(gi) = cols.gender {
                let g = get(gi);
                if g == "男" || g == "女" {
                    g.to_string()
                } else {
                    String::new()
                }
            } else {
                String::new()
            };
            let raw_class = cols.class.map(get).unwrap_or("").to_string();
            let grade_cell = cols.grade.map(get).unwrap_or("");
            let Some((grade, class_no)) = resolve_class(
                &raw_class,
                if grade_cell.is_empty() { None } else { Some(grade_cell) },
            ) else {
                let mut e = Json::obj();
                e.set("name", Json::s(name.clone()));
                e.set("class", Json::s(raw_class.clone()));
                bad_class.push(e);
                continue;
            };
            let note = cols.note.map(get).unwrap_or("").to_string();
            let key = (grade.clone(), class_no, name.clone());
            if !seen_students.contains(&key) {
                seen_students.push(key.clone());
                let mut s = Json::obj();
                s.set("name", Json::s(name.clone()));
                s.set("grade", Json::s(grade.clone()));
                s.set("class_no", Json::Int(class_no));
                s.set("gender", Json::s(gender.clone()));
                students.push(s);
                if !grades.contains(&grade) {
                    grades.push(grade.clone());
                }
            }
            if roster_only {
                continue;
            }
            let evs = events.unwrap_or(&[]);
            for (ci, col_name) in &cols.events {
                if !is_mark(get(*ci)) {
                    continue;
                }
                let mut e = Json::obj();
                e.set("name", Json::s(name.clone()));
                e.set("grade", Json::s(grade.clone()));
                e.set("class_no", Json::Int(class_no));
                e.set("note", Json::s(note.clone()));
                match match_event(col_name, &gender, evs) {
                    Some(id) => {
                        e.set("event_id", Json::Int(id));
                    }
                    None => {
                        e.set("event", Json::s(col_name.clone()));
                        if !unmatched.contains(col_name) {
                            unmatched.push(col_name.clone());
                        }
                    }
                }
                registrations.push(e);
            }
        }
    }

    if students.is_empty() && registrations.is_empty() {
        return Err(ApiErr::new(
            "表里没有读到任何可导入的学生：请检查姓名、班别是否填写，或是否误删了表头",
        ));
    }
    let mut payload = Json::obj();
    payload.set("students", Json::Arr(students.clone()));
    payload.set("registrations", Json::Arr(registrations.clone()));
    payload.set("ensure_grades", Json::Bool(true));
    payload.set("grades", Json::arr(grades.iter().map(|g| Json::s(g.clone()))));

    let mut report = Json::obj();
    report.set("mode", Json::s(if roster_only { "roster" } else { "baoming" }));
    report.set("sections", Json::Int(sections.len() as i64));
    report.set("students", Json::Int(students.len() as i64));
    report.set("registrations", Json::Int(registrations.len() as i64));
    report.set("example_skipped", Json::Int(example_skipped as i64));
    report.set("bad_class", Json::Arr(bad_class.clone()));
    report.set(
        "unmatched_cols",
        Json::arr(unmatched.iter().map(|s| Json::s(s.clone()))),
    );
    Ok((payload, report))
}

/// 报名表解析：必须能识别出项目列。
pub fn rows_to_payload(rows: &[Vec<String>], events: &[Event]) -> Result<(Json, Json), ApiErr> {
    parse_rows(rows, Some(events))
}

/// 名单解析（v1.9.7）：只要姓名 + 班别，项目列忽略。
pub fn rows_to_roster(rows: &[Vec<String>]) -> Result<(Json, Json), ApiErr> {
    parse_rows(rows, None)
}

/// 读取文件为二维表：xlsx 走内置扫描，其余按 CSV/文本。
fn read_rows(filename: &str, bytes: &[u8]) -> Result<Vec<Vec<String>>, ApiErr> {
    let is_xlsx = bytes.starts_with(b"PK\x03\x04")
        || filename.to_ascii_lowercase().ends_with(".xlsx");
    if is_xlsx {
        xlsx_rows(bytes).map_err(|e| {
            ApiErr::new(format!("读取 Excel 失败：{}（可另存为 CSV 后再试）", e.message))
        })
    } else {
        let text = String::from_utf8_lossy(bytes);
        Ok(csv_rows(&text))
    }
}

/// 入口：按魔数/扩展名分派，产出报名表 payload 与解析报告。
pub fn parse_file(
    filename: &str,
    bytes: &[u8],
    events: &[Event],
) -> Result<(Json, Json), ApiErr> {
    if bytes.is_empty() {
        return Err(ApiErr::new("文件内容为空"));
    }
    let rows = read_rows(filename, bytes)?;
    rows_to_payload(&rows, events)
}

/// 入口（v1.9.7）：名单文件 → 只含 students 的 payload。
///
/// 与 `parse_file` 的区别：不要求项目列，也不产生任何报名；
/// 表里若带了项目勾选，一律忽略（要导报名请走「报名表导入」）。
pub fn parse_roster_file(filename: &str, bytes: &[u8]) -> Result<(Json, Json), ApiErr> {
    if bytes.is_empty() {
        return Err(ApiErr::new("文件内容为空"));
    }
    let rows = read_rows(filename, bytes)?;
    rows_to_roster(&rows)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn parse_class_variants() {
        assert_eq!(parse_class("奥创七7"), Some(("奥创七".into(), 7)));
        assert_eq!(parse_class("初一（7）班"), Some(("初一".into(), 7)));
        assert_eq!(parse_class("初一7班"), Some(("初一".into(), 7)));
        assert_eq!(parse_class(""), None);
        assert_eq!(parse_class("七年级"), None);
    }

    #[test]
    fn gender_aware_event_match() {
        let evs = vec![
            ev(1, "男子100米", "男子"),
            ev(2, "女子100米", "女子"),
            ev(3, "跳远", "通用"),
            ev(4, "4×100米接力", "通用"),
            ev(5, "女子4×100米接力", "女子"),
        ];
        assert_eq!(match_event("100米", "男", &evs), Some(1));
        assert_eq!(match_event("100米", "女", &evs), Some(2));
        assert_eq!(match_event("跳远", "女", &evs), Some(3));
        assert_eq!(match_event("4×100米", "男", &evs), Some(4));
        // 女生节若系统里存在「女子4×100米接力」专属项目，应优先于通用接力。
        assert_eq!(match_event("4×100米", "女", &evs), Some(5));
        assert_eq!(match_event("不存在的项", "男", &evs), None);
    }

    #[test]
    fn roster_only_table_imports_students_without_registrations() {
        // 典型名单：姓名 / 年级 / 班级 / 性别 / 学号，没有任何项目列。
        let rows = vec![
            vec!["同和中学参赛名单".into()],
            vec!["姓名".into(), "年级".into(), "班级".into(), "性别".into(), "学号".into()],
            vec!["张三".into(), "初一".into(), "1".into(), "男".into(), "2401".into()],
            vec!["李四".into(), "初一".into(), "2".into(), "女".into(), "2402".into()],
            vec!["王五（示例）".into(), "初一".into(), "3".into(), "男".into(), "2403".into()],
            vec!["赵六".into(), "初二".into(), "5班".into(), "".into(), "".into()],
        ];
        let (p, r) = rows_to_roster(&rows).unwrap();
        assert_eq!(r.get_string("mode"), "roster");
        assert_eq!(r.get_i64("students"), Some(3));
        assert_eq!(r.get_i64("registrations"), Some(0));
        assert_eq!(r.get_i64("example_skipped"), Some(1));
        let st = p.get("students").and_then(|v| v.as_arr()).unwrap();
        assert_eq!(st.len(), 3);
        assert_eq!(st[0].get_string("name"), "张三");
        assert_eq!(st[0].get_string("grade"), "初一");
        assert_eq!(st[0].get_i64("class_no"), Some(1));
        assert_eq!(st[0].get_string("gender"), "男");
        assert_eq!(st[2].get_string("grade"), "初二");
        assert_eq!(st[2].get_i64("class_no"), Some(5), "「5班」也应能解析");
        assert_eq!(
            p.get("registrations").and_then(|v| v.as_arr()).map(|a| a.len()),
            Some(0),
            "名单导入不得产生任何报名"
        );
        // 学号列不应被当成项目列报错
        assert_eq!(
            p.get("registrations").and_then(|v| v.as_arr()).map(|a| a.len()),
            Some(0)
        );
    }

    #[test]
    fn roster_table_with_event_columns_ignores_marks() {
        // 报名表也能当名单用：只导人，项目勾选一律忽略。
        let rows = vec![
            vec!["姓名".into(), "班别".into(), "100米".into()],
            vec!["张三".into(), "初一1".into(), "√".into()],
        ];
        let (p, r) = rows_to_roster(&rows).unwrap();
        assert_eq!(r.get_i64("students"), Some(1));
        assert_eq!(
            p.get("registrations").and_then(|v| v.as_arr()).map(|a| a.len()),
            Some(0)
        );
    }

    #[test]
    fn two_section_table_becomes_payload() {
        let evs = vec![ev(1, "男子100米", "男子"), ev(2, "女子100米", "女子")];
        let rows = vec![
            vec!["同和中学报名表".into()],
            vec!["序号".into(), "姓名（男）".into(), "班别".into(), "100米".into(), "备注".into()],
            vec!["1".into(), "张三（示例）".into(), "初一1".into(), "√".into(), "".into()],
            vec!["2".into(), "王五".into(), "初一1".into(), "√".into(), "".into()],
            vec!["序号".into(), "姓名(女）".into(), "班别".into(), "100米".into(), "备注".into()],
            vec!["3".into(), "赵六".into(), "初一（2）班".into(), "√".into(), "".into()],
        ];
        let (p, r) = rows_to_payload(&rows, &evs).unwrap();
        assert_eq!(r.get_i64("sections"), Some(2));
        assert_eq!(r.get_i64("students"), Some(2));
        assert_eq!(r.get_i64("example_skipped"), Some(1));
        assert_eq!(p.get("students").and_then(|v| v.as_arr()).map(|a| a.len()), Some(2));
        let regs = p.get("registrations").and_then(|v| v.as_arr()).unwrap();
        assert_eq!(regs.len(), 2);
        assert_eq!(regs[0].get_i64("event_id"), Some(1), "男生应落男子项目");
        assert_eq!(regs[1].get_i64("event_id"), Some(2), "女生应落女子项目");
        assert_eq!(regs[1].get_string("grade"), "初一");
        assert_eq!(regs[1].get_i64("class_no"), Some(2));
    }

    #[test]
    fn b64_roundtrip_shape() {
        assert_eq!(b64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(b64_decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn csv_quoted_fields() {
        let rows = csv_rows("\u{feff}姓名,备注\n\"张,三\",\"他说\"\"好\"\"\"\n");
        assert_eq!(rows[1][0], "张,三");
        assert_eq!(rows[1][1], "他说\"好\"");
    }

    #[test]
    fn sheet_cell_ref_and_xml_escape() {
        assert_eq!(cell_ref("A1"), (0, 0));
        assert_eq!(cell_ref("C3"), (2, 2));
        assert_eq!(cell_ref("AA12"), (11, 26));
        assert_eq!(xml_unescape("A&amp;lt;B &lt;C&gt;"), "A&lt;B <C>");
    }
}
