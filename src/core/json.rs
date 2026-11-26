//! 极简 JSON 实现（核心模块）：解析 + 序列化，零第三方依赖。
//! 仅支持标准 JSON 语法；数字区分整数（Int）与浮点（Num）以保证 id 等字段显示无误差。

use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    // ---------- 构造辅助 ----------
    pub fn obj() -> Json {
        Json::Obj(BTreeMap::new())
    }
    pub fn set(&mut self, key: &str, val: Json) -> &mut Self {
        if let Json::Obj(map) = self {
            map.insert(key.to_string(), val);
        }
        self
    }
    pub fn s(v: impl Into<String>) -> Json {
        Json::Str(v.into())
    }
    pub fn arr<I: IntoIterator<Item = Json>>(items: I) -> Json {
        Json::Arr(items.into_iter().collect())
    }

    // ---------- 读取辅助 ----------
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(map) => map.get(key),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|v| v.as_str())
    }
    pub fn get_i64(&self, key: &str) -> Option<i64> {
        self.get(key).and_then(|v| v.as_i64())
    }
    /// JSON 库 API 完整性预留（当前业务未使用，保留以避免调用方手写转换）。
    #[allow(dead_code)]
    pub fn get_f64(&self, key: &str) -> Option<f64> {
        self.get(key).and_then(|v| v.as_f64())
    }
    pub fn get_string(&self, key: &str) -> String {
        self.get_str(key).unwrap_or_default().to_string()
    }
    /// JSON 库 API 完整性预留。
    #[allow(dead_code)]
    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(|v| v.as_bool())
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Int(i) => Some(*i),
            Json::Num(f) => Some(*f as i64),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Int(i) => Some(*i as f64),
            Json::Num(f) => Some(*f),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_arr(&self) -> Option<&Vec<Json>> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }
    /// JSON 库 API 完整性预留。
    #[allow(dead_code)]
    pub fn is_null(&self) -> bool {
        matches!(self, Json::Null)
    }

    /// 字符串简写取值（不存在或类型不符返回 ""）
    #[allow(dead_code)]
    pub fn str_or(&self, key: &str, default: &str) -> String {
        self.get(key).and_then(|v| v.as_str()).unwrap_or(default).to_string()
    }
    #[allow(dead_code)]
    pub fn i64_or(&self, key: &str, default: i64) -> i64 {
        self.get(key).and_then(|v| v.as_i64()).unwrap_or(default)
    }
    #[allow(dead_code)]
    pub fn f64_or(&self, key: &str, default: f64) -> f64 {
        self.get(key).and_then(|v| v.as_f64()).unwrap_or(default)
    }

    // ---------- 序列化 ----------
    /// 带缩进的格式化输出（用于备份文件，便于人工查看）。
    pub fn to_string_pretty(&self) -> String {
        let mut out = String::new();
        self.write_pretty(&mut out, 0);
        out
    }

    fn write_pretty(&self, out: &mut String, indent: usize) {
        let pad = "  ".repeat(indent);
        let pad_in = "  ".repeat(indent + 1);
        match self {
            Json::Arr(items) => {
                if items.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push_str("[\n");
                for (i, item) in items.iter().enumerate() {
                    out.push_str(&pad_in);
                    item.write_pretty(out, indent + 1);
                    if i + 1 < items.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad);
                out.push(']');
            }
            Json::Obj(map) => {
                if map.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push_str("{\n");
                let n = map.len();
                for (i, (k, v)) in map.iter().enumerate() {
                    out.push_str(&pad_in);
                    out.push_str(&Json::Str(k.clone()).to_string());
                    out.push_str(": ");
                    v.write_pretty(out, indent + 1);
                    if i + 1 < n {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad);
                out.push('}');
            }
            other => out.push_str(&other.to_string()),
        }
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(true) => out.push_str("true"),
            Json::Bool(false) => out.push_str("false"),
            Json::Int(i) => {
                let _ = write!(out, "{}", i);
            }
            Json::Num(f) => {
                if f.is_finite() {
                    if f.fract() == 0.0 && f.abs() < 1e15 {
                        let _ = write!(out, "{:.1}", f); // 保留浮点语义
                    } else {
                        let _ = write!(out, "{}", f);
                    }
                } else {
                    out.push_str("null");
                }
            }
            Json::Str(s) => write_escaped(s, out),
            Json::Arr(items) => {
                out.push('[');
                for (i, v) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write(out);
                }
                out.push(']');
            }
            Json::Obj(map) => {
                out.push('{');
                for (i, (k, v)) in map.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_escaped(k, out);
                    out.push(':');
                    v.write(out);
                }
                out.push('}');
            }
        }
    }

    // ---------- 解析 ----------
    pub fn parse(text: &str) -> Result<Json, String> {
        let bytes: Vec<char> = text.chars().collect();
        let mut pos = 0usize;
        skip_ws(&bytes, &mut pos);
        let v = parse_value(&bytes, &mut pos, 0)?;
        skip_ws(&bytes, &mut pos);
        if pos != bytes.len() {
            return Err(format!("JSON 解析：第 {} 字符处有多余内容", pos));
        }
        Ok(v)
    }
}

/// v1.4：序列化改为标准 `Display` 实现——`to_string()` 由 `ToString` 自动提供，
/// 消除 inherent 方法遮蔽标准 trait 的 clippy 告警，序列化输出保持不变。
impl std::fmt::Display for Json {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = String::new();
        self.write(&mut out);
        f.write_str(&out)
    }
}

fn write_escaped(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn skip_ws(b: &[char], pos: &mut usize) {
    while *pos < b.len() && matches!(b[*pos], ' ' | '\t' | '\n' | '\r') {
        *pos += 1;
    }
}

/// JSON 嵌套深度上限（v1.4 安全加固）：防止恶意深嵌套输入造成递归栈溢出（DoS）。
/// 语义：数组/对象容器的最大嵌套层数。正常业务 JSON（项目/学生/成绩/报表）
/// 嵌套不超过 5 层，128 已有极大冗余。检查点在 parse_array / parse_object 入口。
const MAX_JSON_DEPTH: usize = 128;

fn parse_value(b: &[char], pos: &mut usize, depth: usize) -> Result<Json, String> {
    skip_ws(b, pos);
    if *pos >= b.len() {
        return Err("JSON 解析：意外结束".into());
    }
    match b[*pos] {
        'n' => lit(b, pos, "null", Json::Null),
        't' => lit(b, pos, "true", Json::Bool(true)),
        'f' => lit(b, pos, "false", Json::Bool(false)),
        '"' => parse_string(b, pos).map(Json::Str),
        '[' => parse_array(b, pos, depth + 1),
        '{' => parse_object(b, pos, depth + 1),
        _ => parse_number(b, pos),
    }
}

fn lit(b: &[char], pos: &mut usize, word: &str, val: Json) -> Result<Json, String> {
    for c in word.chars() {
        if *pos >= b.len() || b[*pos] != c {
            return Err("JSON 解析：字面量不完整".into());
        }
        *pos += 1;
    }
    Ok(val)
}

fn parse_string(b: &[char], pos: &mut usize) -> Result<String, String> {
    // 进入时 b[*pos] 必为 '"'
    *pos += 1;
    let mut out = String::new();
    while *pos < b.len() {
        let c = b[*pos];
        *pos += 1;
        match c {
            '"' => return Ok(out),
            '\\' => {
                if *pos >= b.len() {
                    return Err("JSON 解析：转义符后意外结束".into());
                }
                let e = b[*pos];
                *pos += 1;
                match e {
                    '"' => out.push('"'),
                    '\\' => out.push('\\'),
                    '/' => out.push('/'),
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'b' => out.push('\u{08}'),
                    'f' => out.push('\u{0C}'),
                    'u' => {
                        if *pos + 4 > b.len() {
                            return Err("JSON 解析：\\u 转义不完整".into());
                        }
                        let hex: String = b[*pos..*pos + 4].iter().collect();
                        *pos += 4;
                        let mut cp = u32::from_str_radix(&hex, 16)
                            .map_err(|_| "JSON 解析：非法 \\u 编码")?;
                        // 代理对
                        if (0xD800..=0xDBFF).contains(&cp)
                            && *pos + 6 <= b.len()
                            && b[*pos] == '\\'
                            && b[*pos + 1] == 'u'
                        {
                            let hex2: String = b[*pos + 2..*pos + 6].iter().collect();
                            if let Ok(lo) = u32::from_str_radix(&hex2, 16) {
                                if (0xDC00..=0xDFFF).contains(&lo) {
                                    *pos += 6;
                                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                                }
                            }
                        }
                        out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                    }
                    _ => return Err(format!("JSON 解析：非法转义 \\{}", e)),
                }
            }
            c => out.push(c),
        }
    }
    Err("JSON 解析：字符串未闭合".into())
}

fn parse_number(b: &[char], pos: &mut usize) -> Result<Json, String> {
    let start = *pos;
    if *pos < b.len() && (b[*pos] == '-' || b[*pos] == '+') {
        *pos += 1;
    }
    let mut is_float = false;
    while *pos < b.len() {
        match b[*pos] {
            '0'..='9' => *pos += 1,
            '.' | 'e' | 'E' => {
                is_float = true;
                *pos += 1;
            }
            '-' | '+' => *pos += 1, // 指数符号
            _ => break,
        }
    }
    if start == *pos {
        return Err(format!("JSON 解析：第 {} 字符处无法识别", start));
    }
    let text: String = b[start..*pos].iter().collect();
    if !is_float {
        if let Ok(i) = text.parse::<i64>() {
            return Ok(Json::Int(i));
        }
    }
    text.parse::<f64>()
        .map(Json::Num)
        .map_err(|_| format!("JSON 解析：非法数字 {}", text))
}

fn parse_array(b: &[char], pos: &mut usize, depth: usize) -> Result<Json, String> {
    // v1.4：深度检查在容器入口——第 depth 层数组/对象超过上限即拒绝
    if depth > MAX_JSON_DEPTH {
        return Err(format!("JSON 解析：嵌套深度超过上限 {}", MAX_JSON_DEPTH));
    }
    *pos += 1; // '['
    let mut items = Vec::new();
    skip_ws(b, pos);
    if *pos < b.len() && b[*pos] == ']' {
        *pos += 1;
        return Ok(Json::Arr(items));
    }
    loop {
        items.push(parse_value(b, pos, depth)?);
        skip_ws(b, pos);
        if *pos >= b.len() {
            return Err("JSON 解析：数组未闭合".into());
        }
        match b[*pos] {
            ',' => {
                *pos += 1;
            }
            ']' => {
                *pos += 1;
                return Ok(Json::Arr(items));
            }
            _ => return Err("JSON 解析：数组元素间缺少 , 或 ]".into()),
        }
    }
}

fn parse_object(b: &[char], pos: &mut usize, depth: usize) -> Result<Json, String> {
    // v1.4：深度检查在容器入口——第 depth 层数组/对象超过上限即拒绝
    if depth > MAX_JSON_DEPTH {
        return Err(format!("JSON 解析：嵌套深度超过上限 {}", MAX_JSON_DEPTH));
    }
    *pos += 1; // '{'
    let mut map = BTreeMap::new();
    skip_ws(b, pos);
    if *pos < b.len() && b[*pos] == '}' {
        *pos += 1;
        return Ok(Json::Obj(map));
    }
    loop {
        skip_ws(b, pos);
        if *pos >= b.len() || b[*pos] != '"' {
            return Err("JSON 解析：对象键必须是字符串".into());
        }
        let key = parse_string(b, pos)?;
        skip_ws(b, pos);
        if *pos >= b.len() || b[*pos] != ':' {
            return Err("JSON 解析：对象键后缺少 :".into());
        }
        *pos += 1;
        let val = parse_value(b, pos, depth)?;
        map.insert(key, val);
        skip_ws(b, pos);
        if *pos >= b.len() {
            return Err("JSON 解析：对象未闭合".into());
        }
        match b[*pos] {
            ',' => {
                *pos += 1;
            }
            '}' => {
                *pos += 1;
                return Ok(Json::Obj(map));
            }
            _ => return Err("JSON 解析：对象键值对间缺少 , 或 }".into()),
        }
    }
}

/// 解析 HTTP 查询串（不含 ?），返回 (key, value) 列表（已 URL 解码）。
pub fn parse_query(qs: &str) -> Vec<(String, String)> {
    qs.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (url_decode(k), url_decode(v)),
            None => (url_decode(p), String::new()),
        })
        .collect()
}

pub fn url_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("");
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                } else {
                    out.push(b'%');
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let src = r#"{"a":[1,2.5,"x\ny"],"b":{"c":true,"d":null},"e":12}"#;
        let v = Json::parse(src).unwrap();
        assert_eq!(v.get("e").unwrap().as_i64(), Some(12));
        assert_eq!(v.get("a").unwrap().as_arr().unwrap().len(), 3);
        let out = v.to_string();
        let v2 = Json::parse(&out).unwrap();
        assert_eq!(v, v2);
    }

    #[test]
    fn unicode_escape() {
        let v = Json::parse(r#""中文A""#).unwrap();
        assert_eq!(v.as_str().unwrap(), "中文A");
    }

    #[test]
    fn urldecode() {
        assert_eq!(url_decode("%E5%88%9D%E4%B8%80+%E7%8F%AD"), "初一 班");
    }

    // ---- v1.4：嵌套深度限制（防栈溢出 DoS）----

    #[test]
    fn depth_within_limit_ok() {
        // 100 层嵌套（低于上限 128）应正常解析
        let mut s = String::new();
        for _ in 0..100 {
            s.push('[');
        }
        for _ in 0..100 {
            s.push(']');
        }
        let v = Json::parse(&s).unwrap();
        let mut cur = &v;
        // 最外层到最内层共 99 个「含 1 元素」的数组，第 100 层为空数组
        for _ in 0..99 {
            match cur {
                Json::Arr(items) => {
                    assert_eq!(items.len(), 1);
                    cur = &items[0];
                }
                _ => panic!("应为数组"),
            }
        }
        assert!(matches!(cur, Json::Arr(items) if items.is_empty()));
    }

    #[test]
    fn depth_over_limit_rejected() {
        // 200 层嵌套（超过上限 128）应返回错误而非栈溢出
        // 数组：[[[...]]]
        let mut s = String::new();
        for _ in 0..200 { s.push('['); }
        for _ in 0..200 { s.push(']'); }
        let err = Json::parse(&s).unwrap_err();
        assert!(err.contains("嵌套深度"), "错误信息应说明深度问题：{}", err);
        // 对象：{"a":{"a":...}}（对象键必须为字符串，故用 "a" 逐层包裹）
        let mut s = String::new();
        for _ in 0..200 { s.push_str("{\"a\":"); }
        s.push('1');
        for _ in 0..200 { s.push('}'); }
        let err = Json::parse(&s).unwrap_err();
        assert!(err.contains("嵌套深度"), "错误信息应说明深度问题：{}", err);
    }

    #[test]
    fn depth_limit_boundary() {
        // 恰好 128 层应成功、129 层应失败（上限边界行为）
        let build = |n: usize| {
            let mut s = String::new();
            for _ in 0..n { s.push('['); }
            for _ in 0..n { s.push(']'); }
            s
        };
        assert!(Json::parse(&build(128)).is_ok());
        assert!(Json::parse(&build(129)).is_err());
    }
}
