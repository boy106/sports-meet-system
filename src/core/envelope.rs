//! 统一响应信封（v1.6.0）。
//!
//! 背景：v1.5.2 及之前，每个 handler 各自拼装响应 JSON —— 有的是
//! `{"ok":true,"students":[...]}`，有的是 `{"events":[...]}`，有的干脆把
//! 数组放在顶层。客户端因此只能"一个接口一套读法"，49 处调用各写各的取值
//! 路径；错误更是五花八门（`error` / `message` / 裸字符串）。
//!
//! v1.6.0 起，**所有核心 API 响应统一为**：
//!
//! ```json
//! // 成功
//! {"ok": true,  "data": <原负载>, "ts": 1790059444}
//! // 失败
//! {"ok": false, "error": {"code": "E_NOT_FOUND", "message": "项目不存在"}, "ts": 1790059444}
//! ```
//!
//! 要点：
//!   * **`data` 原样承载旧负载**——既有字段名一个不改，客户端只需多剥一层。
//!     这样业务语义零改动，重构范围可控。
//!   * **错误码机器可读**（`E_*`），客户端据此分流，不必解析中文文案。
//!   * `ts` 为服务端 Unix 秒，便于前端排查"看到的是不是旧数据"。
//!
//! 例外：**SSE 流**（`text/event-stream`）与**文件下载**不走信封 ——
//! 它们不是 JSON 文档，套信封反而破坏协议（EventSource / 浏览器下载
//! 无法解包）。这个例外在 `envelope_skip` 中显式列明。

use crate::core::error::ApiErr;
use crate::core::json::Json;

/// 当前服务端时间（Unix 秒）。
pub fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// 成功信封：`{"ok":true, "data":..., "ts":...}`
///
/// `data` 为 `None` 时输出 `"data": null`，保证字段始终存在 ——
/// 客户端不必区分"字段缺失"与"值为空"，减少一类判空分支。
pub fn ok_envelope(data: Option<&Json>) -> Json {
    let mut o = Json::obj();
    o.set("ok", Json::Bool(true));
    o.set("data", data.cloned().unwrap_or(Json::Null));
    o.set("ts", Json::Num(now_secs() as f64));
    o
}

/// 失败信封：`{"ok":false, "error":{"code":..., "message":...}, "ts":...}`
///
/// `err.data`（删除预览等）若存在，挂在 `error.detail` 下，避免与
/// 顶层 `data` 语义混淆（失败响应里不该有 `data`）。
pub fn err_envelope(err: &ApiErr) -> Json {
    let mut e = Json::obj();
    e.set("code", Json::s(err.code.as_str()));
    e.set("message", Json::s(err.message.clone()));
    if let Some(detail) = err.data.as_ref() {
        e.set("detail", detail.clone());
    }
    let mut o = Json::obj();
    o.set("ok", Json::Bool(false));
    o.set("error", e);
    // 兼容期字段：老的客户端读 `error`（字符串）或 `message`。
    // 保留一份扁平文案，让未升级的前端在过渡期仍能显示错误。
    o.set("message", Json::s(err.message.clone()));
    o.set("ts", Json::Num(now_secs() as f64));
    o
}

/// 判断该响应是否应跳过信封包装。
///
/// 跳过的情况（非 JSON 文档协议）：
///   * SSE 流 `text/event-stream`——EventSource 有自己的帧协议；
///   * 文件下载（带 `filename`，如 xlsx / csv 导出）——浏览器直接落盘；
///   * 任何非 `application/json` 的响应。
///
/// 静态资源（HTML/CSS）走的是另一条分支，不经过这里。
pub fn envelope_skip(content_type: &str, filename: Option<&str>) -> bool {
    if filename.is_some() {
        return true;
    }
    let ct = content_type.to_ascii_lowercase();
    !ct.starts_with("application/json")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::error::ErrCode;

    #[test]
    fn ok_envelope_shape() {
        let mut d = Json::obj();
        d.set("students", Json::Arr(vec![]));
        let e = ok_envelope(Some(&d));
        // 序列化后应含三个顶层字段
        let s = e.to_string();
        assert!(s.contains("\"ok\":true"), "{}", s);
        assert!(s.contains("\"data\""), "{}", s);
        assert!(s.contains("\"ts\""), "{}", s);
        // 旧负载原样保留，字段名未变——这是"零语义改动"的关键保证
        assert!(s.contains("\"students\""), "{}", s);
    }

    #[test]
    fn ok_envelope_null_data_when_none() {
        let s = ok_envelope(None).to_string();
        assert!(s.contains("\"data\":null"), "{}", s);
    }

    #[test]
    fn err_envelope_carries_stable_code() {
        let e = ApiErr::not_found("项目不存在");
        let s = err_envelope(&e).to_string();
        assert!(s.contains("\"ok\":false"), "{}", s);
        assert!(s.contains("E_NOT_FOUND"), "{}", s);
        assert!(s.contains("项目不存在"), "{}", s);
        // 过渡期扁平文案仍在
        assert!(s.contains("\"message\""), "{}", s);
    }

    #[test]
    fn err_envelope_detail_for_delete_preview() {
        let mut prev = Json::obj();
        prev.set("note", Json::s("将解绑 3 条报名"));
        let e = ApiErr::confirm("需要确认").with_data(prev);
        let s = err_envelope(&e).to_string();
        assert!(s.contains("E_CONFIRM"), "{}", s);
        // detail 挂在 error 下，不与顶层 data 混淆
        assert!(s.contains("\"detail\""), "{}", s);
        assert!(s.contains("将解绑 3 条报名"), "{}", s);
        assert!(!s.contains("\"data\":{\"note\""), "不应有顶层 data: {}", s);
    }

    #[test]
    fn code_override_survives_envelope() {
        // 同为 400，重名用 Conflict 码
        let e = ApiErr::new("该班级已有同名学生").with_code(ErrCode::Conflict);
        let s = err_envelope(&e).to_string();
        assert!(s.contains("E_CONFLICT"), "{}", s);
    }

    #[test]
    fn envelope_skips_stream_and_download() {
        assert!(envelope_skip("text/event-stream; charset=utf-8", None));
        assert!(envelope_skip("application/json", Some("成绩.xlsx")));
        assert!(envelope_skip("text/csv", None));
        assert!(!envelope_skip("application/json; charset=utf-8", None));
    }

    #[test]
    fn now_secs_is_plausible() {
        // 应晚于 2024-01-01，早于 2100 年——防止时钟计算写错
        let t = now_secs();
        assert!(t > 1_704_067_200, "{}", t);
        assert!(t < 4_102_444_800, "{}", t);
    }
}
