//! 赛程编排（秩序册）的 HTTP 接口（核心模块）。
//!
//! 处理器签名与 `http::Route` 的 handler 一致：
//! `fn(&Core, &Request) -> Result<Response, ApiErr>`，
//! 由 `crate::core::api::Core::routes()` 统一注册。
//!
//! 约定（与现有接口保持一致）：
//! - 成功响应自带统一信封：`{ "ok": true, ...data }`
//! - 失败走 `ApiErr` → 路由层统一包成 `{ "ok": false, "error": {... } }`
//! - 写操作经 `Core::write` 自动落盘（原子写）
//! - 遵守既有限流 / 校验（在路由注册处已套）

use crate::core::api::{ApiErr, Core};
use crate::core::http::{Request, Response};
use crate::core::json::Json;
use crate::core::schedule::{
    assign_lanes, auto_arrange, detect_conflicts, ArrangeOptions, Session, Slot, Venue,
    venues_to_json,
};
use crate::core::store::event_to_json;
use std::collections::HashMap;

/// 统一成功响应。
fn ok(o: Json) -> Response {
    Response::json(&o)
}

/// 读取整套赛程视图（场/单元/时段/冲突/项目报名数）。
///
/// 这是前端"赛程"页的主数据接口，一次拉全，避免多次往返。
fn schedule_view(c: &Core) -> Json {
    c.read(|d| {
        let mut o = Json::obj();
        o.set("ok", Json::Bool(true));
        o.set("schedule_days", Json::Int(d.schedule_days));
        o.set("venues", venues_to_json(&d.venues));
        o.set(
            "sessions",
            Json::arr(d.sessions.iter().map(|s| s.to_json())),
        );
        o.set("slots", Json::arr(d.slots.iter().map(|s| s.to_json())));
        // 场地占用总览 + 各单元占用：让老师一眼看出"哪里排满了、哪里空着"
        o.set(
            "venue_usage",
            Json::arr(
                crate::core::schedule::venue_summary(&d.venues, &d.slots)
                    .iter()
                    .map(|u| u.to_json()),
            ),
        );
        let mut susage: Vec<Json> = Vec::new();
        for s in &d.sessions {
            let mut su = Json::obj();
            su.set("session_id", Json::Int(s.id));
            su.set("label", Json::s(s.label()));
            su.set(
                "venues",
                Json::arr(
                    crate::core::schedule::session_usage(s, &d.venues, &d.slots)
                        .iter()
                        .map(|u| u.to_json()),
                ),
            );
            susage.push(su);
        }
        o.set("session_usage", Json::arr(susage));
        // 冲突检测实时跑：老师改完编排，前端立刻能看到红黄提示
        let conflicts = detect_conflicts(
            &d.events,
            &d.registrations,
            &d.slots,
            &d.venues,
            &d.sessions,
            &d.students,
        );
        o.set(
            "conflicts",
            Json::arr(conflicts.iter().map(|c| c.to_json())),
        );
        // 项目列表（带报名人数），供编排 UI 展示"哪些还没排"
        let mut evs: Vec<Json> = Vec::new();
        for e in &d.events {
            let cnt = d
                .registrations
                .iter()
                .filter(|r| r.event_id == e.id)
                .count() as i64;
            let mut eo = event_to_json(e);
            eo.set("registered", Json::Int(cnt));
            evs.push(eo);
        }
        o.set("events", Json::arr(evs));
        o
    })
}

pub fn get_schedule(c: &Core, _req: &Request) -> Result<Response, ApiErr> {
    Ok(ok(schedule_view(c)))
}

/// 解析并校验场地数组。
fn parse_venues(body: &Json) -> Result<Vec<Venue>, ApiErr> {
    let arr = body
        .get("venues")
        .and_then(|x| x.as_arr())
        .ok_or_else(|| ApiErr::new("venues 字段缺失或格式错误"))?;
    let vs: Vec<Venue> = arr.iter().filter_map(Venue::from_json).collect();
    if vs.is_empty() {
        return Err(ApiErr::new("至少需要配置 1 个场地（如：田径场跑道、田赛区）"));
    }
    Ok(vs)
}

/// 解析并校验单元数组。
fn parse_sessions(body: &Json) -> Result<Vec<Session>, ApiErr> {
    let arr = body
        .get("sessions")
        .and_then(|x| x.as_arr())
        .ok_or_else(|| ApiErr::new("sessions 字段缺失或格式错误"))?;
    let ss: Vec<Session> = arr.iter().filter_map(Session::from_json).collect();
    if ss.is_empty() {
        return Err(ApiErr::new("至少需要 1 个竞赛单元（如：第1天上午）"));
    }
    Ok(ss)
}

/// 保存场地配置。
pub fn set_venues(c: &Core, req: &Request) -> Result<Response, ApiErr> {
    let body = req
        .json()
        .map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
    let venues = parse_venues(&body)?;
    c.write(|d| {
        d.venues = venues;
        Ok::<(), ApiErr>(())
    })?;
    Ok(ok(schedule_view(c)))
}

/// 保存单元配置。
pub fn set_sessions(c: &Core, req: &Request) -> Result<Response, ApiErr> {
    let body = req
        .json()
        .map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
    let sessions = parse_sessions(&body)?;
    c.write(|d| {
        d.sessions = sessions;
        Ok::<(), ApiErr>(())
    })?;
    Ok(ok(schedule_view(c)))
}

/// 设置赛程天数，并据此重新生成默认单元（保留场地与已排赛程）。
pub fn set_days(c: &Core, req: &Request) -> Result<Response, ApiErr> {
    let body = req
        .json()
        .map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
    let days = body
        .get_i64("days")
        .unwrap_or(2)
        .clamp(1, 5);
    c.write(|d| {
        d.schedule_days = days;
        d.sessions = crate::core::schedule::default_sessions(days);
        Ok::<(), ApiErr>(())
    })?;
    Ok(ok(schedule_view(c)))
}

/// 一键自动编排（贪心 + 场地并行）。
///
/// `replace=true`：清空重排；`false`：在已有基础上补齐未编排的项目。
/// 未能排入的项目如实返回 `unplaced`，**不静默丢弃**（规则 20 的反面：
/// 这里不是"修复非法值"，而是"不掩盖失败"）。
pub fn arrange(c: &Core, req: &Request) -> Result<Response, ApiErr> {
    let body = req
        .json()
        .map_err(|e| ApiErr::new(format!("JSON 解析失败：{}", e)))?;
    let replace = body.get("replace").and_then(|v| v.as_bool()).unwrap_or(true);
    let opts = ArrangeOptions {
        replace,
        duration_override: HashMap::new(),
    };
    let (slots, unplaced) = c.write(|d| {
        let res = auto_arrange(
            &d.events,
            &d.registrations,
            &d.venues,
            &d.sessions,
            &d.slots,
            &opts,
        );
        d.slots = res.slots.clone();
        Ok::<(Vec<Slot>, Vec<(i64, String)>), ApiErr>((res.slots, res.unplaced))
    })?;

    let placed = slots.len() as i64;
    let mut o = schedule_view(c);
    o.set("placed", Json::Int(placed));
    o.set(
        "unplaced",
        Json::arr(unplaced.iter().map(|(id, why)| {
            let mut u = Json::obj();
            u.set("event_id", Json::Int(*id));
            u.set("reason", Json::s(why.clone()));
            u
        })),
    );
    Ok(ok(o))
}

/// 清空已编排的赛程（保留场地与单元）。
///
/// 这是"撤销一次编排"的最轻量方式：老师排乱了，一键回到"空白画布"，
/// 再重新一键编排。不删项目、不删报名、不删场地。
pub fn clear(c: &Core, _req: &Request) -> Result<Response, ApiErr> {
    c.write(|d| {
        d.slots = Vec::new();
        Ok::<(), ApiErr>(())
    })?;
    Ok(ok(schedule_view(c)))
}

/// 查看某个径赛/田赛项目的分组与分道（依据现有成绩自动排种子）。
///
/// 种子来源：该生在该项目的**已有最好成绩**（径赛取最小、田赛取最大）。
/// 没成绩的学生退化为按报名顺序，保证结果稳定可复现。
pub fn get_lanes(c: &Core, req: &Request) -> Result<Response, ApiErr> {
    let eid = req
        .query_get("event_id")
        .and_then(|s| s.parse::<i64>().ok())
        .ok_or_else(|| ApiErr::new("缺少 event_id 参数"))?;

    let mut err: Option<String> = None;
    let j = c.read(|d| {
        let ev = match d.events.iter().find(|e| e.id == eid) {
            None => {
                err = Some(format!("项目 {} 不存在", eid));
                return Json::obj();
            }
            Some(e) => e,
        };
        let mut parts: Vec<(i64, Option<f64>)> = Vec::new();
        for r in &d.registrations {
            if r.event_id == eid {
                let mut best: Option<f64> = None;
                for res in &d.results {
                    if res.event_id == eid && res.student_id == Some(r.student_id) {
                        if let Some(v) = res.score_value {
                            best = Some(match best {
                                None => v,
                                Some(b) => {
                                    if ev.is_track() {
                                        b.min(v)
                                    } else {
                                        b.max(v)
                                    }
                                }
                            });
                        }
                    }
                }
                parts.push((r.student_id, best));
            }
        }
        let lanes = assign_lanes(ev, &parts, &d.students);
        let mut o = Json::obj();
        o.set("ok", Json::Bool(true));
        o.set("event_id", Json::Int(eid));
        o.set("is_track", Json::Bool(ev.is_track()));
        o.set("lanes", Json::arr(lanes.iter().map(|l| l.to_json())));
        o
    });
    if let Some(e) = err {
        return Err(ApiErr::new(e));
    }
    Ok(ok(j))
}
