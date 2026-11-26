//! 示例扩展一：破纪录快讯。
//!
//! 演示「事件钩子 + 调用核心 API」：订阅成绩计算事件，凡是破校纪录的
//! 成绩，记录到自己的数据文件，并暴露查询接口。扩展状态完全自治，
//! 不侵入核心数据。

use crate::core::ext::{CoreContext, CoreEvent, EventKind, ExtRoute, Extension};
use crate::core::http::Response;
use crate::core::json::Json;
use crate::core::sync::LockExt;
use crate::log_info;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

fn state() -> &'static Mutex<(PathBuf, Vec<Json>)> {
    static S: OnceLock<Mutex<(PathBuf, Vec<Json>)>> = OnceLock::new();
    S.get_or_init(|| Mutex::new((PathBuf::from("data/ext_records.json"), Vec::new())))
}

pub struct RecordsFeed;

impl RecordsFeed {
    pub fn new(data_dir: PathBuf) -> Self {
        let mut g = state().lock_recover();
        g.0 = data_dir.join("ext_records.json");
        RecordsFeed
    }

    fn load() -> Vec<Json> {
        let g = state().lock_recover();
        std::fs::read_to_string(&g.0)
            .ok()
            .and_then(|s| Json::parse(&s).ok())
            .and_then(|j| match j {
                Json::Arr(a) => Some(a),
                _ => None,
            })
            .unwrap_or_default()
    }

    fn save(items: &[Json]) {
        let g = state().lock_recover();
        let _ = std::fs::write(&g.0, Json::arr(items.to_vec()).to_string());
    }
}

impl Extension for RecordsFeed {
    fn name(&self) -> &'static str {
        "records-feed"
    }

    fn description(&self) -> &'static str {
        "破纪录快讯：监听成绩计算事件，自动记录破校纪录的成绩并提供查询接口"
    }

    fn on_init(&self, _ctx: &CoreContext) -> Result<(), String> {
        let items = Self::load();
        let n = items.len();
        Self::save(&items);
        log_info!("ext.records-feed", "破纪录快讯扩展就绪，已有 {} 条历史记录", n);
        Ok(())
    }

    fn routes(&self) -> Vec<ExtRoute> {
        vec![ExtRoute {
            method: "GET",
            path: "/api/ext/records-feed/list",
            handler: Arc::new(|_core, _req| {
                let items = RecordsFeed::load();
                let mut o = Json::obj();
                o.set("ok", Json::Bool(true));
                o.set("count", Json::Int(items.len() as i64));
                o.set("items", Json::Arr(items));
                Ok(Response::json(&o))
            }),
        }]
    }

    fn on_event(&self, ctx: &CoreContext, event: &CoreEvent) {
        if event.kind != EventKind::ResultsComputed {
            return;
        }
        let event_id = event.payload.get_i64("event_id").unwrap_or(0);
        if event_id == 0 {
            return;
        }
        // 调用核心 API 拿到该项目的成绩明细，挑出破纪录的
        let detail = match ctx.results_view(event_id) {
            Ok(v) => v,
            Err(_) => return,
        };
        let ev_name = detail
            .get("event")
            .and_then(|e| e.get_str("name"))
            .unwrap_or("未知项目")
            .to_string();
        let mut new_items = Vec::new();
        if let Some(Json::Arr(entries)) = detail.get("entries") {
            for e in entries {
                if e.get("broke_record").and_then(|b| b.as_bool()) != Some(true) {
                    continue;
                }
                let mut o = Json::obj();
                o.set("time", Json::s(event.time.clone()));
                o.set("event", Json::s(ev_name.clone()));
                o.set("who", e.get("label").cloned().unwrap_or(Json::Null));
                o.set("score", e.get("score_text").cloned().unwrap_or(Json::Null));
                o.set("points", e.get("points").cloned().unwrap_or(Json::Null));
                new_items.push(o);
            }
        }
        if new_items.is_empty() {
            return;
        }
        let mut items = Self::load();
        let added = new_items.len();
        items.extend(new_items);
        let cut = items.len().saturating_sub(200);
        if cut > 0 {
            items.drain(0..cut);
        }
        Self::save(&items);
        log_info!(
            "ext.records-feed",
            "记录 {} 条破纪录成绩（项目：{}），当前共 {} 条",
            added,
            ev_name,
            items.len()
        );
    }
}
