//! 示例扩展二：参与率统计。
//!
//! 演示「纯只读扩展」：不订阅事件，只注册自己的查询路由，
//! 调用核心只读 API 汇总各班报名参与率。

use crate::core::ext::{CoreContext, ExtRoute, Extension};
use crate::core::http::Response;
use crate::core::json::Json;
use crate::log_info;
use std::sync::Arc;

pub struct Participation;

impl Participation {
    fn compute(core: &CoreContext) -> Json {
        core.read(|d| {
            // 各班报名人数 / 学生人数
            let mut per_class: Vec<(String, i64, i64)> = Vec::new(); // 班名, 报名人次, 学生数
            for s in &d.students {
                let name = s.class_name();
                if let Some(e) = per_class.iter_mut().find(|(n, _, _)| *n == name) {
                    e.1 += d
                        .registrations
                        .iter()
                        .filter(|r| r.student_id == s.id)
                        .count() as i64;
                    e.2 += 1;
                } else {
                    per_class.push((
                        name,
                        d.registrations
                            .iter()
                            .filter(|r| r.student_id == s.id)
                            .count() as i64,
                        1,
                    ));
                }
            }
            per_class.sort_by(|a, b| a.0.cmp(&b.0));
            let rows: Vec<Json> = per_class
                .into_iter()
                .map(|(name, regs, total)| {
                    let mut o = Json::obj();
                    o.set("class", Json::s(name));
                    o.set("registrations", Json::Int(regs));
                    o.set("students", Json::Int(total));
                    o.set(
                        "avg_per_student",
                        Json::Num((if total > 0 { regs as f64 / total as f64 } else { 0.0 } * 100.0)
                            .round()
                            / 100.0),
                    );
                    o
                })
                .collect();
            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("classes", Json::Arr(rows));
            o
        })
    }
}

impl Extension for Participation {
    fn name(&self) -> &'static str {
        "participation"
    }

    fn description(&self) -> &'static str {
        "参与率统计：汇总各班报名人次与学生人均报名数"
    }

    fn routes(&self) -> Vec<ExtRoute> {
        vec![ExtRoute {
            method: "GET",
            path: "/api/ext/participation/summary",
            handler: Arc::new(|core, _req| {
                log_info!("ext.participation", "查询班级参与率汇总");
                Ok(Response::json(&Self::compute(core)))
            }),
        }]
    }
}
