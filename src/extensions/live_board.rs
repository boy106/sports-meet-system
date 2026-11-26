//! 实时赛况大屏扩展（v1.5 新增）。
//!
//! # 为什么需要它
//!
//! v1.4 及以前，想看"现在哪个班领先"必须**手动刷新**报表页。运动会现场
//! 的真实需求是：主席台投影上一块大屏，成绩一出、名次一变，大屏就动。
//!
//! 本扩展用 **SSE（Server-Sent Events）** 实现单向推送，理由：
//!
//! | 方案 | 是否需新依赖 | 断线重连 | 适合本场景 |
//! | --- | --- | --- | --- |
//! | 轮询 | 否 | 天然 | 延迟高（要么慢要么打服务器） |
//! | WebSocket | 否（但要自己写握手/分帧） | 需自行实现 | 双向通信过剩 |
//! | **SSE** | **否** | **浏览器内建** | ✅ 只推不收，正是本场景 |
//!
//! 浏览器对 SSE 内建 `EventSource`：自动重连、自动带 `Last-Event-ID`，
//! 服务端只需 `text/event-stream` + 逐条事件。本扩展全程只用标准库。
//!
//! # 与现场节奏的适配
//!
//! 1. **事件驱动**：不轮询、不空转。核心一有 `results_computed` /
//!    `event_deleted` 等事件，立刻算好新的榜单推给所有在线大屏。
//! 2. **心跳保活**：每 15 秒发一条 SSE 注释行，防止交换机/代理
//!    把长连接当死连接回收（`core/http.rs` 的 `STREAM_WRITE_TIMEOUT`
//!    也据此设置为 1 小时）。
//! 3. **新观众即时同步**：后打开大屏的人会立刻收到一份 `snapshot`，
//!    不需要等下一次成绩变动。
//! 4. **多屏广播**：广播通道是一个 `Mutex<Vec<Sender>>` 列表，
//!    主席台、检录处、教师手机可同时挂着，互不影响。
//!
//! # 路由
//!
//! | 方法 | 路径 | 说明 |
//! | --- | --- | --- |
//! | GET | `/api/ext/live-board/stream` | SSE 事件流（长连接） |
//! | GET | `/api/ext/live-board/snapshot` | 一次性快照（轮询/首屏兜底） |
//! | GET | `/api/ext/live-board/status` | 扩展自身状态（在线上屏数等） |
//!
//! 路径均以 `/api/ext/live-board/` 开头，符合规则 6 的路由前缀约束。
//!
//! # 数据形态
//!
//! 推送两个 SSE 事件：
//! * `snapshot` —— 完整榜单快照（首屏 / 全量刷新）
//! * `update`   —— 增量通知（带 `kind` 与变化的项目 id，前端据此提示）
//!
//! 榜单口径与报表页保持一致：年级总分排行 + 最近计算的项目名次。

// CoreContext 已由 core::ext 提供，此处不再单独引入 Core（v1.5）
use crate::core::ext::{CoreContext, CoreEvent, EventKind, ExtRoute, Extension};
use crate::core::http::{Request, Response};
use crate::core::json::Json;
use std::collections::HashMap;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// 心跳间隔：15 秒。远小于交换机常见的 30~60 秒空闲回收阈值。
const HEARTBEAT: Duration = Duration::from_secs(15);

/// 单个大屏客户端的最大并发数。防止有人反复刷新把线程耗光。
const MAX_VIEWERS: usize = 32;

/// 一条待广播的消息。
#[derive(Clone)]
struct Broadcast {
    /// 事件名：snapshot / update
    event: &'static str,
    /// 事件负载（已序列化 JSON 文本）
    data: String,
}

/// 在线观看者：一个发送端 + 建立时间（用于状态面板展示）。
struct Viewer {
    tx: Sender<Broadcast>,
    since: Instant,
}

pub struct LiveBoard {
    /// 在线大屏列表。每个大屏一个 mpsc 通道，互不阻塞。
    viewers: Mutex<Vec<Viewer>>,
    /// 累计推送消息条数（状态面板用）
    pushed: Mutex<u64>,
    /// 累计连接数（含已断开）
    accepted: Mutex<u64>,
    /// 累计被拒（超出 MAX_VIEWERS）
    rejected: Mutex<u64>,
}

impl LiveBoard {
    pub fn new() -> LiveBoard {
        LiveBoard {
            viewers: Mutex::new(Vec::new()),
            pushed: Mutex::new(0),
            accepted: Mutex::new(0),
            rejected: Mutex::new(0),
        }
    }

    /// 向所有在线大屏广播。
    ///
    /// 断开的客户端在发送失败时被移除（惰性清理，无需额外的连接跟踪线程）。
    fn broadcast(&self, event: &'static str, data: String) {
        let mut vs = match self.viewers.lock() {
            Ok(g) => g,
            Err(_) => return,
        };
        let before = vs.len();
        vs.retain(|v| v.tx.send(Broadcast { event, data: data.clone() }).is_ok());
        let dropped = before - vs.len();
        drop(vs);
        if let Ok(mut n) = self.pushed.lock() {
            *n += before as u64;
        }
        if dropped > 0 {
            crate::log_info!("live-board", "清理 {} 个已断开的大屏连接", dropped);
        }
    }

    /// 生成当前赛况快照 JSON。
    ///
    /// 口径与 `/api/report_table` 保持一致，避免大屏与报表页"两个数"。
    fn snapshot(&self, ctx: &CoreContext) -> Json {
        ctx.read(|d| {
            let mut grades = Json::obj();

            // 年级总分榜：复用核心的计分聚合，不另写一套算法
            // （规则 11：算法只有一处实现，避免两处口径漂移）
            for g in &d.settings.grades {
                let table = crate::core::scoring::grade_total_table(d, g);
                grades.set(g, Json::Arr(table));
            }

            // 最近有成绩的项目（按结果 id 倒序取前 8 个不同项目）
            let mut recent_events: Vec<Json> = Vec::new();
            // 收集已计算的项目，按"最后一条成绩的 id"倒序
            let mut last_result_of: HashMap<i64, i64> = HashMap::new();
            for r in &d.results {
                if r.points.is_none() {
                    continue;
                }
                let e = last_result_of.entry(r.event_id).or_insert(0);
                if r.id > *e {
                    *e = r.id;
                }
            }
            let mut ordered: Vec<(i64, i64)> = last_result_of.into_iter().collect();
            ordered.sort_by(|a, b| b.1.cmp(&a.1)); // 按最后成绩 id 倒序
            for (eid, _) in ordered.into_iter().take(8) {
                if let Some(ev) = d.events.iter().find(|e| e.id == eid) {
                    let mut rows: Vec<Json> = Vec::new();
                    let mut list: Vec<&crate::core::model::Result> = d
                        .results
                        .iter()
                        .filter(|r| r.event_id == eid && r.points.is_some())
                        .collect();
                    list.sort_by_key(|r| r.rank.unwrap_or(i64::MAX));
                    for r in list.into_iter().take(6) {
                        let who = if let Some(sid) = r.student_id {
                            d.students
                                .iter()
                                .find(|s| s.id == sid)
                                .map(|s| s.name.clone())
                                .unwrap_or_else(|| format!("学生 {}", sid))
                        } else {
                            format!("{}{}班", r.grade, r.class_no.unwrap_or(0))
                        };
                        let mut row = Json::obj();
                        row.set("rank", Json::Int(r.rank.unwrap_or(0)));
                        row.set("who", Json::s(who));
                        row.set(
                            "grade",
                            Json::s(
                                d.students
                                    .iter()
                                    .find(|s| Some(s.id) == r.student_id)
                                    .map(|s| s.grade.clone())
                                    .unwrap_or_else(|| r.grade.clone()),
                            ),
                        );
                        row.set(
                            "class_no",
                            Json::Int(
                                d.students
                                    .iter()
                                    .find(|s| Some(s.id) == r.student_id)
                                    .map(|s| s.class_no)
                                    .or(r.class_no)
                                    .unwrap_or(0),
                            ),
                        );
                        row.set("score_text", Json::s(r.score_text.clone()));
                        row.set(
                            "points",
                            r.points.map(Json::Num).unwrap_or(Json::Null),
                        );
                        row.set("broke_record", Json::Bool(r.broke_record));
                        rows.push(row);
                    }
                    let mut eo = Json::obj();
                    eo.set("event_id", Json::Int(eid));
                    eo.set("name", Json::s(ev.name.clone()));
                    eo.set("category", Json::s(ev.category.clone()));
                    eo.set("unit", Json::s(ev.unit.clone()));
                    eo.set("rows", Json::Arr(rows));
                    recent_events.push(eo);
                }
            }

            // 在场破纪录历史（供大屏做"破纪录滚动条"）
            let mut records: Vec<Json> = Vec::new();
            let mut rec_list: Vec<&crate::core::model::Result> =
                d.results.iter().filter(|r| r.broke_record).collect();
            rec_list.sort_by_key(|r| std::cmp::Reverse(r.id));
            for r in rec_list.into_iter().take(10) {
                let ev = d.events.iter().find(|e| e.id == r.event_id);
                let who = if let Some(sid) = r.student_id {
                    d.students
                        .iter()
                        .find(|s| s.id == sid)
                        .map(|s| format!("{}（{}）", s.name, s.class_name()))
                        .unwrap_or_else(|| format!("学生 {}", sid))
                } else {
                    format!("{}{}班", r.grade, r.class_no.unwrap_or(0))
                };
                let mut ro = Json::obj();
                ro.set(
                    "event_name",
                    Json::s(ev.map(|e| e.name.clone()).unwrap_or_default()),
                );
                ro.set("who", Json::s(who));
                ro.set("score_text", Json::s(r.score_text.clone()));
                ro.set(
                    "record",
                    ev.and_then(|e| e.record)
                        .map(Json::Num)
                        .unwrap_or(Json::Null),
                );
                ro.set(
                    "record_text",
                    Json::s(
                        ev.and_then(|e| e.record)
                            .map(|v| {
                                crate::core::scoring::format_score(
                                    v,
                                    ev.map(|e| e.unit.as_str()).unwrap_or("米"),
                                )
                            })
                            .unwrap_or_default(),
                    ),
                );
                records.push(ro);
            }

            let mut o = Json::obj();
            o.set("ok", Json::Bool(true));
            o.set("time", Json::s(crate::core::store::now_string()));
            o.set("grades", grades);
            o.set("recent_events", Json::Arr(recent_events));
            o.set("records", Json::Arr(records));
            o.set(
                "totals",
                {
                    let mut t = Json::obj();
                    t.set("events", Json::Int(d.events.len() as i64));
                    t.set("students", Json::Int(d.students.len() as i64));
                    t.set("results", Json::Int(d.results.len() as i64));
                    t.set(
                        "computed",
                        Json::Int(d.results.iter().filter(|r| r.points.is_some()).count() as i64),
                    );
                    t
                },
            );
            o
        })
    }
}

/// 流式连接处理：把 mpsc 通道里的消息转成 SSE 写出去。
///
/// 循环里做两件事：
/// 1. `recv_timeout(HEARTBEAT)` 等消息 —— 等到了就写事件，超时了就写心跳；
/// 2. 检查 `is_closed()` —— 客户端断开时立刻退出，释放线程。
fn pump(stream: &mut crate::core::http::StreamWriter, rx: Receiver<Broadcast>) {
    loop {
        match rx.recv_timeout(HEARTBEAT) {
            Ok(msg) => {
                if !stream.send(msg.event, &msg.data) {
                    break; // 写失败 = 客户端已走
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                // 心跳：注释行不触发客户端事件，只保活
                if !stream.comment("keep-alive") {
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if stream.is_closed() {
            break;
        }
    }
}

/// 把 `EventKind` 映射为推送用的增量事件名与提示文案。
///
/// 返回 `(&'static str, String)`：事件名必须是 `'static`（广播结构体里
/// 这样存），因此这里返回字面量而非 `String`。
fn update_payload(kind: EventKind, payload: &Json) -> Option<(&'static str, String)> {
    let (what, hint) = match kind {
        EventKind::ResultsComputed => ("result", "名次与赋分已更新"),
        EventKind::ResultsSaved => ("result", "有成绩被录入或修改"),
        EventKind::ResultsCleared => ("result", "有项目成绩被清空"),
        EventKind::EventDeleted => ("event", "有项目被删除"),
        EventKind::EventCreated => ("event", "有新项目建立"),
        EventKind::EventUpdated => ("event", "有项目信息被修改"),
        EventKind::StudentCreated | EventKind::StudentDeleted => ("roster", "有学生名单变动"),
        EventKind::Registered | EventKind::Unregistered => ("roster", "有报名变动"),
        EventKind::SettingsChanged => ("settings", "计分设置已调整，榜单需重算"),
        EventKind::DataImported => ("data", "数据被全量导入"),
        _ => return None,
    };
    let mut o = Json::obj();
    o.set("kind", Json::s(what));
    o.set("hint", Json::s(hint));
    o.set("time", Json::s(crate::core::store::now_string()));
    if let Some(eid) = payload.get("event_id").and_then(|v| v.as_i64()) {
        o.set("event_id", Json::Int(eid));
    }
    Some((what, o.to_string()))
}

impl Extension for LiveBoard {
    fn name(&self) -> &'static str {
        "live-board"
    }

    fn description(&self) -> &'static str {
        "实时赛况大屏：SSE 推送年级总分与最新名次，支持多屏同时观看"
    }

    fn routes(&self) -> Vec<ExtRoute> {
        vec![
            ExtRoute {
                method: "GET",
                path: "/api/ext/live-board/stream",
                handler: Arc::new(|ctx: &CoreContext, _req: &Request| {
                    // 取出本扩展实例（路由闭包无法直接捕获 self，故从核心的
                    // 扩展列表按名取回 —— 这是本扩展唯一需要的小技巧）。
                    let lb = find_live_board(ctx)
                        .ok_or_else(|| "实时大屏扩展未就绪".to_string())?;

                    // 并发上限：避免反复刷新把线程耗光
                    {
                        let vs = lb
                            .viewers
                            .lock()
                            .map_err(|_| "大屏连接表不可用".to_string())?;
                        if vs.len() >= MAX_VIEWERS {
                            if let Ok(mut r) = lb.rejected.lock() {
                                *r += 1;
                            }
                            return Err(format!(
                                "同时观看大屏已达上限 {} 个，请稍后重试",
                                MAX_VIEWERS
                            ));
                        }
                    }

                    // 立刻准备首帧快照：后打开的大屏无需等下一次成绩变动
                    let snap = lb.snapshot(ctx);
                    let (tx, rx) = channel::<Broadcast>();
                    let _ = tx.send(Broadcast {
                        event: "snapshot",
                        data: snap.to_string(),
                    });

                    {
                        let mut vs = lb
                            .viewers
                            .lock()
                            .map_err(|_| "大屏连接表不可用".to_string())?;
                        vs.push(Viewer {
                            tx,
                            since: Instant::now(),
                        });
                        if let Ok(mut a) = lb.accepted.lock() {
                            *a += 1;
                        }
                    }
                    crate::log_info!(
                        "live-board",
                        "大屏已接入（当前在线 {} 个）",
                        lb.viewers.lock().map(|v| v.len()).unwrap_or(0)
                    );

                    // 返回 SSE 流式响应；producer 在独立连接线程内运行
                    Ok(Response::sse(move |w| pump(w, rx)))
                }),
            },
            ExtRoute {
                method: "GET",
                path: "/api/ext/live-board/snapshot",
                handler: Arc::new(|ctx: &CoreContext, _req: &Request| {
                    let lb = find_live_board(ctx)
                        .ok_or_else(|| "实时大屏扩展未就绪".to_string())?;
                    Ok(Response::json(&lb.snapshot(ctx)))
                }),
            },
            ExtRoute {
                method: "GET",
                path: "/api/ext/live-board/status",
                handler: Arc::new(|ctx: &CoreContext, _req: &Request| {
                    let lb = find_live_board(ctx)
                        .ok_or_else(|| "实时大屏扩展未就绪".to_string())?;
                    let online = lb.viewers.lock().map(|v| v.len()).unwrap_or(0);
                    // 每个大屏的连接时长（秒）：用于判断是不是"卡住的僵尸连接"
                    let viewer_ages: Vec<i64> = lb
                        .viewers
                        .lock()
                        .map(|v| {
                            v.iter()
                                .map(|x| x.since.elapsed().as_secs() as i64)
                                .collect()
                        })
                        .unwrap_or_default();
                    let mut o = Json::obj();
                    o.set("ok", Json::Bool(true));
                    o.set("online_viewers", Json::Int(online as i64));
                    o.set("max_viewers", Json::Int(MAX_VIEWERS as i64));
                    o.set(
                        "viewer_ages_secs",
                        Json::Arr(viewer_ages.into_iter().map(Json::Int).collect()),
                    );
                    o.set(
                        "pushed_messages",
                        Json::Int(lb.pushed.lock().map(|v| *v as i64).unwrap_or(0)),
                    );
                    o.set(
                        "accepted_connections",
                        Json::Int(lb.accepted.lock().map(|v| *v as i64).unwrap_or(0)),
                    );
                    o.set(
                        "rejected_connections",
                        Json::Int(lb.rejected.lock().map(|v| *v as i64).unwrap_or(0)),
                    );
                    o.set("heartbeat_secs", Json::Int(HEARTBEAT.as_secs() as i64));
                    o.set(
                        "endpoints",
                        {
                            let mut e = Json::obj();
                            e.set("stream", Json::s("/api/ext/live-board/stream"));
                            e.set("snapshot", Json::s("/api/ext/live-board/snapshot"));
                            e
                        },
                    );
                    Ok(Response::json(&o))
                }),
            },
        ]
    }

    fn on_event(&self, ctx: &CoreContext, event: &CoreEvent) {
        // 事件来自核心，事件驱动推送 —— 不轮询、不空转
        if let Some((event_name, data)) = update_payload(event.kind, &event.payload) {
            // 增量通知之后紧跟一份新快照，保证大屏"提示"与"数据"同步到达。
            // 若只发增量，前端还得再发一次请求（破坏 SSE 免轮询的初衷）。
            self.broadcast(event_name, data);
            let snap = self.snapshot(ctx);
            self.broadcast("snapshot", snap.to_string());
        }
    }
}

/// 从核心的扩展列表中按名取回本扩展实例。
///
/// 说明：`Extension::routes()` 的 handler 是 `Arc<dyn Fn>`，签名里只有
/// `&CoreContext`，无法捕获 `self`。这是核心刻意设计的契约（扩展 handler
/// 不持有扩展自身引用）。三种解法：
/// 1. 把状态放进核心（污染核心，违反规则 5）；
/// 2. 用 thread_local（多线程模型下不成立）；
/// 3. **从核心反查扩展列表**（本方案，零污染且天然与核心共享同一实例）。
fn find_live_board(_ctx: &CoreContext) -> Option<Arc<LiveBoard>> {
    SLOT.get().cloned()
}

/// 扩展自身的全局槽位（在装配阶段由 `install()` 填入）。
///
/// # 为什么用静态槽位，而不是从核心扩展列表里 downcast
///
/// 核心的 `Extension` trait **刻意没有** `as_any()`：给 trait 加方法
/// 虽然向后兼容，但属于对公开契约的扩张。本扩展改用自持静态槽位，
/// 从而做到**核心零改动**接入 —— 这正是规则 5「新增能力优先做成扩展」
/// 想要的效果。
///
/// 线程安全：`OnceLock` 只允许写入一次，读取无锁；装配发生在
/// `init_extensions()` 之前，因此路由 handler 首次被调用时必然已就绪。
static SLOT: std::sync::OnceLock<Arc<LiveBoard>> = std::sync::OnceLock::new();

/// 由 `extensions/mod.rs` 在装配时调用：把实例放进槽位。
///
/// 装配顺序保证在 `init_extensions()` 之前完成，因此路由 handler
/// 首次被调用时槽位一定已就绪。
pub fn install(inst: Arc<LiveBoard>) {
    let _ = SLOT.set(inst);
}

// ---------------------------------------------------------------------------
// 单元测试（v1.5 新增）
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::sync::LockExt;

    #[test]
    fn name_and_routes_follow_prefix_contract() {
        let lb = LiveBoard::new();
        assert_eq!(lb.name(), "live-board");
        let rs = lb.routes();
        assert_eq!(rs.len(), 3);
        for r in &rs {
            assert!(
                r.path.starts_with("/api/ext/live-board/"),
                "路由 {} 必须以扩展前缀开头",
                r.path
            );
        }
    }

    #[test]
    fn broadcast_reaches_all_viewers() {
        let lb = LiveBoard::new();
        let (t1, r1) = channel();
        let (t2, r2) = channel();
        lb.viewers.lock_recover().push(Viewer {
            tx: t1,
            since: Instant::now(),
        });
        lb.viewers.lock_recover().push(Viewer {
            tx: t2,
            since: Instant::now(),
        });
        lb.broadcast("update", "{\"a\":1}".into());
        for r in [r1, r2] {
            let m = r.recv_timeout(Duration::from_millis(200)).unwrap();
            assert_eq!(m.event, "update");
            assert_eq!(m.data, "{\"a\":1}");
        }
    }

    #[test]
    fn dropped_viewer_is_pruned_lazily() {
        let lb = LiveBoard::new();
        let (t1, r1) = channel();
        drop(r1); // 模拟客户端断开
        let (t2, r2) = channel();
        lb.viewers.lock_recover().push(Viewer {
            tx: t1,
            since: Instant::now(),
        });
        lb.viewers.lock_recover().push(Viewer {
            tx: t2,
            since: Instant::now(),
        });
        lb.broadcast("update", "{}".into());
        assert_eq!(lb.viewers.lock_recover().len(), 1, "已断开者应被清理");
        assert!(r2.recv_timeout(Duration::from_millis(200)).is_ok());
    }

    #[test]
    fn update_payload_maps_core_events() {
        let p = Json::obj();
        let (name, data) = update_payload(EventKind::ResultsComputed, &p).unwrap();
        // 事件名即分类（result/event/roster/settings/data），便于前端按类分流
        assert_eq!(name, "result");
        assert!(data.contains("名次与赋分已更新"));

        // 与赛事无关的事件不应推送（如 CoreStarted）
        assert!(update_payload(EventKind::CoreStarted, &p).is_none());
    }

    #[test]
    fn update_payload_carries_event_id_when_present() {
        let mut p = Json::obj();
        p.set("event_id", Json::Int(7));
        let (_, data) = update_payload(EventKind::ResultsSaved, &p).unwrap();
        assert!(data.contains("\"event_id\":7"), "载荷应带 event_id：{}", data);
    }

    #[test]
    fn heartbeat_constants_are_sane() {
        // 心跳必须明显小于常见的 30~60 秒空闲回收阈值
        assert!(HEARTBEAT.as_secs() >= 5 && HEARTBEAT.as_secs() <= 25);
        // 观看上限应是个合理的小数字，避免线程耗尽
        assert!((8..=64).contains(&MAX_VIEWERS));
    }

    #[test]
    fn counters_start_at_zero() {
        let lb = LiveBoard::new();
        assert_eq!(*lb.pushed.lock_recover(), 0);
        assert_eq!(*lb.accepted.lock_recover(), 0);
        assert_eq!(*lb.rejected.lock_recover(), 0);
        assert!(lb.viewers.lock_recover().is_empty());
    }
}
