//! 扩展机制（核心模块）。
//!
//! 架构：核心（Core）持有全部领域 API 与事件总线；扩展实现 `Extension`
//! trait，可以：
//!   1. 注册自己的 HTTP 路由（**必须**挂到 `/api/ext/<name>/...` 前缀下）；
//!   2. 订阅核心事件（成绩计算、删除、报名等），调用核心 API 做联动；
//!   3. 在核心启动时初始化（on_init）。
//!
//! 核心对扩展一无所知；扩展之间互不可见。main.rs 负责组装。
//!
//! # 扩展开发契约（v1.2 强化）
//!
//! 注册扩展时核心会执行三项校验，**任一不通过即拒绝注册并记录 ERROR 日志**：
//!
//! | 校验 | 规则 |
//! | ---- | ---- |
//! | 名称合法性 | 非空，且仅含 `[A-Za-z0-9_-]` |
//! | 名称唯一性 | 不得与已注册扩展重名 |
//! | 路由前缀 | 每条路由的 `path` 必须以 `/api/ext/<name>/` 开头 |
//!
//! 运行期提供两项隔离保证：
//!
//! 1. **事件隔离**：`on_event` 内发生 panic 会被 `catch_unwind` 捕获，
//!    仅计入该扩展的 `event_errors`，核心与其他扩展继续运行；
//! 2. **路由隔离**：路由 handler panic 返回 500 JSON，不会导致连接挂起。
//!
//! 扩展健康状况可通过 `GET /api/ext/extensions` 查询（含初始化状态、
//! 路由数、事件数、错误数、健康判定）。
//!
//! # 开发步骤
//!
//! 1. `src/extensions/my_ext.rs` 新建文件，实现 `Extension` trait；
//! 2. 在 `src/extensions/mod.rs` 中 `pub mod my_ext;` 并加入 `load_extensions()`；
//! 3. 完成——核心无需任何改动。

use crate::core::http::{Request, Response};
use crate::core::json::Json;
use std::sync::Arc;

/// 核心暴露给扩展的上下文：即 Core 本身（全部领域 API 为 pub）。
pub type CoreContext = crate::core::api::Core;

/// 核心事件（载荷为 JSON，字段随事件类型而定）。
#[derive(Debug, Clone)]
pub struct CoreEvent {
    pub kind: EventKind,
    pub payload: Json,
    pub time: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    CoreStarted,
    EventCreated,
    EventUpdated,
    EventDeleted,
    StudentCreated,
    StudentDeleted,
    Registered,
    Unregistered,
    ResultsSaved,
    ResultsComputed,
    ResultsCleared,
    SettingsChanged,
    DataImported,
}

impl EventKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            EventKind::CoreStarted => "core_started",
            EventKind::EventCreated => "event_created",
            EventKind::EventUpdated => "event_updated",
            EventKind::EventDeleted => "event_deleted",
            EventKind::StudentCreated => "student_created",
            EventKind::StudentDeleted => "student_deleted",
            EventKind::Registered => "registered",
            EventKind::Unregistered => "unregistered",
            EventKind::ResultsSaved => "results_saved",
            EventKind::ResultsComputed => "results_computed",
            EventKind::ResultsCleared => "results_cleared",
            EventKind::SettingsChanged => "settings_changed",
            EventKind::DataImported => "data_imported",
        }
    }
}

/// 扩展注册的一条路由。
///
/// **契约**：`path` 必须以 `/api/ext/<扩展名>/` 开头（或恰好等于
/// `/api/ext/<扩展名>`）。核心在注册与挂载两处双重校验，不合规的路由
/// 会被拒绝/跳过并记录日志。
/// 扩展 handler 签名（v1.4：提取别名，消除类型复杂度告警）。
pub type ExtHandler =
    dyn Fn(&CoreContext, &Request) -> Result<Response, String> + Send + Sync;

#[derive(Clone)]
pub struct ExtRoute {
    pub method: &'static str,
    /// 形如 "/api/ext/<ext_name>/stats" 的完整路径（支持 {param} 段）
    pub path: &'static str,
    pub handler: Arc<ExtHandler>,
}

/// 扩展 trait：实现它即可接入核心。
///
/// # 实现须知
///
/// * `name()` 返回值必须**唯一**且仅含 `[A-Za-z0-9_-]`，否则注册被拒；
/// * `routes()` 返回的每条路由必须位于 `/api/ext/<name>/` 前缀下；
/// * `on_event()` 中请勿执行耗时阻塞操作——它运行在请求线程上，
///   且持有扩展列表快照；如需慢操作请自行起线程；
/// * `on_event()` 与路由 handler 中的 panic 会被隔离，但**不建议**依赖
///   该机制——捕获到 panic 说明扩展自身有缺陷，应及时修复。
pub trait Extension: Send + Sync {
    /// 扩展唯一名（用于路由前缀与展示）。必须符合命名规范。
    fn name(&self) -> &'static str;
    /// 扩展说明（展示于启动日志与健康面板）。
    fn description(&self) -> &'static str {
        ""
    }
    /// 核心启动时调用一次。返回 Err 会记录到健康状态但不阻断核心。
    fn on_init(&self, _ctx: &CoreContext) -> Result<(), String> {
        Ok(())
    }
    /// 扩展注册的 HTTP 路由（路径须符合 `/api/ext/<name>/` 前缀约定）。
    fn routes(&self) -> Vec<ExtRoute> {
        Vec::new()
    }
    /// 订阅核心事件。异常会被隔离，不传播到核心。
    fn on_event(&self, _ctx: &CoreContext, _event: &CoreEvent) {}
}
