//! 扩展集合：在 main.rs 中按需注册到核心。
//!
//! 新增扩展的步骤：
//!   1. 本目录新建 `my_ext.rs`，实现 `Extension` trait；
//!   2. 在 `mod.rs` 声明模块；
//!   3. 在 `main.rs` 的 `load_extensions()` 中加入实例。

pub mod auto_backup;
pub mod live_board;
pub mod participation;
pub mod records_feed;

use crate::core::ext::Extension;
use std::path::PathBuf;
use std::sync::Arc;

/// 组装本发行版自带的全部扩展。
///
/// v1.5：新增 `live-board`（实时赛况大屏，SSE 推送）。
/// 需要自持状态的扩展在装配阶段调用各自的 `install()` 把实例放入
/// 静态槽位 —— 因为 `Extension::routes()` 的 handler 无法捕获 `self`
/// （核心契约如此，见 `core/ext.rs` 的注释）。
pub fn load_extensions(data_dir: PathBuf) -> Vec<Arc<dyn Extension>> {
    let live = Arc::new(live_board::LiveBoard::new());
    // 装配期登记，保证 init_extensions() 之前就绪
    live_board::install(Arc::clone(&live));
    vec![
        Arc::new(records_feed::RecordsFeed::new(data_dir.clone())),
        Arc::new(participation::Participation),
        Arc::new(auto_backup::AutoBackup::new(data_dir)),
        live,
    ]
}
