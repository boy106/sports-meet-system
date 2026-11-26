//! 示例扩展三：自动备份。
//!
//! 演示「初始化 + 事件钩子」：核心启动时做一次快照备份；每次成绩
//! 计算后（数据发生有意义变化）再做一次，超过保留数自动清理。

use crate::core::ext::{CoreContext, CoreEvent, EventKind, Extension};
use crate::{log_debug, log_info, log_warn};
use std::path::PathBuf;

/// 数据文件尚未存在时的提示（首次启动，正常现象，用 DEBUG 级别）。
fn log_debug_placeholder(label: &str) {
    log_debug!(
        "ext.auto-backup",
        "跳过快照（{}）：数据文件尚未生成，属首次启动的正常情况",
        label
    );
}

pub struct AutoBackup {
    dir: PathBuf,
}

impl AutoBackup {
    pub fn new(data_dir: PathBuf) -> Self {
        AutoBackup { dir: data_dir }
    }

    fn snapshot(&self, label: &str) {
        let core_backup_dir = self.dir.join("backups");
        let _ = std::fs::create_dir_all(&core_backup_dir);
        let src = self.dir.join("sports_meet.json");
        let stamp = crate::core::store::now_string()
            .replace(['-', ' ', ':'], "");
        let dest = core_backup_dir.join(format!("backup_{}_{}.json", stamp, label));
        if let Ok(data) = std::fs::read(&src) {
            match std::fs::write(&dest, data) {
                Ok(()) => log_info!(
                    "ext.auto-backup",
                    "自动快照完成（{}）：{}",
                    label,
                    dest.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
                ),
                Err(e) => log_warn!("ext.auto-backup", "自动快照写入失败（{}）：{}", label, e),
            }
        } else {
            log_debug_placeholder(label);
        }
        Self::prune(&core_backup_dir);
    }

    /// 保留最近 20 个备份（核心自身保留 10 个，扩展额外保留 10 个的容量）。
    fn prune(dir: &std::path::Path) {
        let mut files: Vec<_> = std::fs::read_dir(dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| {
                        let n = e.file_name().to_string_lossy().into_owned();
                        n.starts_with("backup_") && n.ends_with(".json")
                    })
                    .map(|e| e.path())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        files.sort();
        let keep = 20;
        if files.len() > keep {
            for p in files.drain(0..files.len() - keep) {
                let _ = std::fs::remove_file(p);
            }
        }
    }
}

impl Extension for AutoBackup {
    fn name(&self) -> &'static str {
        "auto-backup"
    }

    fn description(&self) -> &'static str {
        "自动备份：核心启动时与每次成绩计算后自动快照 data/sports_meet.json"
    }

    fn on_init(&self, _ctx: &CoreContext) -> Result<(), String> {
        self.snapshot("startup");
        Ok(())
    }

    fn on_event(&self, _ctx: &CoreContext, event: &CoreEvent) {
        if event.kind == EventKind::ResultsComputed {
            self.snapshot("computed");
        }
    }
}
