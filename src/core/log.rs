//! 日志模块（核心）：分级日志 + 控制台输出 + 按日滚动落盘。
//!
//! 设计目标（v1.2 新增）：
//!   1. **零依赖**：只用标准库，不引入 `log` / `env_logger`；
//!   2. **分级**：DEBUG < INFO < WARN < ERROR，运行时可通过 `--log-level` 调整；
//!   3. **落盘**：写入 `<data_dir>/logs/sports-meet-YYYY-MM-DD.log`，按日自动滚动；
//!   4. **全局单例**：`init()` 一次，其他模块用 `log_info!` 等宏直接调用；
//!   5. **线程安全**：内部 `Mutex`，多连接线程可并发写。
//!
//! 使用方式：
//! ```ignore
//! log::init(data_dir, LogLevel::Info);
//! log_info!("核心启动，端口 {}", 8765);
//! log_error!("写入失败：{}", err);
//! ```

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use crate::core::store::now_string;

/// 日志级别。数值越大越严重，低于当前阈值的不输出。
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug = 0,
    Info = 1,
    Warn = 2,
    Error = 3,
}

impl LogLevel {
    /// 从字符串解析（大小写不敏感），无法识别时返回 None。
    pub fn parse(s: &str) -> Option<LogLevel> {
        match s.trim().to_ascii_uppercase().as_str() {
            "DEBUG" | "DBG" => Some(LogLevel::Debug),
            "INFO" | "INF" => Some(LogLevel::Info),
            "WARN" | "WARNING" => Some(LogLevel::Warn),
            "ERROR" | "ERR" => Some(LogLevel::Error),
            _ => None,
        }
    }

    /// 短标签，用于日志行。
    pub fn tag(&self) -> &'static str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }
}

/// 日志器全局状态：级别 + 输出目录 + 当前打开的日志文件句柄。
struct Logger {
    level: LogLevel,
    dir: PathBuf,
    /// 当前日志文件句柄；仅在首次写盘时懒打开。
    file: Option<File>,
    /// 当前句柄对应的日期（YYYY-MM-DD），跨天时重新打开。
    file_date: String,
    /// 是否同时输出到控制台（默认 true）。
    console: bool,
}

impl Logger {
    fn new(dir: PathBuf, level: LogLevel) -> Logger {
        Logger {
            level,
            dir,
            file: None,
            file_date: String::new(),
            console: true,
        }
    }

    /// 取当天日期（本地时间 UTC+8），格式 YYYY-MM-DD。
    fn today(&self) -> String {
        // now_string() 返回 "YYYY-MM-DD HH:MM:SS"，取前 10 位即日期。
        let s = now_string();
        s.chars().take(10).collect()
    }

    /// 确保句柄指向当天日志文件；跨天或首次调用时打开。
    /// 返回 Err 时表示落盘不可用（调用方决定是否降级为仅控制台）。
    fn ensure_file(&mut self) -> Result<&mut File, String> {
        let today = self.today();
        let need_open = self.file.is_none() || self.file_date != today;
        if need_open {
            fs::create_dir_all(&self.dir)
                .map_err(|e| format!("创建日志目录失败：{}", e))?;
            let path = self.dir.join(format!("sports-meet-{}.log", today));
            let f = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(|e| format!("打开日志文件失败：{}", e))?;
            self.file = Some(f);
            self.file_date = today;
            self.prune_old_logs();
        }
        self.file
            .as_mut()
            .ok_or_else(|| "日志文件句柄不可用".to_string())
    }

    /// 保留最近 N 天的日志，其余删除（默认 30 天）。
    /// 失败静默忽略——清理日志不该影响主流程。
    fn prune_old_logs(&self) {
        const KEEP_DAYS: usize = 30;
        let mut logs: Vec<PathBuf> = match fs::read_dir(&self.dir) {
            Ok(rd) => rd
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.file_name()
                        .and_then(|n| n.to_str())
                        .map(|n| n.starts_with("sports-meet-") && n.ends_with(".log"))
                        .unwrap_or(false)
                })
                .collect(),
            Err(_) => return,
        };
        if logs.len() <= KEEP_DAYS {
            return;
        }
        // 文件名含日期，字典序即时间序，升序后删掉最旧的
        logs.sort();
        let remove_count = logs.len() - KEEP_DAYS;
        for p in logs.into_iter().take(remove_count) {
            let _ = fs::remove_file(p);
        }
    }

    /// 写一行日志。写盘失败时回退到控制台并提示一次。
    fn write_line(&mut self, level: LogLevel, target: &str, msg: &str) {
        if level < self.level {
            return;
        }
        let line = format!(
            "[{}] [{:<5}] [{}] {}",
            now_string(),
            level.tag(),
            target,
            msg
        );
        if self.console {
            // ERROR/WARN 走 stderr，便于重定向时区分
            if level >= LogLevel::Warn {
                eprintln!("{}", line);
            } else {
                println!("{}", line);
            }
        }
        if let Ok(f) = self.ensure_file() {
            let _ = writeln!(f, "{}", line);
            let _ = f.flush();
        }
    }
}

/// 全局日志器。
static LOGGER: OnceLock<Mutex<Logger>> = OnceLock::new();

/// 初始化日志系统。重复调用会覆盖上一次的配置（幂等）。
///
/// * `data_dir` — 数据目录，日志写入其下的 `logs/` 子目录
/// * `level`    — 输出阈值
pub fn init(data_dir: &Path, level: LogLevel) {
    let dir = data_dir.join("logs");
    let logger = Logger::new(dir, level);
    match LOGGER.get() {
        Some(l) => {
            // 已初始化：仅更新级别与目录，保留句柄有效性由 ensure_file 处理
            if let Ok(mut g) = l.lock() {
                g.level = level;
                g.dir = logger.dir;
            }
        }
        None => {
            let _ = LOGGER.set(Mutex::new(logger));
        }
    }
}

/// 运行时调整级别（供 /api/ext/core/logs 或命令行热切换使用）。
/// v1.4：当前主链路未调用，保留为运行时调试接口。
#[allow(dead_code)]
pub fn set_level(level: LogLevel) {
    if let Some(l) = LOGGER.get() {
        if let Ok(mut g) = l.lock() {
            g.level = level;
        }
    }
}

/// 读取当前级别。
pub fn current_level() -> Option<LogLevel> {
    LOGGER.get().and_then(|l| l.lock().ok().map(|g| g.level))
}

/// 关闭/开启控制台输出（测试时可关掉以减少噪音）。
/// v1.4：当前主链路未调用，保留为运行时调试接口。
#[allow(dead_code)]
pub fn set_console(enabled: bool) {
    if let Some(l) = LOGGER.get() {
        if let Ok(mut g) = l.lock() {
            g.console = enabled;
        }
    }
}

/// 记录一条日志。这是唯一入口，宏最终都调用它。
///
/// 未初始化时**静默降级**为仅打印到控制台——日志系统本身绝不能让主流程失败。
pub fn log(level: LogLevel, target: &str, msg: &str) {
    match LOGGER.get() {
        Some(l) => {
            if let Ok(mut g) = l.lock() {
                g.write_line(level, target, msg);
            }
        }
        None => {
            // 降级：未初始化也输出，避免"日志消失"造成排查困难
            let line = format!(
                "[{}] [{:<5}] [{}] {}",
                now_string(),
                level.tag(),
                target,
                msg
            );
            if level >= LogLevel::Warn {
                eprintln!("{}", line);
            } else {
                println!("{}", line);
            }
        }
    }
}

/// 读取最近 n 行日志（供诊断接口使用）。文件不存在时返回空串。
pub fn tail(data_dir: &Path, n: usize) -> String {
    let dir = data_dir.join("logs");
    let today = now_string().chars().take(10).collect::<String>();
    let path = dir.join(format!("sports-meet-{}.log", today));
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(_) => return String::new(),
    };
    let lines: Vec<&str> = text.lines().collect();
    let start = lines.len().saturating_sub(n);
    lines[start..].join("\n")
}

// ---------------------------------------------------------------------------
// 宏：调用处只写 log_info!("...")，无需重复写 target 与级别
// ---------------------------------------------------------------------------

/// 调试级日志。
#[macro_export]
macro_rules! log_debug {
    ($target:expr, $($arg:tt)*) => {
        $crate::core::log::log($crate::core::log::LogLevel::Debug, $target, &format!($($arg)*))
    };
}

/// 信息级日志。
#[macro_export]
macro_rules! log_info {
    ($target:expr, $($arg:tt)*) => {
        $crate::core::log::log($crate::core::log::LogLevel::Info, $target, &format!($($arg)*))
    };
}

/// 警告级日志。
#[macro_export]
macro_rules! log_warn {
    ($target:expr, $($arg:tt)*) => {
        $crate::core::log::log($crate::core::log::LogLevel::Warn, $target, &format!($($arg)*))
    };
}

/// 错误级日志。
#[macro_export]
macro_rules! log_error {
    ($target:expr, $($arg:tt)*) => {
        $crate::core::log::log($crate::core::log::LogLevel::Error, $target, &format!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_parse() {
        assert_eq!(LogLevel::parse("info"), Some(LogLevel::Info));
        assert_eq!(LogLevel::parse("WARN"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::parse("Error"), Some(LogLevel::Error));
        assert_eq!(LogLevel::parse("debug"), Some(LogLevel::Debug));
        assert_eq!(LogLevel::parse("nonsense"), None);
    }

    #[test]
    fn level_ordering() {
        assert!(LogLevel::Debug < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Error);
    }

    #[test]
    fn level_tags() {
        assert_eq!(LogLevel::Error.tag(), "ERROR");
        assert_eq!(LogLevel::Debug.tag(), "DEBUG");
    }
}
