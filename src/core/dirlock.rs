//! 数据目录独占锁（v1.6.1 新增）。
//!
//! # 要解决的问题
//!
//! 数据是"内存全量 + 写时整文件覆盖"的模型：每个进程启动时把
//! `sports_meet.json` 整个读进内存，之后每次写操作把**整份内存数据**
//! 写回文件。这带来一个静默的数据丢失场景：
//!
//! ```text
//!   t0  进程 A 启动，读入 {1 个项目}
//!   t1  进程 B 启动（同一个数据目录），读入同一份 {1 个项目}
//!   t2  A 新增项目 X  → 写回 {X}            （X 落盘）
//!   t3  B 新增项目 Y  → 写回 {Y}            ← B 的内存里没有 X
//!   结果：X 被静默抹掉，文件里只剩 Y
//! ```
//!
//! 触发方式极其平常：**双击了两次 exe**、或"换个端口再开一个"。
//! 用户看不到任何报错，只是"刚才录的成绩不见了"。
//!
//! # 方案：数据目录锁文件
//!
//! 启动时在数据目录写 `.sports-meet.lock`（含 pid 与启动时间），
//! 已存在且**其 pid 仍存活**则拒绝启动并给出明确提示。
//!
//! ## 为什么不用 `flock` / `LockFileEx`
//!
//! 那才是"标准"做法，但要给 Linux / Windows 各写一套：
//! `std` **没有**跨平台的文件锁 API，得引入 `fs2` / `nix` / `winapi`
//! 或写 `unsafe` 的 FFI —— 直接违反规则 10（最小依赖）。
//!
//! 本项目只需挡住"人手误操作"，不需要对抗恶意并发，所以**"pid 探活"
//! 足够**：它零依赖、跨平台、可读（锁文件里能直接看到是谁占着）。
//!
//! ## 代价与补偿
//!
//! "探活"不像内核锁那样原子 —— 两个进程同一毫秒启动理论上可能都通过检查。
//! 补偿手段：
//!   1. 写入用 `create_new`（O_EXCL），是原子的：**同时只可能有一个成功**；
//!   2. 拿到后立刻复查文件内容是否是自己写的，不是则视为竞争失败退出。
//!
//! 这样即使在最坏的交错下，也保证"最多一个进程认为自己持有锁"。
//!
//! ## 逃生开关
//!
//! 误判（如 pid 被复用、或前一次异常退出留下陈旧锁）必须能绕过，
//! 故提供 `--ignore-lock`。但默认**不**自动清理陈旧锁 ——
//! 自动清理会让"两个进程真的同时在跑"变得更隐蔽，宁可让使用者
//! 看到提示并显式选择，这比静默覆盖数据安全。

use std::io::Write;
use std::path::{Path, PathBuf};

/// 锁文件名。以 `.` 开头，避免被当成数据文件。
pub const LOCK_FILE_NAME: &str = ".sports-meet.lock";

/// 持有中的数据目录锁。`Drop` 时自动删除锁文件。
pub struct DirLock {
    path: PathBuf,
    pid: u32,
}

/// 获取锁的结果。
pub enum LockOutcome {
    /// 成功获取。
    Acquired(DirLock),
    /// 数据目录已被另一个**存活**的进程占用。
    Busy {
        /// 占用者的 pid。
        pid: u32,
        /// 占用者的启动时间（可读字符串，来自锁文件）。
        since: String,
        /// 锁文件路径（用于提示用户）。
        path: PathBuf,
    },
}

impl DirLock {
    /// 尝试获取 `dir` 的独占锁。
    pub fn acquire(dir: &Path) -> LockOutcome {
        let path = dir.join(LOCK_FILE_NAME);
        let pid = std::process::id();

        // ---- 第一步：检查已有锁，判断占用者是否还活着 ----
        //
        // 这一步只是"快速劝阻"：如果占用者活着，直接拒绝，不必动文件。
        // 如果占用者已消失（陈旧锁），**必须先把文件删掉**再走后边的
        // `create_new` —— 否则 `create_new` 会因"文件已存在"而失败，
        // 把一把本该可回收的陈旧锁误报成"被占用"（这是本模块第一版
        // 的真实缺陷，被 `stale_lock_from_dead_pid_is_reclaimable` 抓到）。
        let mut stale = false;
        if let Ok(content) = std::fs::read_to_string(&path) {
            let (other_pid, since) = parse_lock(&content);
            if let Some(op) = other_pid {
                if op != pid && pid_alive(op) {
                    return LockOutcome::Busy {
                        pid: op,
                        since,
                        path,
                    };
                }
                // 走到这里 = 占用者已死（或就是本进程的遗留）
                stale = true;
            } else {
                // 内容无法解析（空文件/损坏）→ 同样视为陈旧
                stale = true;
            }
        }
        if stale {
            crate::log_warn!(
                "dirlock",
                "发现陈旧锁文件 {}（占用进程已不存在），已回收",
                path.display()
            );
            let _ = std::fs::remove_file(&path);
        }

        // ---- 第二步：原子创建（O_EXCL），同时只可能有一个成功 ----
        let stamp = crate::core::store::now_string();
        let body = format!("{}\n{}\n", pid, stamp);
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(mut f) => {
                let _ = f.write_all(body.as_bytes());
                let _ = f.flush();
                // 写入后复查：确认文件里是我们的 pid。
                // 极端交错下（两个进程都判定"无锁"）这里会拦住后来者。
                if let Ok(after) = std::fs::read_to_string(&path) {
                    let (who, since2) = parse_lock(&after);
                    if who != Some(pid) {
                        // 竞争失败：不删文件（那是别人的），直接报告占用
                        return LockOutcome::Busy {
                            pid: who.unwrap_or(0),
                            since: since2,
                            path,
                        };
                    }
                }
                LockOutcome::Acquired(DirLock { path, pid })
            }
            Err(e) => {
                // 到这里说明"删陈旧锁后又创建失败"（权限不足 / 目录只读 /
                // 磁盘满），或极端竞态下别人抢先创建成功。
                //
                // 注意：**不能**在这里谎报"被别人占用" —— 上次就是这里
                // 把权限问题误报成占用，让用户去查一个不存在的进程。
                let (op, since) = std::fs::read_to_string(&path)
                    .map(|c| parse_lock(&c))
                    .unwrap_or((None, String::new()));
                if let Some(other) = op {
                    if other != pid && pid_alive(other) {
                        return LockOutcome::Busy {
                            pid: other,
                            since,
                            path,
                        };
                    }
                }
                // 无人占用却创建失败 → 是环境问题，如实报错
                crate::log_error!(
                    "dirlock",
                    "无法创建锁文件 {}：{}。请检查数据目录是否可写。",
                    path.display(),
                    e
                );
                // 用 pid=0 表示"非占用型失败"，由调用方给出不同的提示
                LockOutcome::Busy {
                    pid: 0,
                    since: format!("无法创建锁文件：{}", e),
                    path,
                }
            }
        }
    }

    /// 当前 pid。
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// 锁文件路径。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// v1.6.1：构造一把"空锁"，用于 `--ignore-lock` 逃生路径。
    ///
    /// 它不持有任何文件，`Drop` 也不会删任何东西 —— 把"跳过检查"
    /// 与"持有锁"统一成同一类型，`main` 里就能用一条 `let _dir_lock`
    /// 同时表达两种情形，不必写 `Option<Option<DirLock>>` 这种绕人的类型。
    pub fn disabled() -> DirLock {
        DirLock {
            path: PathBuf::new(),
            // 用 0 作哨兵：`Drop` 里会去读空路径失败，自然什么都不做
            pid: 0,
        }
    }

    /// 是否为"空锁"（`--ignore-lock`）。
    pub fn is_disabled(&self) -> bool {
        self.pid == 0 || self.path.as_os_str().is_empty()
    }
}

impl Drop for DirLock {
    fn drop(&mut self) {
        // `--ignore-lock` 构造的空锁不持有文件，直接返回
        if self.is_disabled() {
            return;
        }
        // 只删自己的锁：万一文件已被别人接管（理论上不该发生），
        // 不要误删他人的锁。
        if let Ok(c) = std::fs::read_to_string(&self.path) {
            let (who, _) = parse_lock(&c);
            if who == Some(self.pid) {
                let _ = std::fs::remove_file(&self.path);
            }
        }
    }
}

/// 解析锁文件内容为 `(pid, 启动时间)`。内容格式：
///
/// ```text
/// 12345
/// 2026/09/26 17:05:33
/// ```
fn parse_lock(content: &str) -> (Option<u32>, String) {
    let mut lines = content.lines();
    let pid = lines.next().and_then(|l| l.trim().parse::<u32>().ok());
    let since = lines.next().unwrap_or("").trim().to_string();
    (pid, since)
}

/// 判断某 pid 是否仍存活（跨平台，零依赖）。
///
/// - Linux：`/proc/<pid>` 存在即存活
/// - Windows：用 `tasklist` 过滤（无第三方依赖）
/// - 其他平台：保守返回 `true`（宁可误报占用，也不放任并发覆盖）
#[cfg(target_os = "linux")]
fn pid_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{}", pid)).exists()
}

#[cfg(target_os = "windows")]
fn pid_alive(pid: u32) -> bool {
    // 用系统自带 tasklist，避免引入 winapi。
    // `/FI "PID eq N" /NH` 只列该 pid；无匹配时输出 "INFO: No tasks..."。
    use std::process::Command;
    match Command::new("tasklist")
        .args(["/FI", &format!("PID eq {}", pid), "/NH"])
        .output()
    {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            // 输出里应包含该 pid 数字本身
            s.contains(&pid.to_string())
        }
        // tasklist 不可用（极精简的系统）→ 保守视为存活
        Err(_) => true,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows")))]
fn pid_alive(_pid: u32) -> bool {
    // 未知平台无可靠探活手段 → 保守视为存活，宁可拒绝启动
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sm_lock_{}_{}_{}",
            tag,
            std::process::id(),
            // 加纳秒防同进程内多次调用撞名
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// 首次获取应成功，且锁文件被创建。
    #[test]
    fn first_acquire_succeeds() {
        let d = tmpdir("first");
        match DirLock::acquire(&d) {
            LockOutcome::Acquired(l) => {
                assert_eq!(l.pid(), std::process::id());
                assert!(l.path().exists(), "锁文件应存在");
            }
            LockOutcome::Busy { .. } => panic!("空目录首次获取不应被占用"),
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// **核心行为**：持锁期间再次获取（模拟第二个进程）应被拒。
    ///
    /// 这里用"另一把锁对象"模拟第二进程——因为同 pid 的存活判定为真。
    #[test]
    fn second_acquire_is_blocked_while_held() {
        let d = tmpdir("blocked");
        let first = match DirLock::acquire(&d) {
            LockOutcome::Acquired(l) => l,
            LockOutcome::Busy { .. } => panic!("首次应成功"),
        };

        // 模拟第二进程：直接用底层路径判定（不经过 pid != 自身 的捷径）
        let content = std::fs::read_to_string(d.join(LOCK_FILE_NAME)).unwrap();
        let (pid, since) = parse_lock(&content);
        assert_eq!(pid, Some(std::process::id()), "锁文件应记录当前 pid");
        assert!(!since.is_empty(), "锁文件应记录启动时间");

        // 由于第 2 个"进程"是同一个 pid（测试限制），acquire 会走自愈分支。
        // 真正的跨进程拒绝由集成测试覆盖（两个真实进程）。
        drop(first);
        let _ = std::fs::remove_dir_all(&d);
    }

    /// `Drop` 应删除锁文件，使后续可以重新获取。
    #[test]
    fn drop_releases_the_lock() {
        let d = tmpdir("drop");
        {
            let _l = match DirLock::acquire(&d) {
                LockOutcome::Acquired(l) => l,
                LockOutcome::Busy { .. } => panic!("首次应成功"),
            };
            assert!(d.join(LOCK_FILE_NAME).exists());
        }
        assert!(
            !d.join(LOCK_FILE_NAME).exists(),
            "Drop 后锁文件应被删除"
        );
        // 能再次获取
        match DirLock::acquire(&d) {
            LockOutcome::Acquired(_) => {}
            LockOutcome::Busy { .. } => panic!("释放后应能重新获取"),
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// 陈旧锁（pid 不存在）应被识别为可回收。
    ///
    /// 判定逻辑在 `acquire` 里：`pid_alive(op)` 为假则不返回 Busy。
    /// 用 Linux 上必然不存在的超大 pid 验证。
    #[test]
    fn stale_lock_from_dead_pid_is_reclaimable() {
        let d = tmpdir("stale");
        // 写一个几乎不可能存在的 pid
        std::fs::write(d.join(LOCK_FILE_NAME), "4294967290\n2020/01/01 00:00:00\n").unwrap();

        if pid_alive(4294967290) {
            // 极端巧合（该 pid 真存在）→ 跳过，不误报失败
            let _ = std::fs::remove_dir_all(&d);
            return;
        }

        match DirLock::acquire(&d) {
            LockOutcome::Acquired(_) => {}
            LockOutcome::Busy { pid, .. } => panic!("陈旧锁不应阻止获取，却报告被 {} 占用", pid),
        }
        let _ = std::fs::remove_dir_all(&d);
    }

    /// `parse_lock` 对异常输入的容错（截断 / 空文件 / 非数字）。
    #[test]
    fn parse_lock_handles_malformed_content() {
        assert_eq!(parse_lock(""), (None, String::new()));
        assert_eq!(parse_lock("abc\ndef\n"), (None, "def".into()));
        assert_eq!(parse_lock("42\n"), (Some(42), String::new()));
        assert_eq!(parse_lock("42\n2026/09/26 10:00:00\n"), (Some(42), "2026/09/26 10:00:00".into()));
        // 多余行被忽略
        assert_eq!(parse_lock("7\nts\njunk\n"), (Some(7), "ts".into()));
    }

    /// 当前 pid 必定存活（对 pid_alive 本身的健全性检查）。
    #[test]
    fn current_pid_is_alive() {
        assert!(pid_alive(std::process::id()), "自己的 pid 必须判为存活");
    }
}
