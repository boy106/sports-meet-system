//! 同步原语辅助（v1.6.1 新增）。
//!
//! # 为什么需要这个模块
//!
//! 本项目有 37 处 `Mutex::lock().unwrap()`。绝大多数在"拿锁 → 改内存 → 放锁"
//! 的短临界区里，正常路径不会 panic。但 `.unwrap()` 的语义是：
//!
//! > **一旦有任何一个线程在持锁期间 panic，这把锁就被"毒化"（poisoned），
//! > 之后所有线程的 `lock()` 都返回 `Err`，于是每一次 `unwrap()` 都 panic。**
//!
//! 在本项目里这会造成一个**不可恢复的全服务故障**：
//! `store.data` 是业务数据的唯一入口，任何 handler 只要在持锁时触发一次
//! 越界/断言（例如某个字段解析异常），此后**每一个请求**都会在
//! `self.store.data.lock().unwrap()` 处再次 panic → 全部 500。
//! 服务看起来"突然全坏了"，重启才能恢复，而日志里只有一串重复的
//! "poisoned lock" —— 排查成本极高。
//!
//! # 设计选择：自恢复，而不是中止
//!
//! 另一种常见做法是"毒化即快速失败"（继续 `unwrap`，让程序崩掉）。
//! 这在金融/事务型系统里是对的——宁可停机也不能读到不一致状态。
//!
//! 但本项目是**单机房、单进程、面向一台机器前的老师**的记分工具：
//!   - 数据在内存里是一份**完整的快照**，不是"改了一半的中间态"
//!     （临界区只做整字段赋值与整表增删，不做跨字段的半程提交）；
//!   - "继续服务"的价值远大于"严格一致性保证"——运动会现场，
//!     服务挂在"某个老师手滑触发了一次越界"上，比读到一次可能陈旧的
//!     列表严重得多；
//!   - 且写入路径是**整文件原子写**（见 `store::save`），
//!     内存里的短暂不一致不会直接落盘成损坏文件。
//!
//! 因此选择 `unwrap_or_else(|e| e.into_inner())`：**取回内层数据继续用**，
//! 同时用 `log_warn!` 留下一条痕迹——毒化绝不被静默吞掉。
//!
//! # 用法
//!
//! ```ignore
//! use crate::core::sync::LockExt;
//! let d = self.store.data.lock_recover();        // 替代 .lock().unwrap()
//! let mut d = self.store.data.lock_recover();
//! ```

use std::sync::{Mutex, MutexGuard};

/// 为 `Mutex<T>` 提供"毒化自恢复"的加锁方法。
pub trait LockExt<T> {
    /// 加锁；若锁已被毒化，记录告警后取回内层数据继续。
    fn lock_recover(&self) -> MutexGuard<'_, T>;

    /// 同 [`LockExt::lock_recover`]，但允许调用方自定义告警里的场景名。
    fn lock_recover_as(&self, what: &str) -> MutexGuard<'_, T>;
}

impl<T> LockExt<T> for Mutex<T> {
    fn lock_recover(&self) -> MutexGuard<'_, T> {
        self.lock_recover_as("critical section")
    }

    fn lock_recover_as(&self, what: &str) -> MutexGuard<'_, T> {
        match self.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                // 关键：**不能静默**。毒化意味着此前有线程在持锁时 panic，
                // 这条日志是唯一的线索（panic 本身可能已被 catch 或发生在
                // 别的线程里），必须留下。
                crate::log_warn!(
                    "sync",
                    "检测到 mutex 已被毒化（{}）：此前有线程在持锁期间 panic。\
                     已取回内层数据继续服务，请检查该 panic 的根因。",
                    what
                );
                poisoned.into_inner()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    /// 正常路径：能拿到锁。
    #[test]
    fn lock_recover_works_on_healthy_mutex() {
        let m = Mutex::new(41);
        *m.lock_recover() += 1;
        assert_eq!(*m.lock_recover(), 42);
    }

    /// **核心行为**：毒化后仍能取回数据，且数据是 panicky 线程留下的一致值。
    ///
    /// 这是本次修复的直接目标——旧代码在这里会 `unwrap()` panic，
    /// 于是"一次越界"演变成"服务永久不可用"。
    #[test]
    fn lock_recover_survives_poisoned_mutex() {
        let m = Arc::new(Mutex::new(vec![1, 2, 3]));

        // 制造毒化：在持锁状态下 panic
        let m2 = Arc::clone(&m);
        let _ = std::thread::spawn(move || {
            let _g = m2.lock().unwrap();
            panic!("模拟持锁期间 panic");
        })
        .join();

        // 锁此时必然已被毒化
        assert!(m.lock().is_err(), "前置条件：锁应已被毒化");

        // 旧写法会在这里 panic；新写法应正常返回且能看到 panic 前的数据
        let g = m.lock_recover();
        assert_eq!(*g, vec![1, 2, 3], "应能取回 panic 前的完整数据");

        // 且可以继续写入——锁被"治好"了，后续调用不再走告警分支
        drop(g);
        m.lock_recover().push(4);
        assert_eq!(*m.lock_recover(), vec![1, 2, 3, 4]);
    }

    /// 毒化恢复后，`lock()` 依然会报毒（我们只是绕过它，没有伪造成功）。
    ///
    /// 这条锁定"自恢复是**每次调用都判**，而不是把锁标记改成健康的"——
    /// 避免有人误解为"毒化被清除了"。
    #[test]
    fn poison_state_is_reported_every_time() {
        let m = Arc::new(Mutex::new(0));
        let m2 = Arc::clone(&m);
        let _ = std::thread::spawn(move || {
            let _g = m2.lock().unwrap();
            panic!("毒化");
        })
        .join();

        assert!(m.lock().is_err());
        drop(m.lock_recover());
        assert!(m.lock().is_err(), "毒化标记不会被 lock_recover 抹掉");
    }

    /// `lock_recover_as` 的可读形式与默认形式等价。
    #[test]
    fn lock_recover_as_is_equivalent() {
        let m = Mutex::new(String::from("x"));
        m.lock_recover_as("unit-test").push('y');
        assert_eq!(*m.lock_recover(), "xy");
    }
}
