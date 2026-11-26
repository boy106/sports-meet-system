//! 请求限流（v1.6.0）。
//!
//! 目标场景是**校园单机工具**，不是公网服务：并发极低（<10 人同时操作），
//! 因此不需要 Redis / 令牌桶集群那一套。这里要防的是三件具体的事：
//!
//!   1. **误用打爆服务**——前端某个 bug 导致 1 秒内循环请求几百次；
//!   2. **口令暴力尝试**——对着 `/api/auth/token` 或 `/api/dev/unlock` 刷字典；
//!   3. **意外洪泛**——脚本/爬虫误扫端口。
//!
//! 设计取舍：
//!   * **滑动窗口计数**，不是令牌桶。窗口内计数简单、可解释、易测。
//!   * **分桶限流**：写操作配额远低于读操作配额。读多写少是真实使用分布，
//!     一刀切会让"刷新列表"被误伤。
//!   * **敏感路径单独计数**：登录/解锁类接口配额最严（防字典）。
//!   * **只针对非本机请求生效**？——不。本机也会被前端 bug 打爆，
//!     所以本机同样限流，只是本机配额**放宽**（老师自己用不该被限）。
//!   * 全内存、标准库实现，**零新增依赖**（规则 10）。
//!
//! 诚实声明：这是**服务自身保护**，不是**抗攻击**。进程重启即清零，
//! 单机模型下也无法抵御分布式来源。够用，但不夸大。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// 限流档位。不同档位有独立的窗口与配额。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Bucket {
    /// 读操作（GET，以及只读 POST 白名单）
    Read,
    /// 写操作（POST/DELETE 业务写）
    Write,
    /// 敏感操作（换取令牌、开发者模式解锁）——配额最严
    Sensitive,
}

impl Bucket {
    /// 窗口长度。统一 10 秒，便于用户理解"十秒内最多几次"。
    fn window() -> Duration {
        Duration::from_secs(10)
    }

    /// 本机来源的配额（宽松）。
    fn quota_loopback(self) -> u32 {
        match self {
            Bucket::Read => 600,
            Bucket::Write => 200,
            Bucket::Sensitive => 30,
        }
    }

    /// 非本机来源的配额（严格）。
    ///
    /// 本工具默认只监听 127.0.0.1，非本机流量属"非预期"，
    /// 因此配额定得低——真出现说明有人把它暴露到了局域网，
    /// 限流同时也起到提醒作用（日志里有 WARN）。
    fn quota_remote(self) -> u32 {
        match self {
            Bucket::Read => 120,
            Bucket::Write => 40,
            Bucket::Sensitive => 5,
        }
    }

    fn quota(self, from_loopback: bool) -> u32 {
        if from_loopback {
            self.quota_loopback()
        } else {
            self.quota_remote()
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Bucket::Read => "read",
            Bucket::Write => "write",
            Bucket::Sensitive => "sensitive",
        }
    }
}

/// 限流判定结果。
pub struct Decision {
    pub allowed: bool,
    /// 本窗口内剩余次数（被拒时为 0）
    pub remaining: u32,
    /// 建议的退避秒数（仅被拒时有意义），用于 `Retry-After`
    pub retry_after: u64,
    /// 本窗口的配额上限
    pub limit: u32,
}

/// 单个来源的滑动窗口计数。
struct Entry {
    /// 窗口起点
    start: Instant,
    /// 窗口内已计次数
    count: u32,
    /// 最近一次触顶时间（用于统计"曾被限流"）
    last_limited: Option<Instant>,
}

/// 限流器：按 (来源, 档位) 计数。
pub struct RateLimiter {
    inner: Mutex<HashMap<(String, Bucket), Entry>>,
    /// 累计拒绝次数（诊断页展示）
    rejected: Mutex<u64>,
    /// 累计放行次数
    allowed: Mutex<u64>,
}

impl RateLimiter {
    pub fn new() -> Self {
        RateLimiter {
            inner: Mutex::new(HashMap::new()),
            rejected: Mutex::new(0),
            allowed: Mutex::new(0),
        }
    }

    /// 判定是否放行。**会就地计数**（即调用一次 = 消耗一次配额）。
    ///
    /// `key` 为来源标识。本机请求统一用 `"loopback"` 聚合 —— 否则
    /// 同机多个浏览器标签会各占一份配额，反而更容易被误限。
    pub fn check(&self, key: &str, bucket: Bucket, from_loopback: bool) -> Decision {
        let limit = bucket.quota(from_loopback);
        let window = Bucket::window();
        let now = Instant::now();

        let mut map = match self.inner.lock() {
            Ok(m) => m,
            // 锁中毒：宁可放行也不要因为限流器自身故障把服务卡死。
            Err(_) => {
                return Decision {
                    allowed: true,
                    remaining: limit,
                    retry_after: 0,
                    limit,
                }
            }
        };

        // 顺手做一次轻量清理：过期条目直接丢弃，避免 map 无限增长。
        // 用 retain 而非定时线程，省一个后台线程。
        map.retain(|_, e| now.duration_since(e.start) < window);

        let entry = map
            .entry((key.to_string(), bucket))
            .or_insert_with(|| Entry {
                start: now,
                count: 0,
                last_limited: None,
            });

        // 窗口过期则重置
        if now.duration_since(entry.start) >= window {
            entry.start = now;
            entry.count = 0;
        }

        if entry.count >= limit {
            entry.last_limited = Some(now);
            let elapsed = now.duration_since(entry.start);
            let retry_after = window.saturating_sub(elapsed).as_secs().max(1);
            drop(map);
            if let Ok(mut r) = self.rejected.lock() {
                *r += 1;
            }
            return Decision {
                allowed: false,
                remaining: 0,
                retry_after,
                limit,
            };
        }

        entry.count += 1;
        let remaining = limit - entry.count;
        drop(map);
        if let Ok(mut a) = self.allowed.lock() {
            *a += 1;
        }
        Decision {
            allowed: true,
            remaining,
            retry_after: 0,
            limit,
        }
    }

    /// 诊断统计：`(放行次数, 拒绝次数, 当前活跃来源数)`
    pub fn stats(&self) -> (u64, u64, usize) {
        let a = self.allowed.lock().map(|v| *v).unwrap_or(0);
        let r = self.rejected.lock().map(|v| *v).unwrap_or(0);
        let n = self.inner.lock().map(|m| m.len()).unwrap_or(0);
        (a, r, n)
    }

    /// 把本机来源归类为聚合键，非本机按 IP 分别计数。
    pub fn key_for(ip: &str, from_loopback: bool) -> String {
        if from_loopback {
            "loopback".to_string()
        } else {
            ip.to_string()
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        RateLimiter::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_within_quota_then_blocks() {
        let rl = RateLimiter::new();
        let limit = Bucket::Write.quota_loopback();
        // 配额内全部放行
        for i in 0..limit {
            let d = rl.check("loopback", Bucket::Write, true);
            assert!(d.allowed, "第 {} 次不该被限", i + 1);
            assert_eq!(d.remaining, limit - i - 1);
        }
        // 第 limit+1 次必须被拒
        let d = rl.check("loopback", Bucket::Write, true);
        assert!(!d.allowed);
        assert_eq!(d.remaining, 0);
        assert_eq!(d.limit, limit);
        assert!(d.retry_after >= 1, "应给出退避秒数");
    }

    #[test]
    fn remote_quota_is_stricter_than_loopback() {
        // 非本机配额必须严格小于本机，否则"暴露到局域网"就没有代价
        for b in [Bucket::Read, Bucket::Write, Bucket::Sensitive] {
            assert!(
                b.quota_remote() < b.quota_loopback(),
                "{:?} 的远端配额应小于本机",
                b
            );
        }
    }

    #[test]
    fn buckets_are_independent() {
        // 读配额耗尽不该影响写
        let rl = RateLimiter::new();
        for _ in 0..Bucket::Read.quota_loopback() {
            rl.check("loopback", Bucket::Read, true);
        }
        assert!(!rl.check("loopback", Bucket::Read, true).allowed);
        assert!(rl.check("loopback", Bucket::Write, true).allowed);
        assert!(rl.check("loopback", Bucket::Sensitive, true).allowed);
    }

    #[test]
    fn different_sources_are_independent() {
        let rl = RateLimiter::new();
        for _ in 0..Bucket::Write.quota_remote() {
            rl.check("10.0.0.9", Bucket::Write, false);
        }
        // 这个来源被限，不代表另一个来源被限
        assert!(!rl.check("10.0.0.9", Bucket::Write, false).allowed);
        assert!(rl.check("10.0.0.10", Bucket::Write, false).allowed);
    }

    #[test]
    fn stats_track_allow_and_reject() {
        let rl = RateLimiter::new();
        rl.check("loopback", Bucket::Sensitive, true);
        assert_eq!(rl.stats().0, 1, "放行计数");
        // 打满敏感配额
        for _ in 0..Bucket::Sensitive.quota_loopback() {
            rl.check("loopback", Bucket::Sensitive, true);
        }
        let (_, rej, _) = rl.stats();
        assert!(rej >= 1, "拒绝计数应 >= 1，实际 {}", rej);
    }

    #[test]
    fn key_aggregates_loopback() {
        assert_eq!(RateLimiter::key_for("127.0.0.1", true), "loopback");
        assert_eq!(RateLimiter::key_for("192.168.1.5", false), "192.168.1.5");
    }
}
