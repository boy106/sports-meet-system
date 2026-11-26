//! 核心模块入口：JSON、HTTP、存储、模型、计分、领域 API、扩展总线、日志、
//! 审计哈希链、统一错误类型、密钥与开发者模式、数据保险库。
//!
//! 模块分层（依赖单向，无环）：
//! ```text
//!   log  ← 所有模块可用（仅依赖 store 的时间工具）
//!   json → 无依赖（自实现，v1.4 加嵌套深度上限）
//!   error → json（统一业务错误类型，v1.4 从 api.rs 抽出）
//!   envelope → error / json（v1.6.0 新增：统一响应信封 + 稳定错误码）
//!   ratelimit → 无依赖（v1.6.0 新增：滑动窗口限流，仅用标准库）
//!   audit → json / log / store（v1.5 新增：哈希链审计，仅依赖时间工具）
//!   license → 无依赖（v1.5.1 新增：慢哈希密钥 + 开发者模式状态机）
//!   aim/hwid → 无依赖（v1.8.0 新增：机器指纹）
//!   aim/channel → 无依赖（v1.8.0 新增：加密信道 + 防重放）
//!   aim/client → hwid / channel / json / log（v1.8.0：授权管理器 + 离线降级）
//!   vault → license / json / log（v1.5.1 新增：流加密保险库）
//!   http → api / error / json
//!   store → json / model / scoring
//!   model → json
//!   scoring → json / model / store
//!   ext  → http / json
//!   api  → 以上全部
//!   export → json / model / store / api
//!   smart → json / model / scoring / store（v1.5 新增：智能建议）
//! ```
//!
//! 注意：`log` 被 `store` 使用，而 `log` 又用 `store::now_string()` 取时间。
//! 为避免循环，`log` 对 `store` 的使用是**函数级**调用（Rust 允许同 crate
//! 内模块互相引用函数，不构成编译期循环依赖），且 `store` 对 `log` 的调用
//! （宏）是**运行时**展开，不产生类型级依赖。`audit` 同理。
//!
//! `license` 刻意**不依赖任何其他核心模块**（连 `log` 都不用），因此可被
//! `http` / `api` / `vault` 任意引用而不引入环。

// v1.8.0 新增：服务端授权（机器指纹 + 加密信道 + 离线降级）。
// 与 license 模块职责不同：license 管"开发者模式"，aim 管"正式授权"。
// 子模块均不依赖其他核心模块（client 仅用 json/log），不引入依赖环。
pub mod aim;
// v1.9.8：内置 AI 助手配置（Agnes），只依赖 json。
pub mod ai;
pub mod api;
pub mod audit;
// v1.9.3 报名表文件解析（xlsx/csv → 导入 payload），只依赖 json/model/api。
pub mod baoming;
// v1.6.1 新增：数据目录独占锁，防"两个进程同写一份数据"静默覆盖
pub mod dirlock;
pub mod envelope;
pub mod error;
pub mod ext;
pub mod export;
pub mod http;
pub mod json;
pub mod license;
pub mod log;
pub mod model;
pub mod ratelimit;
pub mod scoring;
// v1.9.8 成绩公布表解析（每项目一个 sheet → 批量成绩），只依赖 baoming/api。
pub mod scoresheet;
// v1.9.10 AI 表格文本导入（Markdown / 制表符 / CSV → 中性行），只依赖 scoresheet/api。
pub mod ai_table;
// v1.9.10 团体总分表（项目 × 班级矩阵 → xlsx），依赖 model/store。
pub mod summary;
pub mod smart;
pub mod store;
// v1.6.1 新增：Mutex 毒化自恢复。只依赖 std，可被任意模块引用而不引入环。
pub mod sync;
pub mod schedule;
pub mod schedule_api;
pub mod vault;
