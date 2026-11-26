//! 数据存储（核心模块）：全量状态驻内存，变更后原子落盘 JSON。
//! 撤销机制与 Python 版对齐：记录最近一次破坏性操作的 action + payload。

use crate::core::json::Json;
use crate::core::model::{Event, Registration, Result as DomainResult, Settings, Student};
use crate::core::schedule::{default_sessions, default_venues, Session, Slot, Venue};
use crate::core::scoring;
use crate::core::sync::LockExt;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

#[derive(Clone)]
pub struct Data {
    pub settings: Settings,
    pub events: Vec<Event>,
    pub students: Vec<Student>,
    pub registrations: Vec<Registration>,
    pub results: Vec<DomainResult>,
    pub next_event_id: i64,
    pub next_student_id: i64,
    pub next_reg_id: i64,
    pub next_result_id: i64,
    /// 可撤销操作栈（v1.2：由单条改为多步）。
    ///
    /// 语义约定：**栈顶为最近一次操作**（即 `undo.last()`）。
    /// 上限由 `Core::undo_keep` 控制，超出时从栈底（最旧）丢弃。
    /// 持久化时写入 JSON 的 `undo_stack` 字段；为兼容 v1.1 数据，
    /// 读取时也会识别旧的单条 `undo` 字段并转换为栈。
    pub undo_stack: Vec<UndoEntry>,
    // ---- v1.7：赛程编排（秩序册）----
    /// 场地清单（跑道/田赛区）。缺失时回退默认（规则 20）。
    pub venues: Vec<Venue>,
    /// 竞赛单元（按天、按上午/下午划分）。驱动默认生成的是 schedule_days。
    pub sessions: Vec<Session>,
    /// 已编排的赛程时段。空 = 还没排。
    pub slots: Vec<Slot>,
    /// 赛程天数（1 起），驱动默认单元生成；旧数据无此字段时回退 2。
    pub schedule_days: i64,
}

#[derive(Debug, Clone)]
pub struct UndoEntry {
    pub time: String,
    pub action: String,
    pub payload: Json,
}

impl Default for Data {
    fn default() -> Self {
        Data {
            settings: Settings::default(),
            events: Vec::new(),
            students: Vec::new(),
            registrations: Vec::new(),
            results: Vec::new(),
            next_event_id: 1,
            next_student_id: 1,
            next_reg_id: 1,
            next_result_id: 1,
            undo_stack: Vec::new(),
            // v1.7 默认：两块场地（1 跑道 + 1 田赛区）+ 2 天 × 2 单元。
            // 用默认而非空，保证老数据读到后赛程功能立即可用（规则 20）。
            venues: default_venues(),
            sessions: default_sessions(2),
            slots: Vec::new(),
            schedule_days: 2,
        }
    }
}

// ---------------------------------------------------------------------------
// 序列化 / 反序列化
// ---------------------------------------------------------------------------

impl Data {
    pub fn to_json(&self) -> Json {
        use crate::core::json::Json;
        let mut o = Json::obj();
        o.set("version", Json::Int(2));
        o.set("settings", self.settings.to_json());
        o.set(
            "events",
            Json::arr(self.events.iter().map(event_to_json)),
        );
        o.set(
            "students",
            Json::arr(self.students.iter().map(student_to_json)),
        );
        o.set(
            "registrations",
            Json::arr(self.registrations.iter().map(reg_to_json)),
        );
        o.set("results", Json::arr(self.results.iter().map(result_to_json)));
        o.set("next_event_id", Json::Int(self.next_event_id));
        o.set("next_student_id", Json::Int(self.next_student_id));
        o.set("next_reg_id", Json::Int(self.next_reg_id));
        o.set("next_result_id", Json::Int(self.next_result_id));
        // v1.2：撤销栈按时间序（最旧 -> 最新）落盘，读取时还原为同样顺序，
        // 栈顶（最新）始终是 undo_stack.last()。
        o.set(
            "undo_stack",
            Json::arr(self.undo_stack.iter().map(undo_to_json)),
        );
        // v1.7：赛程编排
        o.set("venues", crate::core::schedule::venues_to_json(&self.venues));
        o.set(
            "sessions",
            crate::core::schedule::sessions_to_json(&self.sessions),
        );
        o.set("slots", crate::core::schedule::slots_to_json(&self.slots));
        o.set("schedule_days", Json::Int(self.schedule_days));
        o
    }

    pub fn from_json(j: &Json) -> Option<Data> {
        let st = Settings::from_json(j.get("settings"))?;
        let mut d = Data {
            settings: st,
            ..Data::default()
        };
        if let Some(Json::Arr(arr)) = j.get("events") {
            for e in arr {
                if let Some(ev) = event_from_json(e) {
                    d.events.push(ev);
                }
            }
        }
        if let Some(Json::Arr(arr)) = j.get("students") {
            for e in arr {
                if let Some(s) = student_from_json(e) {
                    d.students.push(s);
                }
            }
        }
        if let Some(Json::Arr(arr)) = j.get("registrations") {
            for e in arr {
                d.registrations.push(Registration {
                    id: e.get_i64("id").unwrap_or(0),
                    event_id: e.get_i64("event_id").unwrap_or(0),
                    student_id: e.get_i64("student_id").unwrap_or(0),
                    note: e.get_string("note"),
                });
            }
        }
        if let Some(Json::Arr(arr)) = j.get("results") {
            for e in arr {
                d.results.push(DomainResult {
                    id: e.get_i64("id").unwrap_or(0),
                    event_id: e.get_i64("event_id").unwrap_or(0),
                    student_id: e.get("student_id").and_then(|v| v.as_i64()),
                    grade: e.get_string("grade"),
                    class_no: e.get("class_no").and_then(|v| v.as_i64()),
                    score_text: e.get_string("score_text"),
                    score_value: e.get("score_value").and_then(|v| v.as_f64()),
                    rank: e.get("rank").and_then(|v| v.as_i64()),
                    points: e.get("points").and_then(|v| v.as_f64()),
                    broke_record: e
                        .get("broke_record")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(0)
                        != 0,
                });
            }
        }
        d.next_event_id = j.get_i64("next_event_id").unwrap_or(1);
        d.next_student_id = j.get_i64("next_student_id").unwrap_or(1);
        d.next_reg_id = j.get_i64("next_reg_id").unwrap_or(1);
        d.next_result_id = j.get_i64("next_result_id").unwrap_or(1);

        // v1.7：赛程编排。缺失 → 回退默认（规则 20：非法/缺失输入修复到合法值）。
        // 旧数据（v1.6 及以前）无这些字段，读到的就是默认的两场地 + 2 天单元，
        // 用户无需任何迁移即可用赛程功能。
        d.schedule_days = j.get_i64("schedule_days").unwrap_or(2).max(1);
        d.venues = crate::core::schedule::venues_from_json(j.get("venues"));
        d.sessions = crate::core::schedule::sessions_from_json(j.get("sessions"), d.schedule_days);
        d.slots = crate::core::schedule::slots_from_json(j.get("slots"));

        // v1.2：优先读多步栈；若不存在则回退兼容 v1.1 的单条 undo 字段。
        if let Some(Json::Arr(arr)) = j.get("undo_stack") {
            for e in arr {
                if let Some(u) = undo_from_json(e) {
                    d.undo_stack.push(u);
                }
            }
        } else if let Some(u) = j.get("undo").and_then(undo_from_json) {
            // 旧格式：单条 undo -> 转成只有一个元素的栈
            d.undo_stack.push(u);
        }
        Some(d)
    }
}

/// 撤销条目序列化（v1.2）。
pub fn undo_to_json(u: &UndoEntry) -> Json {
    let mut o = Json::obj();
    o.set("time", Json::s(u.time.clone()));
    o.set("action", Json::s(u.action.clone()));
    o.set("payload", u.payload.clone());
    o
}

/// 撤销条目反序列化（v1.2）；缺少 action 视为无效条目。
pub fn undo_from_json(j: &Json) -> Option<UndoEntry> {
    let action = j.get_str("action")?.to_string();
    Some(UndoEntry {
        time: j.get_string("time"),
        action,
        payload: j.get("payload").cloned().unwrap_or_else(Json::obj),
    })
}

pub fn event_to_json(ev: &Event) -> Json {
    let mut o = Json::obj();
    o.set("id", Json::Int(ev.id));
    o.set("name", Json::s(ev.name.clone()));
    o.set("category", Json::s(ev.category.clone()));
    o.set("gender", Json::s(ev.gender.clone()));
    o.set("grade", Json::s(ev.grade.clone()));
    o.set("is_team", Json::Bool(ev.is_team));
    o.set("unit", Json::s(ev.unit.clone()));
    o.set(
        "record",
        ev.record.map(Json::Num).unwrap_or(Json::Null),
    );
    o.set(
        "record_text",
        match ev.record {
            Some(v) => Json::s(scoring::format_score(v, &ev.unit)),
            None => Json::Null,
        },
    );
    o
}

pub fn event_from_json(j: &Json) -> Option<Event> {
    Some(Event {
        id: j.get_i64("id")?,
        name: j.get_str("name")?.to_string(),
        category: j.get_str("category").unwrap_or("径赛").to_string(),
        gender: j.get_str("gender").unwrap_or("通用").to_string(),
        grade: j.get_str("grade").unwrap_or("全部").to_string(),
        is_team: j.get("is_team").and_then(|v| v.as_bool()).unwrap_or(false),
        unit: j.get_str("unit").unwrap_or("米").to_string(),
        record: j.get("record").and_then(|v| v.as_f64()),
    })
}

pub fn student_to_json(s: &Student) -> Json {
    let mut o = Json::obj();
    o.set("id", Json::Int(s.id));
    o.set("grade", Json::s(s.grade.clone()));
    o.set("class_no", Json::Int(s.class_no));
    o.set("name", Json::s(s.name.clone()));
    o.set("gender", Json::s(s.gender.clone()));
    o
}

pub fn student_from_json(j: &Json) -> Option<Student> {
    Some(Student {
        id: j.get_i64("id")?,
        grade: j.get_str("grade")?.to_string(),
        class_no: j.get_i64("class_no")?,
        name: j.get_str("name")?.to_string(),
        gender: j.get_str("gender").unwrap_or_default().to_string(),
    })
}

pub fn reg_to_json(r: &Registration) -> Json {
    let mut o = Json::obj();
    o.set("id", Json::Int(r.id));
    o.set("event_id", Json::Int(r.event_id));
    o.set("student_id", Json::Int(r.student_id));
    o.set("note", Json::s(r.note.clone()));
    o
}

pub fn result_to_json(r: &DomainResult) -> Json {
    let mut o = Json::obj();
    o.set("id", Json::Int(r.id));
    o.set("event_id", Json::Int(r.event_id));
    o.set(
        "student_id",
        r.student_id.map(Json::Int).unwrap_or(Json::Null),
    );
    o.set("grade", Json::s(r.grade.clone()));
    o.set(
        "class_no",
        r.class_no.map(Json::Int).unwrap_or(Json::Null),
    );
    o.set("score_text", Json::s(r.score_text.clone()));
    o.set(
        "score_value",
        r.score_value.map(Json::Num).unwrap_or(Json::Null),
    );
    o.set("rank", r.rank.map(Json::Int).unwrap_or(Json::Null));
    o.set("points", r.points.map(Json::Num).unwrap_or(Json::Null));
    o.set("broke_record", Json::Int(r.broke_record as i64));
    o
}

/// 全量导出（与 Python export_all 字段对齐，可直接互相导入）。
pub fn export_all_json(d: &Data) -> Json {
    let mut o = d.to_json();
    o.set("app", Json::s("同和中学校运会积分系统"));
    o.set("exported_at", Json::s(now_string()));
    o
}

// ---------------------------------------------------------------------------
// 持久化
// ---------------------------------------------------------------------------

pub struct Store {
    pub db_path: PathBuf,
    pub data: Mutex<Data>,
    /// v1.5.1：是否加密落盘（`--encrypt-data`）。默认 `false`。
    pub encrypt: bool,
    /// v1.5.1：加密种子（由 `--devkey` 派生）。`encrypt = true` 时必须为 Some。
    pub seed: Option<String>,
    /// v1.5.1：保险库**是否已实际武装**（密钥齐备并成功接管）。
    /// 与 `encrypt` 的区别：自动探测到密文时会同时置真；
    /// 而"用户没传 `--encrypt-data` 也没传 `--devkey`、只有个密文躺着"时
    /// 两者都是 `false`，诊断页据此提示"需要密钥"。
    pub vault_enabled: bool,
    /// v1.5.1：是否探测到了密文文件但缺少可用密钥。
    /// 用于诊断页给出准确提示（而不是笼统的"未启用"）。
    pub vault_detected: bool,
}

/// v1.5.1：数据文件名（明文与密文共用同一基名，仅后缀不同）。
pub const DATA_FILE_NAME: &str = "sports_meet.json";

impl Store {
    pub fn load(dir: &std::path::Path) -> Store {
        // v1.5.1：初始不带密钥、不加密；`Core::new` 之后由 `main.rs`
        // 调用 `store.enable_vault(...)` 注入。这样 `Store::load` 本身
        // 无需知道密钥从哪来，保持模块职责单一。
        Store {
            db_path: dir.join(DATA_FILE_NAME),
            data: Mutex::new(Data::default()),
            encrypt: false,
            seed: None,
            vault_enabled: false,
            vault_detected: false,
        }
    }

    /// v1.5.1：启用/关闭数据保险库。
    ///
    /// 返回 `true` 表示**确实启用了加密**（密钥齐备）。
    /// `encrypt = true` 但 `seed = None` 时拒绝启用并返回 `false` ——
    /// 宁可明文存储，也不能出现"以为加密了其实没加密"的假安全感。
    pub fn enable_vault(&mut self, encrypt: bool, seed: Option<String>) -> bool {
        if encrypt && seed.is_none() {
            crate::log_warn!("store", "未提供密钥，数据加密未启用（按明文存储）");
            self.encrypt = false;
            self.seed = None;
            self.vault_enabled = false;
            return false;
        }
        self.encrypt = encrypt;
        self.seed = seed;
        self.vault_enabled = encrypt;
        encrypt
    }

    /// 实际读取数据文件的字节（自动兼容明文 / 密文）。
    fn read_db_bytes(&self) -> Result<Vec<u8>, String> {
        crate::core::vault::read_auto(&self.db_path, self.seed.as_deref())
            .map_err(|e| e.to_string())
    }

    /// v1.5.1：从磁盘载入数据（带保险库支持）。
    pub fn load_from_disk(&mut self, dir: &std::path::Path) {
        let db_path = dir.join(DATA_FILE_NAME);
        let bytes = match self.read_db_bytes() {
            Ok(b) => b,
            Err(e) => {
                // 加密文件但没密钥 → 这是**必须让使用者看到**的错误，
                // 不能像"文件不存在"那样静默降级为空库（那会看着像丢数据）。
                if self.seed.is_some() {
                    // 有密钥却解不开：密钥错误或文件损坏，必须报错
                    crate::log_error!("store", "数据文件无法读取：{}", e);
                } else if std::path::Path::new(&db_path).exists()
                    || crate::core::vault::enc_path(&db_path).exists()
                {
                    // 文件确实存在但没有（或没有正确的）密钥。
                    // 这里**刻意统一用 INFO**：如果"密钥错误"报 ERROR 而"没给密钥"
                    // 报 INFO，就等于给爆破者开了一条反馈信道——他能分清
                    // "猜错了"和"没猜"。保持同样的措辞，让两种情形不可区分，
                    // 与 `License` 的静默降级原则一致（见 docs/12）。
                    if self.vault_detected {
                        crate::log_info!(
                            "store",
                            "检测到加密数据文件，但当前未提供可用密钥，暂以空数据启动；\
                             若需读取原有数据，请用 --devkey 提供正确密钥"
                        );
                    } else {
                        crate::log_error!(
                            "store",
                            "数据文件无法读取：{}（若该文件已加密，请用 --devkey 提供正确密钥）",
                            e
                        );
                    }
                } else {
                    crate::log_info!("store", "数据文件不存在，以空库启动");
                }
                let mut d = Data::default();
                seed_events(&mut d);
                *self.data.lock_recover() = d;
                self.db_path = db_path;
                return;
            }
        };
        let parsed = Json::parse(&String::from_utf8_lossy(&bytes))
            .ok()
            .and_then(|j| Data::from_json(&j));
        match parsed {
            Some(d) => {
                crate::log_info!(
                    "store",
                    "已加载数据：{}（项目 {} 个，学生 {} 人，成绩 {} 条）{}",
                    db_path.display(),
                    d.events.len(),
                    d.students.len(),
                    d.results.len(),
                    if self.encrypt { "（已解密）" } else { "" }
                );
                *self.data.lock_recover() = d;
            }
            None => {
                crate::log_error!(
                    "store",
                    "数据文件解析失败，已回退为空库并预置项目：{}",
                    db_path.display()
                );
                let mut d = Data::default();
                seed_events(&mut d);
                *self.data.lock_recover() = d;
            }
        }
        self.db_path = db_path;
    }

    /// 原子落盘：先写临时文件再改名。
    ///
    /// v1.2：写盘失败会记录 ERROR 日志（含路径与错误原因），
    /// 便于事后定位磁盘满 / 权限不足等问题。
    ///
    /// v1.5.1：`encrypt = true` 时改为「加密 → 写临时文件 → 改名」，
    /// 且**必须**走临时文件 + rename，否则写一半断电会留下半个密文块，
    /// 下次启动整份数据都读不出来（MAC 校验必然失败）。
    pub fn save(&self, d: &Data) -> Result<(), String> {
        if let Some(parent) = self.db_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let body = d.to_json().to_string_pretty();

        // 加密模式：目标文件名带 .smev 后缀（避免被误当明文打开）
        let (final_path, payload) = if self.encrypt {
            let seed = self
                .seed
                .as_deref()
                .ok_or_else(|| "加密已启用但密钥缺失".to_string())?;
            (
                crate::core::vault::enc_path(&self.db_path),
                crate::core::vault::seal(seed, body.as_bytes()),
            )
        } else {
            (self.db_path.clone(), body.clone().into_bytes())
        };

        let tmp = final_path.with_extension(if self.encrypt { "smev.tmp" } else { "tmp" });
        let write = || -> std::io::Result<()> {
            let mut f = fs::File::create(&tmp)?;
            f.write_all(&payload)?;
            f.flush()?;
            // fsync：确保 rename 之前数据真的落到盘上。
            // 少了这一步，断电后可能出现"文件名换了但内容是空的"
            // —— 比不加密还危险的数据损坏。
            f.sync_all()?;
            drop(f);
            fs::rename(&tmp, &final_path)?;
            Ok(())
        };
        match write() {
            Ok(()) => {
                // 加密成功后清理同名明文，防止旧明文残留形成"隐蔽后门"
                if self.encrypt {
                    let _ = fs::remove_file(&self.db_path);
                } else {
                    // 切回明文时清理旧密文
                    let _ = fs::remove_file(crate::core::vault::enc_path(&self.db_path));
                }
                Ok(())
            }
            Err(e) => {
                let msg = format!("写入数据失败：{}", e);
                crate::log_error!("store", "{}（目标 {}）", msg, final_path.display());
                Err(msg)
            }
        }
    }
}

/// 预置项目行（v1.4：提取别名消除类型复杂度告警）：
/// （名称, 类别, 性别组, 是否集体, 计分单位, 校纪录）
type EventPreset = (&'static str, &'static str, &'static str, bool, &'static str, Option<f64>);

/// 预置项目（v1.9.7：改用同和中学 2026 年校运会实际项目与校纪录）。
///
/// 数据来源：学校在 v1.9.6 数据文件里维护的 26 个项目。相对上一版
/// （21 个通用项目），这里按学校实际设置拆分了男女项目，并换上真实校纪录。
/// 四处原始数据疑点已按校方确认修正：
///   · 女子三级跳远：类别「径赛」→「田赛」（否则计分方向会反过来）
///   · 铅球：纪录 0.0 → 无纪录（0 会被当成"人人破纪录"）
///   · 女子跳远：性别「通用」→「女子」
///   · 摸高：单位「厘米」→「米」，纪录留空（原 55 是厘米口径）
pub fn seed_events(d: &mut Data) {
    let presets: Vec<EventPreset> = vec![
        ("男子100米", "径赛", "男子", false, "时间", Some(11.94)),
        ("女子100米", "径赛", "女子", false, "时间", Some(13.99)),
        ("男子400米", "径赛", "男子", false, "时间", Some(56.6)),
        ("女子400米", "径赛", "女子", false, "时间", Some(71.7)),
        ("男子1000米", "径赛", "男子", false, "时间", Some(176.0)),
        ("女子800米", "径赛", "女子", false, "时间", Some(172.94)),
        ("男子200米", "径赛", "男子", false, "时间", Some(25.49)),
        ("女子200米", "径赛", "女子", false, "时间", Some(30.53)),
        ("男子跳远", "田赛", "男子", false, "米", Some(5.6)),
        ("摸高", "田赛", "男子", false, "米", None),
        ("立定三级蛙跳", "田赛", "通用", false, "米", Some(7.0)),
        ("铅球", "田赛", "男子", false, "米", None),
        ("男子跳高", "田赛", "男子", false, "米", Some(1.61)),
        ("男子实心球", "田赛", "通用", false, "米", Some(14.72)),
        ("投掷沙包", "田赛", "通用", false, "米", Some(12.0)),
        ("引体向上", "田赛", "男子", false, "个", Some(18.0)),
        ("仰卧起坐", "田赛", "女子", false, "个", Some(40.0)),
        ("男子跳绳", "田赛", "男子", false, "个", Some(274.0)),
        ("女子跳绳", "田赛", "女子", false, "个", Some(250.0)),
        ("男子4×100米接力", "径赛", "男子", true, "时间", Some(50.68)),
        ("女子4×100米接力", "径赛", "女子", true, "时间", Some(59.94)),
        ("女子实心球", "田赛", "女子", false, "米", Some(9.6)),
        ("女子跳高", "田赛", "女子", false, "米", Some(1.3)),
        ("女子跳远", "田赛", "女子", false, "米", Some(4.32)),
        ("男子三级跳远", "田赛", "男子", false, "米", Some(12.2)),
        ("女子三级跳远", "田赛", "女子", false, "米", Some(8.89)),
    ];
    for (name, category, gender, is_team, unit, record) in presets {
        d.events.push(Event {
            id: d.next_event_id,
            name: name.into(),
            category: category.into(),
            gender: gender.into(),
            grade: "全部".into(),
            is_team,
            unit: unit.into(),
            record,
        });
        d.next_event_id += 1;
    }
}

// ---------------------------------------------------------------------------
// 时间工具（本地时间，UTC+8）
// ---------------------------------------------------------------------------

pub fn now_string() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
        + 8 * 3600;
    let days = secs / 86400;
    let rem = secs % 86400;
    let (y, m, d) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
        y,
        m,
        d,
        rem / 3600,
        (rem % 3600) / 60,
        rem % 60
    )
}

/// 天数转公历日期（Howard Hinnant 算法）。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// 对外暴露的公历换算（v1.5）：供 `api::unix_to_string` 统一时区口径使用，
/// 避免在别处重复实现一份日期算法而引入偏差。
pub fn civil_from_days_pub(days: i64) -> (i64, u32, u32) {
    civil_from_days(days)
}

// ---------------------------------------------------------------------------
// 单元测试（v1.6.1 新增）
// ---------------------------------------------------------------------------
//
// `store` 是所有业务数据的**唯一出入口**（加载 / 保存 / 原子写 / 加密切换），
// 此前 0 个单元测试，只靠集成测试间接覆盖 —— 而集成测试走的是"正常路径的
// 最终结果"，覆盖不到"文件损坏""空文件""切换加密方式"这类边界。
//
// 这些用例全部落在**可观测结果**上：磁盘上有什么文件、`Data` 字段是否一致、
// 函数返回 `Ok` 还是 `Err`。
#[cfg(test)]
mod tests {
    use super::*;

    /// 建一个带纳秒后缀的临时目录，避免同进程内多次调用互相干扰。
    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sm_store_{}_{}_{}",
            tag,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|x| x.as_nanos())
                .unwrap_or(0)
        ));
        let _ = fs::create_dir_all(&d);
        d
    }

    /// 新建的 Store 应指向 `<dir>/sports_meet.json`，且初始为空数据。
    #[test]
    fn load_initializes_paths_and_empty_data() {
        let d = tmpdir("init");
        let s = Store::load(&d);
        assert_eq!(s.db_path, d.join(DATA_FILE_NAME));
        assert!(!s.encrypt, "默认不加密");
        assert!(s.seed.is_none());
        assert!(!s.vault_enabled);
        // 数据为空（不含预置项目——预置由 api 层决定，store 不管策略）
        assert_eq!(s.data.lock_recover().events.len(), 0);
        let _ = fs::remove_dir_all(&d);
    }

    /// **往返一致性**：写入 → 落盘 → 重新加载，数据应完全相同。
    #[test]
    fn save_then_load_roundtrip_is_lossless() {
        let d = tmpdir("roundtrip");

        let mut data = Data::default();
        seed_events(&mut data);
        data.settings.class_count = 37;
        let n_events = data.events.len();
        let first_name = data.events[0].name.clone();
        let first_record = data.events[0].record;

        let s = Store::load(&d);
        s.save(&data).expect("保存应成功");

        // 校验确实生成了明文文件（未加密时不应该出现 .smev）
        assert!(s.db_path.exists(), "明文数据文件应存在");
        assert!(
            !crate::core::vault::enc_path(&s.db_path).exists(),
            "未加密时不应产生密文文件"
        );

        // 重新加载（新 Store 实例，完全从磁盘读）
        let mut s2 = Store::load(&d);
        s2.load_from_disk(&d);
        let back = s2.data.lock_recover();

        assert_eq!(back.events.len(), n_events, "项目数应一致");
        assert_eq!(back.events[0].name, first_name, "项目名应一致");
        assert_eq!(back.events[0].record, first_record, "校纪录应一致");
        assert_eq!(back.settings.class_count, 37, "设置应一致");

        let _ = fs::remove_dir_all(&d);
    }

    /// 保存应生成文件；且**不留临时文件**（原子写的 tmp 必须被 rename 掉）。
    ///
    /// 这条守护"原子写"契约：若 rename 失败却吞掉错误，会留下 .tmp，
    /// 下次启动读到旧数据而用户以为已保存。
    #[test]
    fn save_leaves_no_temp_file_behind() {
        let d = tmpdir("tmpclean");
        let mut data = Data::default();
        seed_events(&mut data);

        let s = Store::load(&d);
        s.save(&data).expect("保存应成功");

        let leftovers: Vec<String> = fs::read_dir(&d)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".tmp") || n.contains(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "不应残留临时文件，实际：{:?}", leftovers);

        let _ = fs::remove_dir_all(&d);
    }

    /// 数据文件**不存在**时，加载应回退到"预置项目库"而非 panic。
    ///
    /// 注意语义：store 的**回退**不是"空数据"，而是 `Data::default()` +
    /// `seed_events()` —— 即一套标准的预置项目集（数量随学校需求调整，
    /// 当前 21 个）。这是刻意设计：首次运行时老师打开就该看到可直接
    /// 使用的项目列表，而不是白板。
    ///
    /// （第一版测试写成"应为 0 条"是错的，被这条用例自己抓出来。）
    /// 断言**不写死数字**，而是与 `seed_events()` 的产出比——预置库
    /// 增删项目时这三条回退用例不该再红。（v1.9.0 修：17 → 21 时
    /// 魔法数没跟着更新，红了一片。）
    #[test]
    fn load_from_disk_with_missing_file_falls_back_to_seeded_library() {
        let d = tmpdir("missing");
        let mut s = Store::load(&d);
        s.load_from_disk(&d); // 不 panic
        let g = s.data.lock_recover();
        let mut expect = Data::default();
        seed_events(&mut expect);
        assert_eq!(
            g.events.len(),
            expect.events.len(),
            "应回退到预置项目库（与 seed_events 数量一致）"
        );
        assert_eq!(g.events[0].name, "男子100米", "首个预置项目名应正确");
        drop(g);
        let _ = fs::remove_dir_all(&d);
    }

    /// 数据文件**内容损坏**（非合法 JSON）时应回退到空数据，而不是 panic。
    ///
    /// 语义选择说明：这里与"加密文件缺密钥"刻意不同 —— 后者必须**报错**，
    /// 因为静默清空等于丢数据；而明文 JSON 损坏时若无法解析，
    /// 回退空数据并让自动备份/日志兜底，比直接 panic 让服务起不来更可用。
    #[test]
    fn load_from_disk_with_corrupt_json_does_not_panic() {
        let d = tmpdir("corrupt");
        fs::write(d.join(DATA_FILE_NAME), b"{ this is not valid json!!! ").unwrap();

        let mut s = Store::load(&d);
        s.load_from_disk(&d); // 关键：不应 panic

        // 要么回退空数据，要么保留了能解析的部分；两者都可接受，
        // 但绝不能是"进程崩溃"。
        drop(s.data.lock_recover());
        let _ = fs::remove_dir_all(&d);
    }

    /// 空文件（0 字节）同样不能 panic。
    #[test]
    fn load_from_disk_with_empty_file_does_not_panic() {
        let d = tmpdir("empty");
        fs::write(d.join(DATA_FILE_NAME), b"").unwrap();

        let mut s = Store::load(&d);
        s.load_from_disk(&d);
        // 与"文件不存在"同路径：解析失败 → 预置项目库
        let mut expect = Data::default();
        seed_events(&mut expect);
        assert_eq!(
            s.data.lock_recover().events.len(),
            expect.events.len(),
            "空文件应回退到预置项目库"
        );
        let _ = fs::remove_dir_all(&d);
    }

    /// `enable_vault(true, None)` 必须**拒绝**启用 —— 不允许"以为加密了其实没加密"。
    #[test]
    fn enable_vault_refuses_encrypt_without_seed() {
        let d = tmpdir("vault_refuse");
        let mut s = Store::load(&d);

        let enabled = s.enable_vault(true, None);
        assert!(!enabled, "无密钥时必须拒绝启用加密");
        assert!(!s.encrypt, "encrypt 应被强制关回 false");
        assert!(s.seed.is_none());
        assert!(!s.vault_enabled);

        let _ = fs::remove_dir_all(&d);
    }

    /// `enable_vault(true, Some(seed))` 应真正启用。
    #[test]
    fn enable_vault_with_seed_arms_the_vault() {
        let d = tmpdir("vault_on");
        let mut s = Store::load(&d);

        let enabled = s.enable_vault(true, Some("secret-seed".into()));
        assert!(enabled);
        assert!(s.encrypt);
        assert!(s.vault_enabled);
        assert_eq!(s.seed.as_deref(), Some("secret-seed"));

        let _ = fs::remove_dir_all(&d);
    }

    /// **加密往返**：加密保存 → 新实例加载 → 数据一致，且明文文件被清理。
    ///
    /// 这条覆盖 v1.5.1 加的加密链路在 store 层的行为（vault.rs 只测了
    /// 编解码本身，没测"store 是否正确地选文件、清另一份"）。
    #[test]
    fn encrypted_save_and_load_roundtrip() {
        let d = tmpdir("enc_roundtrip");

        let mut data = Data::default();
        seed_events(&mut data);
        data.settings.class_count = 41;
        let n = data.events.len();

        // 保存（加密）
        let mut saver = Store::load(&d);
        saver.enable_vault(true, Some("k1".into()));
        saver.save(&data).expect("加密保存应成功");

        // 密文应存在，明文应被清理（防"隐蔽后门"）
        let enc = crate::core::vault::enc_path(&saver.db_path);
        assert!(enc.exists(), "应生成密文文件 {}", enc.display());
        assert!(
            !saver.db_path.exists(),
            "加密后不应残留明文数据文件"
        );

        // 加载：新实例 + 同密钥
        let mut loader = Store::load(&d);
        loader.enable_vault(true, Some("k1".into()));
        loader.load_from_disk(&d);
        let back = loader.data.lock_recover();
        assert_eq!(back.events.len(), n, "加密往返后项目数应一致");
        assert_eq!(back.settings.class_count, 41, "加密往返后设置应一致");

        let _ = fs::remove_dir_all(&d);
    }

    /// 用**错误密钥**加载加密数据时，必须**放弃**而不是解出乱码。
    ///
    /// 这是加密的底线：MAC 校验失败就宁可空手而归，绝不返回损坏/伪造内容。
    ///
    /// # 断言写法说明（第一版这里是错的，值得记下）
    ///
    /// 初版断言是 `assert_ne!(got, data.events.len())` —— 用"条数不同"
    /// 来证明"没解出正确数据"。但**回退路径本身也会预置一批项目**，
    /// 若自定义数据条数恰好相同（如 17），`17 != 17` 失败：
    /// 一个**正确的实现**被一个**写了等价类陷阱的断言语**判为失败。
    ///
    /// 正确做法是断言**内容**而非**数量**——用一个预置库里不存在的
    /// 标记值来区分"真实数据"与"回退预置数据"。
    /// （v1.9.0 补：末条的数量断言同样不写死，与 `seed_events()`
    /// 的产出比——预置库从 17 扩到 21 时它红过。）
    #[test]
    fn encrypted_load_with_wrong_seed_discards_data_instead_of_garbling() {
        let d = tmpdir("enc_wrong");

        // 造一份**与预置库可区分**的数据：清空后只放一个自定义项目
        let mut data = Data::default();
        data.events.clear();
        data.events.push(Event {
            id: 1,
            name: "绝密测试项目".into(),
            category: "田赛".into(),
            gender: "通用".into(),
            grade: "全部".into(),
            is_team: false,
            unit: "米".into(),
            record: None,
        });
        data.next_event_id = 2;

        let mut saver = Store::load(&d);
        saver.enable_vault(true, Some("correct-key".into()));
        saver.save(&data).expect("加密保存应成功");

        // 正确密钥：应读出"绝密测试项目"
        let mut ok = Store::load(&d);
        ok.enable_vault(true, Some("correct-key".into()));
        ok.load_from_disk(&d);
        assert_eq!(
            ok.data.lock_recover().events.len(),
            1,
            "正确密钥应读出 1 条自定义数据"
        );
        assert_eq!(
            ok.data.lock_recover().events[0].name,
            "绝密测试项目",
            "正确密钥应读出真实内容"
        );

        // 错误密钥：不应 panic，且**不能出现那个自定义项目**
        let mut bad = Store::load(&d);
        bad.enable_vault(true, Some("WRONG-KEY".into()));
        bad.load_from_disk(&d);
        let names: Vec<String> = bad
            .data
            .lock_recover()
            .events
            .iter()
            .map(|e| e.name.clone())
            .collect();
        assert!(
            !names.iter().any(|n| n == "绝密测试项目"),
            "错误密钥绝不能解出真实数据，实际读到：{:?}",
            names
        );
        // 回退到预置库（可区分于"空"）：说明是走了明确的失败分支
        let mut expect = Data::default();
        seed_events(&mut expect);
        assert_eq!(
            names.len(),
            expect.events.len(),
            "错误密钥应回退到预置库，实际：{:?}",
            names
        );

        let _ = fs::remove_dir_all(&d);
    }

    /// `store.data` 经过 `lock_recover` 后可正常读写（基本健全性）。
    #[test]
    fn data_mutex_is_usable_via_lock_recover() {
        let d = tmpdir("mutex");
        let s = Store::load(&d);
        {
            let mut g = s.data.lock_recover();
            g.next_event_id = 77;
        }
        assert_eq!(s.data.lock_recover().next_event_id, 77);
        let _ = fs::remove_dir_all(&d);
    }

    /// v1.7：赛程字段（场地/单元/时段）应随数据一起持久化、再加载一致。
    #[test]
    fn save_then_load_preserves_schedule_fields() {
        let d = tmpdir("sched_rt");
        let mut data = Data::default();
        // 故意用自定义值，确保不走默认分支
        data.venues = vec![crate::core::schedule::Venue {
            id: 9,
            name: "备用场".into(),
            for_track: true,
            for_field: false,
        }];
        data.schedule_days = 3;
        data.sessions = crate::core::schedule::default_sessions(3);
        data.slots = vec![crate::core::schedule::Slot {
            event_id: 1,
            session_id: 1,
            start_min: 500,
            duration_min: 12,
            venue_id: 9,
            group_count: 2,
        }];

        let s = Store::load(&d);
        s.save(&data).expect("保存应成功");

        let mut s2 = Store::load(&d);
        s2.load_from_disk(&d);
        let g = s2.data.lock_recover();
        assert_eq!(g.venues.len(), 1, "场地应被持久化");
        assert_eq!(g.venues[0].name, "备用场");
        assert_eq!(g.schedule_days, 3);
        assert_eq!(g.sessions.len(), 6, "3 天 × 2 单元 = 6");
        assert_eq!(g.slots.len(), 1, "时段应被持久化");
        assert_eq!(g.slots[0].start_min, 500);
        drop(g);
        let _ = fs::remove_dir_all(&d);
    }

    /// v1.7：老数据（无赛程字段）读入后必须回退到合法默认（规则 20）。
    ///
    /// 这是"零迁移"承诺的实测：v1.6 及以前的用户升级后，
    /// 赛程功能立即可用，无需任何手工操作。
    #[test]
    fn load_missing_schedule_fields_falls_back_to_default() {
        let d = tmpdir("sched_def");
        let mut o = Json::obj();
        o.set("version", Json::Int(2));
        o.set("settings", Settings::default().to_json());
        o.set("events", Json::arr(Vec::new()));
        o.set("students", Json::arr(Vec::new()));
        o.set("registrations", Json::arr(Vec::new()));
        o.set("results", Json::arr(Vec::new()));
        o.set("next_event_id", Json::Int(1));
        o.set("next_student_id", Json::Int(1));
        o.set("next_reg_id", Json::Int(1));
        o.set("next_result_id", Json::Int(1));
        o.set("undo_stack", Json::arr(Vec::new()));
        // 注意：故意不写 venues/sessions/slots/schedule_days
        let path = d.join(DATA_FILE_NAME);
        fs::write(&path, o.to_string()).unwrap();

        let mut s = Store::load(&d);
        s.load_from_disk(&d);
        let g = s.data.lock_recover();
        assert!(!g.venues.is_empty(), "缺失场地应回退默认（非空）");
        assert_eq!(g.schedule_days, 2, "缺失天数回退 2");
        assert!(!g.sessions.is_empty(), "缺失单元应回退默认");
        assert!(g.slots.is_empty(), "缺失时段 = 空（还没排过）");
        drop(g);
        let _ = fs::remove_dir_all(&d);
    }
}
