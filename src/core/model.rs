//! 领域模型（核心模块）：与 Python 版数据结构严格对齐。

use crate::core::json::Json;

#[derive(Debug, Clone)]
pub struct Settings {
    pub grades: Vec<String>,
    pub class_count: i64,
    pub max_individual: i64,
    pub max_team: i64,
    /// 每班每单项限报人数（0=不限）
    pub max_per_class_per_event: i64,
    /// 是否强制性别匹配（男子/女子项目按性别限制）
    pub enforce_gender: bool,
    pub points_table: Vec<f64>,
    pub record_bonus: f64,
    pub team_multiplier: f64,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            grades: vec!["初一".into(), "初二".into(), "初三".into()],
            class_count: 20,
            max_individual: 2,
            max_team: 2,
            max_per_class_per_event: 2,
            enforce_gender: true,
            points_table: vec![7.0, 5.0, 4.0, 3.0, 2.0, 1.0],
            record_bonus: 7.0,
            team_multiplier: 2.0,
        }
    }
}

impl Settings {
    pub fn to_json(&self) -> crate::core::json::Json {
        use crate::core::json::Json;
        let mut o = Json::obj();
        o.set("grades", Json::arr(self.grades.iter().map(|g| Json::s(g.clone()))));
        o.set("class_count", Json::Int(self.class_count));
        o.set("max_individual", Json::Int(self.max_individual));
        o.set("max_team", Json::Int(self.max_team));
        o.set("max_per_class_per_event", Json::Int(self.max_per_class_per_event));
        o.set("enforce_gender", Json::Bool(self.enforce_gender));
        o.set("points_table", Json::arr(self.points_table.iter().map(|p| Json::Num(*p))));
        o.set("record_bonus", Json::Num(self.record_bonus));
        o.set("team_multiplier", Json::Num(self.team_multiplier));
        o
    }

    pub fn from_json(j: Option<&crate::core::json::Json>) -> Option<Settings> {
        let j = j?;
        let mut s = Settings::default();
        if let Some(Json::Arr(arr)) = j.get("grades") {
            let grades: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str().map(|x| x.to_string()))
                .collect();
            if !grades.is_empty() {
                s.grades = grades;
            }
        }
        if let Some(v) = j.get_i64("class_count") {
            s.class_count = v;
        }
        if let Some(v) = j.get_i64("max_individual") {
            s.max_individual = v;
        }
        if let Some(v) = j.get_i64("max_team") {
            s.max_team = v;
        }
        if let Some(v) = j.get_i64("max_per_class_per_event") {
            s.max_per_class_per_event = v;
        }
        if let Some(v) = j.get("enforce_gender").and_then(|v| v.as_bool()) {
            s.enforce_gender = v;
        }
        if let Some(Json::Arr(arr)) = j.get("points_table") {
            let pts: Vec<f64> = arr.iter().filter_map(|v| v.as_f64()).collect();
            if !pts.is_empty() {
                s.points_table = pts;
            }
        }
        if let Some(v) = j.get("record_bonus").and_then(|v| v.as_f64()) {
            s.record_bonus = v;
        }
        if let Some(v) = j.get("team_multiplier").and_then(|v| v.as_f64()) {
            s.team_multiplier = v;
        }
        Some(s)
    }
}

#[derive(Debug, Clone)]
pub struct Event {
    pub id: i64,
    pub name: String,
    pub category: String, // 径赛 / 田赛
    pub gender: String,   // 男子 / 女子 / 通用
    pub grade: String,    // 初一 / 初二 / 初三 / 全部
    pub is_team: bool,
    pub unit: String,           // 时间 / 米 / 个
    pub record: Option<f64>,    // 校纪录（换算后的数值）
}

impl Event {
    /// 径赛：成绩越小越好；田赛：成绩越大越好。
    pub fn is_track(&self) -> bool {
        self.category == "径赛"
    }
}

#[derive(Debug, Clone)]
pub struct Student {
    pub id: i64,
    pub grade: String,
    pub class_no: i64,
    pub name: String,
    pub gender: String, // 男 / 女 / 空（未知）
}

impl Student {
    pub fn class_name(&self) -> String {
        format!("{}{}班", self.grade, self.class_no)
    }
}

#[derive(Debug, Clone)]
pub struct Registration {
    pub id: i64,
    pub event_id: i64,
    pub student_id: i64,
    pub note: String,
}

#[derive(Debug, Clone)]
pub struct Result {
    pub id: i64,
    pub event_id: i64,
    pub student_id: Option<i64>, // 个人成绩；集体项目为 None
    pub grade: String,
    pub class_no: Option<i64>, // 集体项目班级；个人项目为 None
    pub score_text: String,
    pub score_value: Option<f64>,
    pub rank: Option<i64>,
    pub points: Option<f64>,
    pub broke_record: bool,
}
