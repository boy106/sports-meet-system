//! v1.9.8：内置 AI 助手（Agnes 国内站）配置。
//!
//! 开源版不内置任何密钥：首次使用请在「系统设置 → AI 助手」里填自己的 key，
//! 或设置环境变量 AGNES_API_KEY（环境变量优先级低于 ai.json）。
//! 配置单独存 `ai.json`，与 `sports_meet.json` 分开：
//! 换密钥不该触发成绩数据的备份/撤销链。
//!
//! 调用方式：前端浏览器直连 `{base_url}/chat/completions`。
//! 这样不往二进制里塞 TLS 栈（本项目坚持最小依赖），
//! 且 Agnes 已开放 CORS（`Access-Control-Allow-Origin: *`）。

use crate::core::json::Json;
use std::path::Path;

pub const DEFAULT_BASE_URL: &str = "https://api.agnes-ai.cn/v1";
pub const DEFAULT_MODEL: &str = "agnes-2.5-flash";
/// 开源版不内置密钥；可用环境变量 `AGNES_API_KEY` 预置，或在设置页填写。
pub const DEFAULT_API_KEY: &str = "";
const FILE_NAME: &str = "ai.json";

#[derive(Clone, Debug)]
pub struct AiConfig {
    pub base_url: String,
    pub model: String,
    pub api_key: String,
    pub enabled: bool,
}

impl Default for AiConfig {
    fn default() -> Self {
        AiConfig {
            base_url: DEFAULT_BASE_URL.to_string(),
            model: DEFAULT_MODEL.to_string(),
            api_key: std::env::var("AGNES_API_KEY")
                .unwrap_or_default()
                .trim()
                .to_string(),
            enabled: true,
        }
    }
}

impl AiConfig {
    pub fn load(dir: &Path) -> AiConfig {
        let mut c = AiConfig::default();
        let Ok(text) = std::fs::read_to_string(dir.join(FILE_NAME)) else {
            return c;
        };
        let Ok(j) = Json::parse(&text) else {
            return c;
        };
        if let Some(v) = j.get_str("base_url") {
            let v = v.trim().trim_end_matches('/');
            if !v.is_empty() {
                c.base_url = v.to_string();
            }
        }
        if let Some(v) = j.get_str("model") {
            if !v.trim().is_empty() {
                c.model = v.trim().to_string();
            }
        }
        if let Some(v) = j.get_str("api_key") {
            if !v.trim().is_empty() {
                c.api_key = v.trim().to_string();
            }
        }
        if let Some(v) = j.get("enabled").and_then(|v| v.as_bool()) {
            c.enabled = v;
        }
        c
    }

    pub fn save(&self, dir: &Path) -> Result<(), String> {
        let mut o = Json::obj();
        o.set("base_url", Json::s(self.base_url.clone()));
        o.set("model", Json::s(self.model.clone()));
        o.set("api_key", Json::s(self.api_key.clone()));
        o.set("enabled", Json::Bool(self.enabled));
        std::fs::create_dir_all(dir).map_err(|e| format!("创建数据目录失败：{}", e))?;
        std::fs::write(dir.join(FILE_NAME), o.to_string_pretty())
            .map_err(|e| format!("写入 ai.json 失败：{}", e))
    }

    /// 给前端用：需要真实 key 才能从浏览器直连，因此不脱敏。
    /// 用户明确表示这台机器上的密钥由其本人控制。
    pub fn to_json(&self) -> Json {
        let mut o = Json::obj();
        o.set("base_url", Json::s(self.base_url.clone()));
        o.set("model", Json::s(self.model.clone()));
        o.set("api_key", Json::s(self.api_key.clone()));
        o.set("enabled", Json::Bool(self.enabled));
        o.set("has_key", Json::Bool(!self.api_key.trim().is_empty()));
        // 默认模型清单：设置页下拉用，避免老师手打模型名打错
        o.set(
            "models",
            Json::arr(
                [
                    "agnes-2.5-flash",
                    "agnes-2.5-pro",
                    "agnes-3.0-flash",
                    "agnes-3.0-pro",
                ]
                .iter()
                .map(|m| Json::s(m.to_string())),
            ),
        );
        o
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_has_no_key_and_cn_endpoint() {
        let c = AiConfig::default();
        // 开源版不内置密钥：未设置环境变量时必须为空
        if std::env::var("AGNES_API_KEY").is_err() {
            assert!(c.api_key.is_empty());
        }
        assert_eq!(c.base_url, "https://api.agnes-ai.cn/v1");
        assert!(c.enabled);
    }

    #[test]
    fn json_reports_has_key_honestly() {
        let mut c = AiConfig::default();
        c.api_key = String::new();
        let j = c.to_json();
        assert_eq!(j.get_str("base_url").unwrap(), DEFAULT_BASE_URL);
        assert_eq!(j.get("has_key").and_then(|v| v.as_bool()), Some(false));

        c.api_key = "sk-test-key-for-json".to_string();
        let j = c.to_json();
        assert_eq!(j.get("has_key").and_then(|v| v.as_bool()), Some(true));
    }
}
