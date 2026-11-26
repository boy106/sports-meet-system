//! 统一业务错误类型与错误码（核心模块）。
//!
//! v1.4：从 api.rs 抽出为独立文件——此前 docs/02、docs/09 已按此结构描述，
//! 但文件实际缺失（文档与代码不一致，v1.3 全项目审查 P0-3）。
//! 现在 `core::error` 名副其实：`ApiErr` 为业务错误，`ApiResult` 为统一结果别名。
//!
//! v1.6.0：引入**稳定错误码**（`ErrCode`）。此前客户端只能靠 HTTP 状态码或
//! 解析中文 message 来判断错误种类——前者粒度太粗（所有 400 都是一个码），
//! 后者一改文案就失效。现在每个 `ApiErr` 携带一个**机器可读、承诺稳定**的码，
//! 前端据此分流（例如 `E_CONFIRM` 弹二次确认、`E_AUTH` 弹口令框）。
//!
//! 稳定性承诺：**已发布的码不复用、不改语义**。新增只能追加。

use crate::core::json::Json;

/// 稳定错误码。序列化为 `"E_XXX"` 字符串，客户端据此分流。
///
/// 设计原则：**按"客户端该怎么处理"分类，而非按"服务端哪里出错"分类**。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrCode {
    /// 请求参数不合法（缺字段、格式错、超范围）。客户端：修正输入后重试。
    Validation,
    /// 目标资源不存在。客户端：刷新列表，不要自动重试。
    NotFound,
    /// 与当前状态冲突（如重复报名、同班重名）。客户端：提示用户，不重试。
    Conflict,
    /// 未认证 / 令牌失效。客户端：弹出口令框换取令牌后**重试一次**。
    Auth,
    /// 敏感操作需要二次确认。客户端：弹出确认框，带上口令**重放**该请求。
    Confirm,
    /// 触发限流。客户端：**退避后重试**，不要立刻重发。
    Limit,
    /// 请求体过大 / 格式不被接受。客户端：提示用户，不重试。
    Payload,
    /// 服务端内部错误。客户端：提示"系统异常"，可重试一次。
    Internal,
}

impl ErrCode {
    /// 稳定的字符串码。**这些字符串是公开契约，不可随意修改。**
    pub fn as_str(self) -> &'static str {
        match self {
            ErrCode::Validation => "E_VALIDATION",
            ErrCode::NotFound => "E_NOT_FOUND",
            ErrCode::Conflict => "E_CONFLICT",
            ErrCode::Auth => "E_AUTH",
            ErrCode::Confirm => "E_CONFIRM",
            ErrCode::Limit => "E_LIMIT",
            ErrCode::Payload => "E_PAYLOAD",
            ErrCode::Internal => "E_INTERNAL",
        }
    }

    /// 由 HTTP 状态码推出**默认**错误码。
    ///
    /// 在 `ApiErr::new` / `with_status` 这类未显式指定码的构造路径上兜底，
    /// 保证"任何错误都至少有一个合理的码"，不需要改动既有约 200 处调用点。
    pub fn from_status(status: u16) -> ErrCode {
        match status {
            401 | 403 => ErrCode::Auth,
            404 => ErrCode::NotFound,
            409 => ErrCode::Conflict,
            413 | 415 => ErrCode::Payload,
            428 => ErrCode::Confirm,
            429 => ErrCode::Limit,
            s if s >= 500 => ErrCode::Internal,
            _ => ErrCode::Validation,
        }
    }
}

/// 业务错误：message 用户可读，status 为 HTTP 状态码，code 为稳定错误码。
#[derive(Debug, Clone)]
pub struct ApiErr {
    pub message: String,
    pub status: u16,
    /// 附带数据（如删除预览），随响应 JSON 输出。
    pub data: Option<Json>,
    /// 稳定错误码。默认由 status 推出，可用 `code()` 显式覆盖。
    pub code: ErrCode,
}

impl ApiErr {
    pub fn new(message: impl Into<String>) -> ApiErr {
        ApiErr {
            message: message.into(),
            status: 400,
            data: None,
            code: ErrCode::Validation,
        }
    }

    pub fn with_status(message: impl Into<String>, status: u16) -> ApiErr {
        ApiErr {
            message: message.into(),
            status,
            data: None,
            code: ErrCode::from_status(status),
        }
    }

    /// 显式指定错误码（覆盖由 status 推出的默认值）。
    ///
    /// 用于"状态码相同但语义不同"的场景，例如同为 400：
    /// 参数格式错用 `E_VALIDATION`，同班重名用 `E_CONFLICT`。
    pub fn with_code(mut self, code: ErrCode) -> ApiErr {
        self.code = code;
        self
    }

    /// 附带数据的链式构造（删除预览等）。
    pub fn with_data(mut self, data: Json) -> ApiErr {
        self.data = Some(data);
        self
    }

    /// 语义化构造器：最常用的几种错误，省去手写状态码。
    pub fn not_found(message: impl Into<String>) -> ApiErr {
        ApiErr::with_status(message, 404)
    }
    pub fn conflict(message: impl Into<String>) -> ApiErr {
        ApiErr::with_status(message, 409)
    }
    pub fn auth(message: impl Into<String>) -> ApiErr {
        ApiErr::with_status(message, 401)
    }
    pub fn confirm(message: impl Into<String>) -> ApiErr {
        ApiErr::with_status(message, 428)
    }
    pub fn limit(message: impl Into<String>) -> ApiErr {
        ApiErr::with_status(message, 429)
    }
    pub fn payload(message: impl Into<String>) -> ApiErr {
        ApiErr::with_status(message, 415)
    }
    pub fn internal(message: impl Into<String>) -> ApiErr {
        ApiErr::with_status(message, 500)
    }
}

impl From<String> for ApiErr {
    fn from(e: String) -> Self {
        ApiErr::new(e)
    }
}

impl From<&str> for ApiErr {
    fn from(e: &str) -> Self {
        ApiErr::new(e)
    }
}

/// 统一结果别名：handler / 领域方法的标准返回类型。
/// （v1.4：由 api.rs 中无人使用的死别名 `ApiResult = Result<Json, ApiErr>`
/// 改为泛型别名，并被 `Route::handler` 真实使用。）
pub type ApiResult<T> = Result<T, ApiErr>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_err_defaults_and_from() {
        let e = ApiErr::new("出错了");
        assert_eq!(e.status, 400);
        assert_eq!(e.message, "出错了");
        assert!(e.data.is_none());

        let e2: ApiErr = "字符串错误".into();
        assert_eq!(e2.status, 400);

        let e3 = ApiErr::with_status("未找到", 404);
        assert_eq!(e3.status, 404);
    }

    /// v1.6.0：错误码必须能从状态码推出，且语义正确。
    #[test]
    fn error_codes_derive_from_status() {
        assert_eq!(ErrCode::from_status(400), ErrCode::Validation);
        assert_eq!(ErrCode::from_status(401), ErrCode::Auth);
        assert_eq!(ErrCode::from_status(403), ErrCode::Auth);
        assert_eq!(ErrCode::from_status(404), ErrCode::NotFound);
        assert_eq!(ErrCode::from_status(409), ErrCode::Conflict);
        assert_eq!(ErrCode::from_status(413), ErrCode::Payload);
        assert_eq!(ErrCode::from_status(415), ErrCode::Payload);
        assert_eq!(ErrCode::from_status(428), ErrCode::Confirm);
        assert_eq!(ErrCode::from_status(429), ErrCode::Limit);
        assert_eq!(ErrCode::from_status(500), ErrCode::Internal);
        assert_eq!(ErrCode::from_status(503), ErrCode::Internal);
        // 未列举的 4xx 一律归为参数错误，而不是 Internal
        assert_eq!(ErrCode::from_status(418), ErrCode::Validation);
    }

    /// v1.6.0：字符串码是公开契约，锁定其字面值防止被无意改掉。
    /// 这个测试失败 = 破坏了对外承诺，必须谨慎评估后再改。
    #[test]
    fn error_code_strings_are_stable_contract() {
        assert_eq!(ErrCode::Validation.as_str(), "E_VALIDATION");
        assert_eq!(ErrCode::NotFound.as_str(), "E_NOT_FOUND");
        assert_eq!(ErrCode::Conflict.as_str(), "E_CONFLICT");
        assert_eq!(ErrCode::Auth.as_str(), "E_AUTH");
        assert_eq!(ErrCode::Confirm.as_str(), "E_CONFIRM");
        assert_eq!(ErrCode::Limit.as_str(), "E_LIMIT");
        assert_eq!(ErrCode::Payload.as_str(), "E_PAYLOAD");
        assert_eq!(ErrCode::Internal.as_str(), "E_INTERNAL");
    }

    /// v1.6.0：语义化构造器与 with_code 覆盖。
    #[test]
    fn semantic_constructors_and_code_override() {
        assert_eq!(ApiErr::not_found("x").status, 404);
        assert_eq!(ApiErr::not_found("x").code, ErrCode::NotFound);
        assert_eq!(ApiErr::conflict("x").code, ErrCode::Conflict);
        assert_eq!(ApiErr::auth("x").code, ErrCode::Auth);
        assert_eq!(ApiErr::confirm("x").code, ErrCode::Confirm);
        assert_eq!(ApiErr::limit("x").code, ErrCode::Limit);
        assert_eq!(ApiErr::payload("x").code, ErrCode::Payload);
        assert_eq!(ApiErr::internal("x").code, ErrCode::Internal);

        // 同为 400，可用 with_code 把"重名"从 Validation 提升为 Conflict
        let e = ApiErr::new("该班级已有同名学生").with_code(ErrCode::Conflict);
        assert_eq!(e.status, 400);
        assert_eq!(e.code, ErrCode::Conflict);
    }
}
