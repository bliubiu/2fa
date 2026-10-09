//! CLI 错误类型与退出码。
//!
//! 退出码约定（供脚本判断）：`0` 成功；`1` 一般错误；`2` 认证失败
//! （密码或恢复码错误）。脚本只需区分 0 与非 0；`2` 专用于凭据错误。

/// CLI 错误。
#[derive(Debug)]
pub enum CliError {
    /// 一般错误（信息以「错误：」前缀输出到 stderr）。
    Generic(String),
    /// 认证失败：密码或恢复码错误。
    AuthFailed,
}

impl CliError {
    /// 进程退出码。
    pub fn exit_code(&self) -> u8 {
        match self {
            CliError::Generic(_) => 1,
            CliError::AuthFailed => 2,
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CliError::Generic(message) => write!(f, "{message}"),
            CliError::AuthFailed => write!(f, "认证失败：密码或恢复码错误"),
        }
    }
}

impl From<String> for CliError {
    fn from(message: String) -> Self {
        CliError::Generic(message)
    }
}

impl From<&str> for CliError {
    fn from(message: &str) -> Self {
        CliError::Generic(message.to_string())
    }
}

impl From<crate::paths::ResolveError> for CliError {
    fn from(err: crate::paths::ResolveError) -> Self {
        CliError::Generic(err.to_string())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// 退出码：成功 0 由运行路径保证；一般错误 1；认证失败 2。
    #[test]
    fn 退出码约定() {
        assert_eq!(CliError::Generic("任意".into()).exit_code(), 1);
        assert_eq!(CliError::AuthFailed.exit_code(), 2);
    }

    /// Display：认证失败给出中文说明。
    #[test]
    fn 认证失败信息() {
        assert_eq!(
            CliError::AuthFailed.to_string(),
            "认证失败：密码或恢复码错误"
        );
    }
}
