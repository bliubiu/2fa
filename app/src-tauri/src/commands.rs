//! Tauri commands：前端可调用的命令薄封装。
//!
//! 业务逻辑全部在 [`crate::session`] 与 `two-fa-core`；本模块只做参数接收、
//! 时钟取值（壳层取系统时间后传入，core 零环境感知不变）、错误映射与视图序列化。
//! 错误以 `{ kind, message }` 结构返回：kind 供前端分支，message 恒为中文，
//! 不回显密码或密钥（脱敏规范）。

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tauri::State;
use two_fa_core::domain::totp;
use two_fa_core::usecase::entries::{self, EntryOpError};
use two_fa_core::vault::Entry;

use crate::session::{Session, SessionError};

/// 前端可见的结构化错误。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AppError {
    /// 错误类别（auth / locked / no_vault / not_found / other）。
    pub kind: &'static str,
    /// 中文错误消息。
    pub message: String,
}

impl From<SessionError> for AppError {
    fn from(e: SessionError) -> Self {
        Self {
            kind: e.kind(),
            message: e.message(),
        }
    }
}

/// 会话互斥锁中毒：唯一的不可恢复内部错误。
fn poisoned() -> AppError {
    AppError {
        kind: "other",
        message: "内部状态异常（会话已被污染），请重启应用".to_string(),
    }
}

/// 在共享会话上执行操作，统一错误映射。
fn with_session<T>(
    state: &Mutex<Session>,
    op: impl FnOnce(&mut Session) -> Result<T, SessionError>,
) -> Result<T, AppError> {
    let mut session = state.lock().map_err(|_| poisoned())?;
    op(&mut session).map_err(AppError::from)
}

/// 当前 Unix 秒（壳层取系统时钟；时钟异常映射为中文错误）。
pub fn now_unix() -> Result<u64, AppError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| AppError {
            kind: "other",
            message: format!("系统时钟异常：{e}"),
        })
}

// ---------------------------------------------------------------------------
// 视图与纯构造函数（可单元测试）
// ---------------------------------------------------------------------------

/// 条目列表视图。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct EntryView {
    /// 完整 UUID。
    pub id: String,
    /// 库内唯一的 ID 前缀（长度随库自适应，与 CLI list 一致）。
    pub id_prefix: String,
    pub issuer: String,
    pub account: String,
    /// 当前验证码；密钥解码失败时为 None（前端显示「错误」）。
    pub code: Option<String>,
    /// 当前周期剩余秒数。
    pub remaining_secs: u64,
    /// 算法标签（SHA1 / SHA256 / SHA512 / STEAM）。
    pub algorithm: &'static str,
    pub digits: u8,
    pub period: u32,
    pub tags: Vec<String>,
}

/// 当前验证码（十进制按位数补零）；密钥解码或计算失败时返回 None。
/// counter = floor(now / period)，与 CLI list 的取码语义一致。
pub fn code_of(entry: &Entry, now: u64) -> Option<String> {
    let bytes = entry.secret.to_bytes().ok()?;
    let counter = now / u64::from(entry.period);
    let code = totp::compute(&bytes, counter, entry.algorithm, entry.digits).ok()?;
    Some(format!("{code:0width$}", width = usize::from(entry.digits)))
}

/// 当前周期剩余秒数（整数除法，与 CLI 一致）。
pub fn remaining_secs(entry: &Entry, now: u64) -> u64 {
    u64::from(entry.period) - now % u64::from(entry.period)
}

/// 构造条目视图。`plen` 来自 core 的库内唯一前缀长度。
pub fn entry_view(entry: &Entry, now: u64, plen: usize) -> EntryView {
    EntryView {
        id: entry.id.to_string(),
        id_prefix: entry.id.to_string()[..plen].to_string(),
        issuer: entry.issuer.clone(),
        account: entry.account.clone(),
        code: code_of(entry, now),
        remaining_secs: remaining_secs(entry, now),
        algorithm: entry.algorithm.label(),
        digits: entry.digits,
        period: entry.period,
        tags: entry.tags.clone(),
    }
}

/// 单条取码视图（`get_code` 返回）。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct CodeView {
    pub id: String,
    pub issuer: String,
    pub account: String,
    pub code: Option<String>,
    pub remaining_secs: u64,
}

/// 构造单条取码视图。
pub fn code_view(entry: &Entry, now: u64) -> CodeView {
    CodeView {
        id: entry.id.to_string(),
        issuer: entry.issuer.clone(),
        account: entry.account.clone(),
        code: code_of(entry, now),
        remaining_secs: remaining_secs(entry, now),
    }
}

/// ID 前缀定位失败映射：无匹配与多匹配均为 not_found（core 文本含候选列表）。
fn map_entry_err(err: EntryOpError) -> SessionError {
    match err {
        EntryOpError::NotFound(msg) | EntryOpError::Ambiguous(msg) => SessionError::NotFound(msg),
        other => SessionError::Other(other.to_string()),
    }
}

// ---------------------------------------------------------------------------
// Tauri commands（薄封装）
// ---------------------------------------------------------------------------

/// 解锁结果：条目数量。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct UnlockOut {
    pub entry_count: usize,
}

/// `unlock`：主密码解锁，返回条目数量。
#[tauri::command]
pub fn unlock(state: State<'_, Mutex<Session>>, password: String) -> Result<UnlockOut, AppError> {
    with_session(&state, |s| {
        s.unlock(&password)
            .map(|entry_count| UnlockOut { entry_count })
    })
}

/// `lock`：立即锁定并归零内存。返回是否确实发生了锁定。
#[tauri::command]
pub fn lock(state: State<'_, Mutex<Session>>) -> Result<bool, AppError> {
    with_session(&state, |s| Ok(s.lock()))
}

/// `status`：路径、来源、解锁状态；解锁后另含条目数与 KDF 版本。
#[tauri::command]
pub fn status(state: State<'_, Mutex<Session>>) -> Result<crate::session::StatusView, AppError> {
    with_session(&state, |s| s.status())
}

/// `list_entries`：全部条目与当前验证码（时钟由本层取系统时间传入）。
#[tauri::command]
pub fn list_entries(state: State<'_, Mutex<Session>>) -> Result<Vec<EntryView>, AppError> {
    let now = now_unix()?;
    with_session(&state, |s| {
        let body = s.require_unlocked()?;
        let plen = entries::unique_prefix_len(body);
        Ok(body
            .entries
            .iter()
            .map(|e| entry_view(e, now, plen))
            .collect())
    })
}

/// `get_code`：按 ID 前缀定位单条条目，返回验证码与剩余秒数。
#[tauri::command]
pub fn get_code(state: State<'_, Mutex<Session>>, prefix: String) -> Result<CodeView, AppError> {
    let now = now_unix()?;
    with_session(&state, |s| {
        let body = s.require_unlocked()?;
        let idx = entries::find_index_by_prefix(body, &prefix).map_err(map_entry_err)?;
        Ok(code_view(&body.entries[idx], now))
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use two_fa_core::domain::totp::Algorithm;
    use two_fa_core::vault::SecretKey;

    /// 构造标准测试条目（SHA1 / 6 位 / 30 秒）。
    fn sample_entry() -> Entry {
        Entry::new(
            "GitHub".to_string(),
            "alice".to_string(),
            SecretKey::from_base32("JBSWY3DPEHPK3PXP").unwrap(),
            Algorithm::Sha1,
            6,
            30,
            vec![],
        )
        .unwrap()
    }

    /// 剩余秒数整数除法语义：周期边界显示整周期，边界前一秒为 1。
    #[test]
    fn 剩余秒数边界() {
        let entry = sample_entry();
        assert_eq!(remaining_secs(&entry, 120), 30);
        assert_eq!(remaining_secs(&entry, 119), 1);
        assert_eq!(remaining_secs(&entry, 91), 30 - 1);
    }

    /// 错误映射：SessionError → AppError 的 kind/message 接线。
    #[test]
    fn 错误映射() {
        let e: AppError = SessionError::Locked.into();
        assert_eq!(e.kind, "locked");
        assert_eq!(e.message, "保险库处于锁定状态，请先解锁");

        let e: AppError = SessionError::Auth.into();
        assert_eq!(e.kind, "auth");

        let e: AppError =
            map_entry_err(EntryOpError::NotFound("未找到条目：gh".to_string())).into();
        assert_eq!(e.kind, "not_found");
        assert!(e.message.contains("未找到条目"));
    }
}
