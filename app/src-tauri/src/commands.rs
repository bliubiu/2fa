//! Tauri commands：前端可调用的命令薄封装。
//!
//! 业务逻辑全部在 [`crate::session`] 与 `two-fa-core`；本模块只做参数接收、
//! 时钟取值（壳层取系统时间后传入，core 零环境感知不变）、错误映射与视图序列化。
//! 错误以 `{ kind, message }` 结构返回：kind 供前端分支，message 恒为中文，
//! 不回显密码或密钥（脱敏规范）。

use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tauri::State;
use two_fa_core::domain::totp;
use two_fa_core::usecase::entries::{self, EntryOpError};
use two_fa_core::vault::{Entry, VaultBody, VaultKey, VaultLock};

use crate::add::{self, AddSourceDto, DecisionDto};
use crate::clipboard::ClipboardCleaner;
use crate::io;
use crate::mutate::{self, EditFieldsDto};
use crate::session::{Session, SessionError};

/// 复制验证码后剪贴板自动清除的延迟（PRD §10.2：30 秒）。
pub const COPY_CLEAR_DELAY: Duration = Duration::from_secs(30);

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

/// `lock`：立即锁定并归零内存；同时清除剪贴板残留验证码并作废未决清除计时。
/// 返回是否确实发生了锁定。
#[tauri::command]
pub fn lock(
    state: State<'_, Mutex<Session>>,
    clipboard: State<'_, ClipboardCleaner>,
) -> Result<bool, AppError> {
    clipboard.invalidate();
    with_session(&state, |s| Ok(s.lock()))
}

/// `check_idle`：前端心跳定期调用；空闲超过阈值则后端自动锁定。
/// 返回是否因本次检查触发了锁定（前端据此回解锁屏并提示）。
#[tauri::command]
pub fn check_idle(state: State<'_, Mutex<Session>>) -> Result<bool, AppError> {
    with_session(&state, |s| Ok(s.check_idle()))
}

/// `copy_code`：按 ID 前缀取验证码写入系统剪贴板，30 秒后自动清除
/// （仅当内容仍是该验证码；锁定亦会立即清除）。
#[tauri::command]
pub fn copy_code(
    state: State<'_, Mutex<Session>>,
    clipboard: State<'_, ClipboardCleaner>,
    prefix: String,
) -> Result<(), AppError> {
    let now = now_unix()?;
    let code = with_session(&state, |s| {
        let body = s.require_unlocked()?;
        let idx = entries::find_index_by_prefix(body, &prefix).map_err(map_entry_err)?;
        code_of(&body.entries[idx], now).ok_or_else(|| {
            SessionError::Other("无法生成验证码：密钥解码失败，请检查该条目".to_string())
        })
    })?;
    clipboard
        .copy_code(&code, COPY_CLEAR_DELAY)
        .map_err(|e| AppError {
            kind: "other",
            message: e,
        })
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

/// `add_preview`：解析添加来源（otpauth 文本 / 手填 / 图片），产出预览
/// （不含密钥）并暂存待提交区。返回的 token 在提交时回传校验。
#[tauri::command]
pub fn add_preview(
    state: State<'_, Mutex<Session>>,
    source: AddSourceDto,
) -> Result<add::AddPreview, AppError> {
    let token = next_token();
    with_session(&state, |s| {
        let body = s.require_unlocked()?;
        let mut parsed = add::parse_source(&source, body).map_err(SessionError::Other)?;
        add::set_token(&mut parsed, token);
        s.stash_pending_add(parsed.pending);
        Ok(parsed.view)
    })
}

/// `add_commit`：按决策把待提交条目并入正文并落盘（持文件锁）。
/// 冲突条目未决策即报错；无变更不写盘。
#[tauri::command]
pub fn add_commit(
    state: State<'_, Mutex<Session>>,
    token: u64,
    decisions: Vec<DecisionDto>,
) -> Result<add::AddSummary, AppError> {
    let mapped: Vec<(usize, add::DecisionAction)> =
        decisions.into_iter().map(|d| (d.index, d.action)).collect();
    with_session(&state, |s| {
        let (key, body, pending, path) = s.commit_parts()?;
        if pending.token != token {
            return Err(SessionError::Other(
                "添加预览已过期或不存在，请重新提交".to_string(),
            ));
        }
        let summary = add::apply(pending, body, &mapped).map_err(SessionError::Other)?;
        if summary.changed {
            persist_locked(path, key, body)?;
        }
        s.clear_pending_add();
        Ok(summary)
    })
}

/// `edit_entry`：按 ID 前缀编辑条目（仅提供的字段被修改，语义对齐 CLI `edit`）。
#[tauri::command]
pub fn edit_entry(
    state: State<'_, Mutex<Session>>,
    prefix: String,
    fields: EditFieldsDto,
) -> Result<(), AppError> {
    with_session(&state, |s| {
        let (key, body, path) = s.write_parts()?;
        mutate::edit(body, &prefix, &fields).map_err(SessionError::Other)?;
        persist_locked(path, key, body)?;
        Ok(())
    })
}

/// `delete_entry`：按 ID 前缀删除条目（前端二次确认后调用），返回被删条目描述。
#[tauri::command]
pub fn delete_entry(state: State<'_, Mutex<Session>>, prefix: String) -> Result<String, AppError> {
    with_session(&state, |s| {
        let (key, body, path) = s.write_parts()?;
        let desc = mutate::delete(body, &prefix).map_err(SessionError::Other)?;
        persist_locked(path, key, body)?;
        Ok(desc)
    })
}

/// 非 `SessionError` 的普通错误（io 模块的中文文本直接透传）。
fn plain_err(msg: String) -> AppError {
    AppError {
        kind: "other",
        message: msg,
    }
}

/// 解码 Base64（前端文件字节以 Base64 传输，与图片扫码来源同模式）。
fn decode_b64(s: &str) -> Result<Vec<u8>, AppError> {
    data_encoding::BASE64
        .decode(s.trim().as_bytes())
        .map_err(|_| plain_err("传输数据不是合法的 Base64".to_string()))
}

/// `export_backup`：导出加密备份——字节级拷贝，无需解锁。
/// 目标路径由前端系统另存对话框显式给出。
#[tauri::command]
pub fn export_backup(
    state: State<'_, Mutex<Session>>,
    path: String,
) -> Result<io::ExportOut, AppError> {
    let vault_path = with_session(&state, |s| Ok(s.vault_path().to_path_buf()))?;
    io::export_backup(&vault_path, std::path::Path::new(&path)).map_err(plain_err)
}

/// `import_backup`：导入加密备份（两段式）。未确认时只读验证备份凭据并返回
/// 预览；确认后整文件覆盖当前保险库（覆盖前自动存 `.bak`）。导入成功即强制
/// 锁定会话——当前主密码与恢复码已被替换为备份中的凭据，须重新解锁。
#[tauri::command]
pub fn import_backup(
    state: State<'_, Mutex<Session>>,
    bytes_b64: String,
    password: String,
    confirmed: bool,
) -> Result<io::ImportOut, AppError> {
    let raw = decode_b64(&bytes_b64)?;
    if !confirmed {
        return io::import_backup_preview(&raw, &password).map_err(plain_err);
    }
    let vault_path = with_session(&state, |s| Ok(s.vault_path().to_path_buf()))?;
    let entry_count = io::import_backup_commit(&vault_path, &raw, &password).map_err(plain_err)?;
    with_session(&state, |s| {
        s.lock();
        Ok(())
    })?;
    Ok(io::ImportOut::Done { entry_count })
}

/// `export_plain`：明文导出（危险出口）。门槛 1（输入当前条目数二次确认）由
/// 后端校验；门槛 2（显式路径）由前端另存对话框给出；门槛 3（首行警告注释）
/// 由 core 序列化器写入；门槛 4（完成后强提示删除）由前端完成态承担。
#[tauri::command]
pub fn export_plain(
    state: State<'_, Mutex<Session>>,
    path: String,
    confirm_count: String,
) -> Result<io::ExportOut, AppError> {
    with_session(&state, |s| {
        let body = s.require_unlocked()?;
        let text = io::plain_export_text(body, &confirm_count).map_err(SessionError::Other)?;
        let target = s.vault_path().to_path_buf();
        io::write_export(&target, std::path::Path::new(&path), text.as_bytes())
            .map_err(SessionError::Other)
    })
}

/// `show_entry`：查看条目完整明细（含明文密钥，`show` 等价）。确认弹窗由前端
/// 在调用前完成并提示明文风险。
#[tauri::command]
pub fn show_entry(
    state: State<'_, Mutex<Session>>,
    prefix: String,
) -> Result<io::SecretView, AppError> {
    let now = now_unix()?;
    with_session(&state, |s| {
        let body = s.require_unlocked()?;
        let idx = entries::find_index_by_prefix(body, &prefix).map_err(map_entry_err)?;
        let plen = entries::unique_prefix_len(body);
        Ok(io::secret_view(&body.entries[idx], now, plen))
    })
}

/// `change_password`：改主密码（旧密码验证 + 新密码替换）。主密钥与条目明文
/// 不变，成功后会话状态无需复位；新密码为空在 io 层拒绝。
#[tauri::command]
pub fn change_password(
    state: State<'_, Mutex<Session>>,
    old_password: String,
    new_password: String,
) -> Result<(), AppError> {
    let vault_path = with_session(&state, |s| Ok(s.vault_path().to_path_buf()))?;
    io::change_password(&vault_path, &old_password, &new_password).map_err(plain_err)
}

/// `recover`：恢复码恢复——验证旧恢复码、强制轮换并返回新恢复码（只显示
/// 这一次）。恢复码通道不解锁会话，恢复完成后仍需主密码或新恢复码解锁
/// （CLI `recover` 同语义）。
#[tauri::command]
pub fn recover(state: State<'_, Mutex<Session>>, old_code: String) -> Result<String, AppError> {
    let vault_path = with_session(&state, |s| Ok(s.vault_path().to_path_buf()))?;
    io::recover(&vault_path, &old_code).map_err(plain_err)
}

/// 落盘共享段：持文件锁短持（不与会话互斥锁嵌套）写入正文。
fn persist_locked(
    path: &std::path::Path,
    key: &VaultKey,
    body: &VaultBody,
) -> Result<(), SessionError> {
    let _lock = VaultLock::acquire(path).map_err(|e| match e {
        two_fa_core::vault::LockError::Busy { pid } => SessionError::Other(format!(
            "另一个 2FA 进程（PID {pid}）正在编辑此保险库，请稍后再试"
        )),
        two_fa_core::vault::LockError::Io(err) => {
            SessionError::Other(format!("文件锁操作失败：{err}"))
        }
    })?;
    entries::save(path, key, body).map_err(map_entry_err)
}

/// 待提交区令牌：进程内单调递增（防陈旧预览错配）。
fn next_token() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static TOKEN: AtomicU64 = AtomicU64::new(1);
    TOKEN.fetch_add(1, Ordering::Relaxed)
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
