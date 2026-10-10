//! 2FA 桌面 GUI 的 Tauri 壳。
//!
//! 本 crate 只负责窗口创建、路径解析与会话编排；全部业务逻辑在 `two-fa-core`，
//! 时钟与路径等上下文由本壳层解析后传入（core 零环境感知的边界不变）。
//! release 构建隐藏控制台窗口；devtools 特性未启用，release 天然禁用。
//! 日志仅走 stderr，遵守脱敏规范（不记录密码、密钥与 otpauth 载荷）。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod add;
mod clipboard;
mod commands;
mod paths;
mod session;

use std::sync::Mutex;
use std::time::Duration;

use two_fa_core::vault::{MemoryLockStatus, try_lock_memory};

use crate::paths::Env;

/// 空闲超时默认值：5 分钟，与 CLI 同语义（PRD §10.2）。
const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 300;

fn main() {
    // 尽力而为内存锁（ADR-0005）：失败仅警告，不得拒绝服务
    match try_lock_memory() {
        MemoryLockStatus::Unsupported => {
            eprintln!("警告：当前环境不支持内存锁页，密钥内存保护以零化为准")
        }
    }
    if let Err(err) = run() {
        eprintln!("2FA 验证器启动失败：{err}");
        std::process::exit(1);
    }
}

/// 空闲超时（秒）：环境变量 `TWO_FA_IDLE_TIMEOUT` 可覆盖，非法取值警告后用默认。
fn idle_timeout() -> Duration {
    match std::env::var("TWO_FA_IDLE_TIMEOUT") {
        Ok(v) => v.parse::<u64>().map_or_else(
            |_| {
                eprintln!("警告：TWO_FA_IDLE_TIMEOUT 应为整数秒，收到「{v}」，使用默认 300 秒");
                Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS)
            },
            Duration::from_secs,
        ),
        Err(_) => Duration::from_secs(DEFAULT_IDLE_TIMEOUT_SECS),
    }
}

/// 采集系统环境值供路径解析（壳层职责；core 不读环境变量）。
fn system_env() -> Env {
    Env {
        cwd: std::env::current_dir().unwrap_or_default(),
        #[cfg(windows)]
        appdata: std::env::var_os("APPDATA").map(std::path::PathBuf::from),
        #[cfg(not(windows))]
        xdg_data_home: std::env::var_os("XDG_DATA_HOME").map(std::path::PathBuf::from),
        #[cfg(not(windows))]
        home: std::env::var_os("HOME").map(std::path::PathBuf::from),
    }
}

fn run() -> Result<(), String> {
    let vault = paths::resolve(&system_env()).map_err(|e| e.to_string())?;
    // 每条命令回显保险库路径是 CLI 的防呆纪律；GUI 在启动时向 stderr 回显一次，
    // 并通过 status 命令随时可查
    eprintln!(
        "保险库：{}（{}）",
        vault.path.display(),
        vault.source.label()
    );

    let session = session::Session::new(vault, idle_timeout());
    tauri::Builder::default()
        .manage(Mutex::new(session))
        .manage(clipboard::ClipboardCleaner::system())
        .invoke_handler(tauri::generate_handler![
            commands::unlock,
            commands::lock,
            commands::check_idle,
            commands::status,
            commands::list_entries,
            commands::get_code,
            commands::copy_code,
            commands::add_preview,
            commands::add_commit,
        ])
        .run(tauri::generate_context!())
        .map_err(|e| e.to_string())
}
