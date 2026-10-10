//! 2FA 桌面 GUI 的 Tauri 壳。
//!
//! 本 crate 只负责窗口创建与前后端通信编排；全部业务逻辑在 `two-fa-core`，
//! 保险库路径等上下文由壳层解析后传入（core 零环境感知的边界不变）。
//! release 构建隐藏控制台窗口；devtools 特性未启用，release 天然禁用。

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Err(err) = run() {
        eprintln!("2FA 验证器启动失败：{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), tauri::Error> {
    tauri::Builder::default().run(tauri::generate_context!())
}
