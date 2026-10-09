//! 交互式 REPL（`2fa` 不带子命令时进入）。
//!
//! - `rustyline` 驱动，提示符 `2fa> `
//! - 启动时处于锁定状态，`unlock` 输入主密码后持有主密钥
//! - `lock` 立即锁定（密钥 `drop` 清零）；空闲超时自动锁定
//! - Ctrl-C / Ctrl-D / `exit` 退出进程，`Drop` 无条件归零
//!
//! 每条命令输出都回显保险库路径（`docs/adr/0004`）。

use std::time::Duration;

use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use two_fa_core::vault::{UnlockError, UpgradeOutcome, unlock};

use crate::paths::ResolvedVault;
use crate::session::Session;

/// 单条命令的处理结果。
enum Flow {
    /// 继续下一轮。
    Continue,
    /// 退出 REPL。
    Exit,
}

/// 运行 REPL，正常退出返回 `Ok(())`。
pub fn run(vault: &ResolvedVault, idle_timeout: Duration) -> Result<(), String> {
    let mut rl = DefaultEditor::new().map_err(|e| format!("初始化交互输入失败：{e}"))?;
    let mut session = Session::new(idle_timeout);

    println!("2FA 两步验证器（完全离线）");
    println!("保险库：{}", vault.path.display());
    println!("来源：{}", vault.source.label());
    println!("输入 help 查看可用命令。");

    loop {
        if session.check_idle() {
            println!("已因空闲超时自动锁定。");
        }
        match rl.readline("2fa> ") {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(line);
                match dispatch(&mut session, line, vault)? {
                    Flow::Continue => {}
                    Flow::Exit => break,
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl-C：退出，密钥随进程结束经 Drop 归零
                println!();
                break;
            }
            Err(ReadlineError::Eof) => {
                println!();
                break;
            }
            Err(err) => return Err(format!("读取输入失败：{err}")),
        }
    }
    println!("再见。");
    Ok(())
}

/// 解析并执行一条 REPL 命令。
fn dispatch(session: &mut Session, line: &str, vault: &ResolvedVault) -> Result<Flow, String> {
    let mut parts = line.split_whitespace();
    let cmd = parts.next().unwrap_or("");
    match cmd {
        "help" | "?" => {
            print_help();
        }
        "lock" => {
            if session.lock() {
                println!("已锁定，密钥已从内存清零。");
            } else {
                println!("当前已是锁定状态。");
            }
        }
        "unlock" => {
            cmd_unlock(session, vault)?;
        }
        "status" => {
            echo_vault(vault);
            println!(
                "状态：{}",
                if session.is_unlocked() {
                    "已解锁"
                } else {
                    "已锁定"
                }
            );
        }
        "exit" | "quit" | "q" => return Ok(Flow::Exit),
        _ => {
            echo_vault(vault);
            println!("未知命令：{cmd}。输入 help 查看可用命令。");
        }
    }
    Ok(Flow::Continue)
}

/// `unlock`：输入主密码解锁保险库。
fn cmd_unlock(session: &mut Session, vault: &ResolvedVault) -> Result<(), String> {
    if session.is_unlocked() {
        echo_vault(vault);
        println!("当前已是解锁状态。");
        return Ok(());
    }
    let password =
        rpassword::prompt_password("主密码：").map_err(|e| format!("读取密码失败：{e}"))?;
    match unlock(&vault.path, &password) {
        Ok((key, outcome)) => {
            session.unlock(key);
            echo_vault(vault);
            println!("已解锁。");
            match outcome {
                UpgradeOutcome::NotNeeded => {}
                UpgradeOutcome::Upgraded => println!("封套 KDF 已自动升级到当前版本。"),
                UpgradeOutcome::Failed(err) => {
                    eprintln!("警告：KDF 自动升级失败（不影响本次使用）：{err}")
                }
            }
            Ok(())
        }
        Err(UnlockError::AuthFailed) => {
            eprintln!("认证失败：密码或恢复码错误。");
            Ok(())
        }
        Err(err) => Err(err.to_string()),
    }
}

/// 回显保险库路径（每条命令都必须）。
fn echo_vault(vault: &ResolvedVault) {
    println!("保险库：{}", vault.path.display());
}

/// 帮助信息。
fn print_help() {
    println!("可用命令：");
    println!("  unlock  解锁保险库（输入主密码或恢复码）");
    println!("  lock    立即锁定并清零内存中的密钥");
    println!("  status  显示保险库路径与锁定状态");
    println!("  exit    退出（或 Ctrl-D / Ctrl-C）");
}
