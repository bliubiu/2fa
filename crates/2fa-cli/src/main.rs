//! 2FA 命令行工具入口：参数解析、路径解析、命令分发。
//!
//! 每条命令都必须回显当前保险库的绝对路径与来源；
//! stdout 只放命令输出，错误与日志走 stderr（退出码：成功 0，失败非 0）。

mod paths;
mod repl;
mod session;

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use two_fa_core::usecase;
use two_fa_core::vault::atomic_write;

/// 2FA：完全离线的 TOTP 两步验证命令行工具
#[derive(Parser)]
#[command(name = "2fa", version, about = "完全离线的 TOTP 两步验证命令行工具")]
struct Cli {
    /// 保险库文件路径（默认：当前目录 .2fa/vault.json，其次平台惯例路径）
    #[arg(long, global = true, value_name = "路径")]
    vault: Option<PathBuf>,

    /// 交互模式空闲超时（分钟，默认 5；超时自动锁定并清零内存）
    #[arg(long, global = true, value_name = "分钟", default_value_t = 5)]
    idle_timeout: u64,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// 创建新保险库并执行首次设置：主密码 → 恢复码 → 首份加密备份
    Init {
        /// 在当前目录创建项目保险库 .2fa/vault.json
        #[arg(long)]
        project: bool,
    },
    /// 显示当前保险库路径与来源
    Status,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("错误：{err}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: &Cli) -> Result<(), String> {
    warn_memory_lock();
    let env = collect_env()?;
    match &cli.command {
        Some(Command::Init { project }) => cmd_init(*project, cli.vault.clone(), &env),
        Some(Command::Status) => {
            let resolved = paths::resolve(cli.vault.clone(), &env).map_err(|e| e.to_string())?;
            println!("保险库：{}", resolved.path.display());
            println!("来源：{}", resolved.source.label());
            Ok(())
        }
        None => {
            let resolved = paths::resolve(cli.vault.clone(), &env).map_err(|e| e.to_string())?;
            let idle_timeout = std::time::Duration::from_secs(cli.idle_timeout * 60);
            repl::run(&resolved, idle_timeout)
        }
    }
}

/// 内存锁尽力而为：当前构建不支持时向 stderr 输出中文警告后继续
/// （`docs/adr/0005`——锁页失败不得导致拒绝服务）。
fn warn_memory_lock() {
    if two_fa_core::vault::try_lock_memory() == two_fa_core::vault::MemoryLockStatus::Unsupported {
        eprintln!(
            "警告：当前环境不支持内存锁页，密钥在内存中可能被换出到交换区；\
             密钥使用后即清零，风险已尽可能降低。"
        );
    }
}

/// 采集路径解析所需的环境值（core 不读环境变量，采集归 CLI）。
fn collect_env() -> Result<paths::Env, String> {
    let cwd = std::env::current_dir().map_err(|e| format!("读取当前目录失败：{e}"))?;
    #[cfg(windows)]
    {
        Ok(paths::Env {
            cwd,
            appdata: std::env::var("APPDATA").ok().map(PathBuf::from),
        })
    }
    #[cfg(not(windows))]
    {
        Ok(paths::Env {
            cwd,
            xdg_data_home: std::env::var("XDG_DATA_HOME").ok().map(PathBuf::from),
            home: std::env::var("HOME")
                .or_else(|_| std::env::var("USERPROFILE"))
                .ok()
                .map(PathBuf::from),
        })
    }
}

/// `2fa init [--project]`：创建新保险库并执行首次设置。
///
/// 流程：目标路径检查 → 创建目录 → 设置主密码 → 生成并打印恢复码 →
/// 写入保险库 → 生成首份加密备份 → 强制确认已保存。
fn cmd_init(project: bool, vault_arg: Option<PathBuf>, env: &paths::Env) -> Result<(), String> {
    let explicit = vault_arg.is_some();
    let target = paths::init_target(vault_arg, project, env).map_err(|e| e.to_string())?;
    if target.exists() {
        return Err(format!(
            "保险库已存在：{}，拒绝重复初始化",
            target.display()
        ));
    }

    // 创建目录；首次在 CWD 创建 .2fa/ 时显式提示
    if let Some(parent) = target.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| format!("创建目录失败：{e}"))?;
            if parent == env.cwd.join(paths::PROJECT_DIR) {
                println!("已在本目录创建项目保险库");
            }
        }
    }

    let password = prompt_master_password()?;
    let recovery = usecase::recovery::generate().map_err(|e| e.to_string())?;
    let created_at = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("系统时钟异常：{e}"))?
        .as_secs();
    let bytes = usecase::init::create_vault(
        &password,
        &usecase::recovery::normalize(&recovery),
        created_at,
    )
    .map_err(|e| e.to_string())?;

    atomic_write(&target, &bytes).map_err(|e| format!("写入保险库失败：{e}"))?;

    // 首份加密备份：保险库文件的字节级拷贝
    let backup = backup_target(&target);
    atomic_write(&backup, &bytes).map_err(|e| format!("写入加密备份失败：{e}"))?;

    let source = if explicit {
        paths::VaultSource::Explicit
    } else if project {
        paths::VaultSource::Project
    } else {
        paths::VaultSource::Platform
    };
    println!("保险库已创建：{}", target.display());
    println!("来源：{}", source.label());
    println!("首份加密备份：{}", backup.display());
    println!();
    println!("════════════════════════════════════════════");
    println!("恢复码（丢失主密码时的唯一恢复手段，");
    println!("请抄写到纸上并妥善保存，不要存入联网设备）：");
    println!();
    println!("    {recovery}");
    println!();
    println!("════════════════════════════════════════════");

    // 强制确认：未确认已保存不允许结束初始化
    loop {
        print!("确认已保存恢复码与备份文件？（输入 yes 继续）：");
        std::io::stdout()
            .flush()
            .map_err(|e| format!("输出失败：{e}"))?;
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(|e| format!("读取输入失败：{e}"))?;
        match answer.trim() {
            "yes" | "y" | "Y" | "是" => break,
            _ => println!("未确认保存前无法完成初始化，恢复码只显示这一次。"),
        }
    }
    println!("初始化完成。");
    Ok(())
}

/// 交互式设置主密码：非空且两次一致，否则重试。
fn prompt_master_password() -> Result<String, String> {
    loop {
        let first =
            rpassword::prompt_password("设置主密码：").map_err(|e| format!("读取密码失败：{e}"))?;
        if first.is_empty() {
            println!("主密码不能为空。");
            continue;
        }
        let second = rpassword::prompt_password("再次输入主密码：")
            .map_err(|e| format!("读取密码失败：{e}"))?;
        if first != second {
            println!("两次输入不一致，请重试。");
            continue;
        }
        return Ok(first);
    }
}

/// 加密备份路径：`<保险库文件名>.backup`。
fn backup_target(vault: &std::path::Path) -> PathBuf {
    let mut name = vault
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".backup");
    vault.with_file_name(name)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// 备份路径命名：vault.json → vault.json.backup。
    #[test]
    fn 备份路径命名() {
        assert_eq!(
            backup_target(std::path::Path::new("D:/x/vault.json")),
            std::path::Path::new("D:/x/vault.json.backup")
        );
    }
}
