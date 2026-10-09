//! 2FA 命令行工具入口：参数解析、路径解析、命令分发。
//!
//! 每条命令都必须回显当前保险库的绝对路径与来源；
//! stdout 只放命令输出，错误与日志走 stderr（退出码：成功 0，失败非 0）。

mod commands;
mod error;
mod logging;
mod paths;
mod repl;
mod session;

use std::io::{IsTerminal as _, Write as _};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use error::CliError;
use two_fa_core::usecase;
use two_fa_core::vault::atomic_write;

/// 2FA：完全离线的 TOTP 两步验证命令行工具
#[derive(Parser)]
#[command(name = "2fa", version, about = "完全离线的 TOTP 两步验证命令行工具")]
struct Cli {
    /// 保险库文件路径（默认：当前目录 .2fa/vault.json，其次平台惯例路径）
    #[arg(long, global = true, value_name = "路径")]
    vault: Option<PathBuf>,

    /// 从 stdin 第一行读取主密码（供脚本与管道使用）
    #[arg(long, global = true)]
    stdin_password: bool,

    /// 交互模式空闲超时（分钟，默认 5；超时自动锁定并清零内存）
    #[arg(long, global = true, value_name = "分钟", default_value_t = 5)]
    idle_timeout: u64,

    /// 日志级别：DEBUG / INFO / ERROR（默认 INFO；RUST_LOG 环境变量优先于本参数）
    #[arg(long, global = true, value_name = "级别", default_value = "info")]
    log_level: String,

    /// 日志写入平台日志目录并按日轮转（默认仅 stderr，不落盘）
    #[arg(long, global = true)]
    log_to_file: bool,

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
    /// 显示保险库路径、来源、条目数量与 KDF 版本（需解锁）
    Status,
    /// 列出全部条目（服务商、账号、当前验证码、剩余秒数）
    List,
    /// 按服务商 / 账号 / 标签模糊搜索条目（不区分大小写）
    Find {
        /// 搜索关键词
        query: String,
    },
    /// 添加条目
    Add {
        /// 服务商名
        issuer: String,
        /// 账号名
        account: String,
        /// Base32 密钥
        secret: String,
        /// 算法：SHA1 / SHA256 / SHA512（缺省 SHA1）
        #[arg(long)]
        algorithm: Option<String>,
        /// 验证码位数（缺省 6）
        #[arg(long)]
        digits: Option<u8>,
        /// 周期秒数（缺省 30）
        #[arg(long)]
        period: Option<u32>,
        /// 逗号分隔的标签
        #[arg(long)]
        tags: Option<String>,
        /// 已有同标识条目时覆盖之
        #[arg(long)]
        overwrite: bool,
        /// 已有同标识条目时并存保留（与 --overwrite 互斥）
        #[arg(long, conflicts_with = "overwrite")]
        keep_both: bool,
    },
    /// 更新条目字段（仅给出的字段会被修改）
    Edit {
        /// 条目 ID 前缀
        prefix: String,
        /// 新服务商名
        #[arg(long)]
        issuer: Option<String>,
        /// 新账号名
        #[arg(long)]
        account: Option<String>,
        /// 新 Base32 密钥
        #[arg(long)]
        secret: Option<String>,
        /// 新算法：SHA1 / SHA256 / SHA512
        #[arg(long)]
        algorithm: Option<String>,
        /// 新位数
        #[arg(long)]
        digits: Option<u8>,
        /// 新周期秒数
        #[arg(long)]
        period: Option<u32>,
        /// 新标签（整组替换）
        #[arg(long)]
        tags: Option<String>,
    },
    /// 删除条目（交互确认，或 --yes 跳过确认）
    Del {
        /// 条目 ID 前缀
        prefix: String,
        /// 跳过确认（非交互环境必须）
        #[arg(long, short)]
        yes: bool,
    },
    /// 显示条目详情与明文密钥（交互确认，或 --yes 跳过确认）
    Show {
        /// 条目 ID 前缀
        prefix: String,
        /// 跳过确认（非交互环境必须）
        #[arg(long, short)]
        yes: bool,
    },
    /// 忘记主密码：交互输入恢复码解锁并强制轮换新恢复码
    Recover,
    /// 导入条目（自动识别 otpauth 文本 / GA 迁移 / 加密备份）
    Import {
        /// 导入文件路径
        file: PathBuf,
        /// 同标识不同密钥时覆盖既有条目（非交互必须显式选择）
        #[arg(long)]
        overwrite: bool,
        /// 同标识不同密钥时并存保留（非交互必须显式选择）
        #[arg(long)]
        keep_both: bool,
    },
    /// 日志管理
    Logs {
        #[command(subcommand)]
        action: LogsAction,
    },
    /// 基准测试：KDF 派生（含 Argon2id）与单次 TOTP 计算耗时
    Bench,
}

/// 日志管理子命令。
#[derive(Subcommand)]
enum LogsAction {
    /// 清理超过保留期（7 天）的日志文件
    Purge,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("错误：{err}");
            ExitCode::from(err.exit_code())
        }
    }
}

fn run(cli: &Cli) -> Result<(), CliError> {
    init_logging(cli)?;
    log::info!("2fa 已启动（版本 {}）", env!("CARGO_PKG_VERSION"));
    warn_memory_lock();
    let env = collect_env()?;
    match &cli.command {
        Some(Command::Init { project }) => {
            cmd_init(*project, cli.vault.clone(), &env).map_err(CliError::from)
        }
        Some(Command::Status) => {
            let resolved = paths::resolve(cli.vault.clone(), &env)?;
            commands::cmd_status(&resolved, cli.stdin_password)
        }
        Some(Command::List) => {
            let resolved = paths::resolve(cli.vault.clone(), &env)?;
            commands::cmd_list(&resolved, cli.stdin_password)
        }
        Some(Command::Find { query }) => {
            let resolved = paths::resolve(cli.vault.clone(), &env)?;
            commands::cmd_find(&resolved, cli.stdin_password, query)
        }
        Some(Command::Add {
            issuer,
            account,
            secret,
            algorithm,
            digits,
            period,
            tags,
            overwrite,
            keep_both,
        }) => {
            let resolved = paths::resolve(cli.vault.clone(), &env)?;
            let mut args = commands::AddArgs {
                issuer: issuer.clone(),
                account: account.clone(),
                secret: secret.clone(),
                algorithm: algorithm.clone(),
                digits: *digits,
                period: *period,
                tags: tags.clone(),
                overwrite: *overwrite,
                keep_both: *keep_both,
            };
            let interactive = std::io::stdin().is_terminal();
            commands::cmd_add(&resolved, cli.stdin_password, &mut args, interactive)
        }
        Some(Command::Edit {
            prefix,
            issuer,
            account,
            secret,
            algorithm,
            digits,
            period,
            tags,
        }) => {
            let resolved = paths::resolve(cli.vault.clone(), &env)?;
            let args = commands::EditArgs {
                issuer: issuer.clone(),
                account: account.clone(),
                secret: secret.clone(),
                algorithm: algorithm.clone(),
                digits: *digits,
                period: *period,
                tags: tags.clone(),
            };
            commands::cmd_edit(&resolved, cli.stdin_password, prefix, &args)
        }
        Some(Command::Del { prefix, yes }) => {
            let resolved = paths::resolve(cli.vault.clone(), &env)?;
            let interactive = std::io::stdin().is_terminal();
            commands::cmd_del(&resolved, cli.stdin_password, prefix, *yes, interactive)
        }
        Some(Command::Show { prefix, yes }) => {
            let resolved = paths::resolve(cli.vault.clone(), &env)?;
            let interactive = std::io::stdin().is_terminal();
            commands::cmd_show(&resolved, cli.stdin_password, prefix, *yes, interactive)
        }
        Some(Command::Recover) => {
            let resolved = paths::resolve(cli.vault.clone(), &env)?;
            commands::cmd_recover(&resolved)
        }
        Some(Command::Import {
            file,
            overwrite,
            keep_both,
        }) => {
            let resolved = paths::resolve(cli.vault.clone(), &env)?;
            let interactive = std::io::stdin().is_terminal();
            commands::cmd_import(
                &resolved,
                cli.stdin_password,
                file,
                *overwrite,
                *keep_both,
                interactive,
            )
        }
        Some(Command::Logs { action }) => match action {
            LogsAction::Purge => commands::cmd_logs_purge(resolve_log_dir()),
        },
        Some(Command::Bench) => commands::cmd_bench(),
        None => {
            let resolved = paths::resolve(cli.vault.clone(), &env)?;
            let idle_timeout = std::time::Duration::from_secs(cli.idle_timeout * 60);
            repl::run(&resolved, idle_timeout).map_err(CliError::from)
        }
    }
}

/// 初始化日志：`RUST_LOG`（合法值）优先于 `--log-level`，默认 INFO；
/// 默认仅 stderr 不落盘，`--log-to-file` 显式开启平台日志目录写入。
fn init_logging(cli: &Cli) -> Result<(), CliError> {
    let level_text = std::env::var("RUST_LOG")
        .ok()
        .filter(|value| logging::parse_level(value).is_some())
        .unwrap_or_else(|| cli.log_level.clone());
    let level = logging::parse_level(&level_text).unwrap_or(log::LevelFilter::Info);
    let dir = if cli.log_to_file {
        Some(resolve_log_dir().ok_or_else(|| {
            CliError::Generic(
                "无法确定平台日志目录（缺少 LOCALAPPDATA / XDG_STATE_HOME / HOME 环境变量）"
                    .to_string(),
            )
        })?)
    } else {
        None
    };
    logging::init(level, cli.log_to_file, dir).map_err(CliError::Generic)
}

/// 解析平台日志目录（core 不读环境变量，采集归 CLI）。
fn resolve_log_dir() -> Option<PathBuf> {
    let localappdata = std::env::var("LOCALAPPDATA").ok();
    let xdg_state = std::env::var("XDG_STATE_HOME").ok();
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok();
    logging::platform_log_dir(
        localappdata.as_deref(),
        xdg_state.as_deref(),
        home.as_deref(),
    )
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
