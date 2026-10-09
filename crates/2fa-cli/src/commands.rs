//! 单次命令模式：凭据读取、解锁、加载保险库正文。
//!
//! 每条子命令独立进程执行：本模块提供命令共用的「解锁 + 加载」流程，
//! 命令结束进程退出，主密钥随 `Drop` 清零。
//!
//! stdout 纪律：stdout 只放命令输出（可被管道解析）；
//! 警告与日志一律走 stderr。

use std::io::{IsTerminal as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use two_fa_core::domain::totp::{self, Algorithm};
use two_fa_core::importexport::otpauth_text::{self, BatchItem};
use two_fa_core::usecase::entries::{self, EntryOpError};
use two_fa_core::usecase::recovery;
use two_fa_core::vault::{
    Entry, LockError, RotateError, SecretKey, UnlockError, UpgradeOutcome, VaultBody, VaultKey,
    VaultLock, load_and_migrate, rotate_recovery, unlock,
};

use crate::error::CliError;
use crate::paths::ResolvedVault;

/// 读取凭据并解锁保险库，返回主密钥。
///
/// 凭据来源：`--stdin-password` 时读 stdin 第一行（供脚本与管道使用，
/// 只去除行尾换行，保留密码本身的空格）；否则交互式提示输入。
pub fn unlock_once(vault: &ResolvedVault, stdin_password: bool) -> Result<VaultKey, CliError> {
    if !vault.path.is_file() {
        return Err(CliError::Generic(format!(
            "保险库文件不存在：{}（可先运行 2fa init 创建）",
            vault.path.display()
        )));
    }
    let password = if stdin_password {
        read_stdin_password()?
    } else if std::io::stdin().is_terminal() {
        rpassword::prompt_password("主密码：")
            .map_err(|e| CliError::Generic(format!("读取密码失败：{e}")))?
    } else {
        // 非交互环境（管道/脚本）下没有可用的密码来源，立即报错而非挂起等待
        return Err(CliError::Generic(
            "没有可用的密码来源：非交互环境请使用 --stdin-password".to_string(),
        ));
    };

    match unlock(&vault.path, &password) {
        Ok((key, outcome)) => {
            log::info!("保险库已解锁");
            match outcome {
                UpgradeOutcome::NotNeeded => {}
                UpgradeOutcome::Upgraded => log::info!("封套 KDF 已自动升级到当前版本"),
                UpgradeOutcome::Failed(err) => {
                    eprintln!("警告：KDF 自动升级失败（不影响本次使用）：{err}");
                    log::error!("KDF 自动升级失败（不影响本次使用）：{err}");
                }
            }
            Ok(key)
        }
        Err(UnlockError::AuthFailed) => Err(CliError::AuthFailed),
        Err(err) => Err(CliError::Generic(err.to_string())),
    }
}

/// 从 stdin 读取第一行作为密码（只去除行尾换行符）。
fn read_stdin_password() -> Result<String, CliError> {
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| CliError::Generic(format!("读取 stdin 失败：{e}")))?;
    let password = line.trim_end_matches(['\r', '\n']).to_string();
    if password.is_empty() {
        return Err(CliError::Generic(
            "--stdin-password 收到空密码，请通过管道传入主密码".to_string(),
        ));
    }
    Ok(password)
}

/// 解锁并加载保险库正文（含 schema 迁移）。
pub fn load_unlocked(
    vault: &ResolvedVault,
    stdin_password: bool,
) -> Result<(VaultKey, VaultBody), CliError> {
    let key = unlock_once(vault, stdin_password)?;
    let body = load_and_migrate(&vault.path, &key)
        .map_err(|e| CliError::Generic(format!("加载保险库失败：{e}")))?
        .0;
    Ok((key, body))
}

/// `status`：显示路径、来源、条目数量、封套 KDF 版本（需解锁）。
pub fn cmd_status(vault: &ResolvedVault, stdin_password: bool) -> Result<(), CliError> {
    let (_key, body) = load_unlocked(vault, stdin_password)?;
    echo_vault(vault);
    println!("来源：{}", vault.source.label());
    println!("条目数量：{}", body.entries.len());
    println!("封套 KDF 版本：{}", kdf_versions(vault)?);
    Ok(())
}

/// 汇总封套的 KDF 版本（去重后升序，逗号分隔）。
fn kdf_versions(vault: &ResolvedVault) -> Result<String, CliError> {
    use two_fa_core::vault::{VaultFile, kdf_params};
    let raw = std::fs::read(&vault.path)
        .map_err(|e| CliError::Generic(format!("读取保险库文件失败：{e}")))?;
    let file =
        VaultFile::parse(&raw).map_err(|e| CliError::Generic(format!("保险库格式错误：{e}")))?;
    let mut versions = file
        .envelopes
        .iter()
        .map(|env| env.kdf_version)
        .collect::<Vec<_>>();
    versions.sort_unstable();
    versions.dedup();
    // 校验版本可解析（当前实现不支持的历史版本在此暴露）
    for v in &versions {
        if let Err(err) = kdf_params(*v) {
            return Err(CliError::Generic(format!(
                "封套 KDF 版本 {v} 无法解析：{err}"
            )));
        }
    }
    Ok(versions
        .iter()
        .map(|v| format!("v{v}"))
        .collect::<Vec<_>>()
        .join("、"))
}

/// 回显保险库路径（每条命令都必须）。
pub fn echo_vault(vault: &ResolvedVault) {
    println!("保险库：{}", vault.path.display());
}

// ---------------------------------------------------------------------------
// 条目 CRUD 与展示（M3-4）
// ---------------------------------------------------------------------------

/// 当前 Unix 秒。
fn now_unix() -> Result<u64, CliError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| CliError::Generic(format!("系统时钟异常：{e}")))
}

/// 当前验证码（十进制按位数补零）；密钥解码失败时返回 None。
fn current_code(entry: &Entry, now: u64) -> Option<String> {
    let bytes = entry.secret.to_bytes().ok()?;
    let counter = now / u64::from(entry.period);
    let code = totp::compute(&bytes, counter, entry.algorithm, entry.digits).ok()?;
    Some(format!("{code:0width$}", width = usize::from(entry.digits)))
}

/// 当前周期剩余秒数。
fn remaining_secs(entry: &Entry, now: u64) -> u64 {
    u64::from(entry.period) - now % u64::from(entry.period)
}

/// 列表行：id 前 8 位、服务商、账号、当前验证码、剩余秒数。
fn list_row(entry: &Entry, now: u64) -> String {
    let id8 = entry.id.to_string()[..8].to_string();
    let code = current_code(entry, now).unwrap_or_else(|| "错误".to_string());
    format!(
        "{id8}  {:<16}  {:<24}  {:>6}  {:>3}s",
        entry.issuer,
        entry.account,
        code,
        remaining_secs(entry, now)
    )
}

/// 交互确认（读取一行，`yes`/`y`/`是` 视为确认）。
fn confirm(prompt: &str) -> Result<bool, CliError> {
    print!("{prompt}");
    std::io::stdout()
        .flush()
        .map_err(|e| CliError::Generic(format!("输出失败：{e}")))?;
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .map_err(|e| CliError::Generic(format!("读取输入失败：{e}")))?;
    Ok(matches!(line.trim(), "yes" | "y" | "Y" | "是"))
}

/// `list`：全部条目（服务商、账号、当前验证码、剩余秒数）。
pub fn cmd_list(vault: &ResolvedVault, stdin_password: bool) -> Result<(), CliError> {
    let (_key, body) = load_unlocked(vault, stdin_password)?;
    op_list(vault, &body)
}

/// 共享操作：全部条目列表（供 REPL 复用已解锁的会话）。
pub fn op_list(vault: &ResolvedVault, body: &VaultBody) -> Result<(), CliError> {
    echo_vault(vault);
    if body.entries.is_empty() {
        println!("保险库为空，使用 2fa add 添加条目。");
        return Ok(());
    }
    let now = now_unix()?;
    println!(
        "{:<8}  {:<16}  {:<24}  {:>6}  剩余",
        "ID", "服务商", "账号", "验证码"
    );
    for entry in &body.entries {
        println!("{}", list_row(entry, now));
    }
    Ok(())
}

/// `find <关键词>`：按服务商 / 账号 / 标签模糊搜索（不区分大小写）。
pub fn cmd_find(vault: &ResolvedVault, stdin_password: bool, query: &str) -> Result<(), CliError> {
    let (_key, body) = load_unlocked(vault, stdin_password)?;
    op_find(vault, &body, query)
}

/// 共享操作：模糊搜索（供 REPL 复用）。
pub fn op_find(vault: &ResolvedVault, body: &VaultBody, query: &str) -> Result<(), CliError> {
    echo_vault(vault);
    let needle = query.to_lowercase();
    let hits: Vec<&Entry> = body
        .entries
        .iter()
        .filter(|e| {
            e.issuer.to_lowercase().contains(&needle)
                || e.account.to_lowercase().contains(&needle)
                || e.tags.iter().any(|t| t.to_lowercase().contains(&needle))
        })
        .collect();
    if hits.is_empty() {
        println!("没有匹配「{query}」的条目。");
        return Ok(());
    }
    let now = now_unix()?;
    println!(
        "{:<8}  {:<16}  {:<24}  {:>6}  剩余",
        "ID", "服务商", "账号", "验证码"
    );
    for entry in hits {
        println!("{}", list_row(entry, now));
    }
    Ok(())
}

/// `add` 参数（由 clap 组装）。
#[derive(Debug, Default)]
pub struct AddArgs {
    /// 服务商名。
    pub issuer: String,
    /// 账号名。
    pub account: String,
    /// Base32 密钥。
    pub secret: String,
    /// 算法（缺省 SHA1）。
    pub algorithm: Option<String>,
    /// 位数（缺省 6）。
    pub digits: Option<u8>,
    /// 周期秒（缺省 30）。
    pub period: Option<u32>,
    /// 逗号分隔标签。
    pub tags: Option<String>,
    /// 同标识冲突时覆盖既有条目。
    pub overwrite: bool,
    /// 同标识冲突时并存保留。
    pub keep_both: bool,
}

/// 解析标签参数。
fn parse_tags(tags: Option<&str>) -> Vec<String> {
    tags.map(|t| {
        t.split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect()
    })
    .unwrap_or_default()
}

/// 解析算法参数（缺省 SHA1）。
fn parse_algorithm(algorithm: Option<&str>) -> Result<Algorithm, CliError> {
    match algorithm {
        None => Ok(Algorithm::Sha1),
        Some(text) => Algorithm::parse_label(text).ok_or_else(|| {
            CliError::Generic(format!("未知算法：{text}（可选 SHA1/SHA256/SHA512）"))
        }),
    }
}

/// `add`：添加条目；同标识冲突时按参数或交互选择处理。
pub fn cmd_add(
    vault: &ResolvedVault,
    stdin_password: bool,
    args: &mut AddArgs,
    interactive: bool,
) -> Result<(), CliError> {
    let (key, mut body) = load_unlocked(vault, stdin_password)?;
    op_add(vault, &key, &mut body, args, interactive)
}

/// 共享操作：添加条目（供 REPL 复用会话密钥与已加载正文）。
pub fn op_add(
    vault: &ResolvedVault,
    key: &VaultKey,
    body: &mut VaultBody,
    args: &mut AddArgs,
    interactive: bool,
) -> Result<(), CliError> {
    // 同标识冲突处理：覆盖 / 并存 / 取消
    let same = body.find_same_identity(&args.issuer, &args.account);
    if !same.is_empty() && !args.overwrite && !args.keep_both {
        if interactive {
            println!(
                "已存在 {} 条同标识条目（{}）：",
                same.len(),
                same.iter()
                    .map(|e| format!("{} / {}", e.issuer, e.account))
                    .collect::<Vec<_>>()
                    .join("；")
            );
            print!("选择：覆盖(o) / 并存保留(b) / 取消(c)？");
            std::io::stdout()
                .flush()
                .map_err(|e| CliError::Generic(format!("输出失败：{e}")))?;
            let mut line = String::new();
            std::io::stdin()
                .read_line(&mut line)
                .map_err(|e| CliError::Generic(format!("读取输入失败：{e}")))?;
            match line.trim() {
                "o" | "O" => args.overwrite = true,
                "b" | "B" => args.keep_both = true,
                _ => {
                    println!("已取消。");
                    return Ok(());
                }
            }
        } else {
            return Err(CliError::Generic(format!(
                "已存在 {} 条同标识条目（归一化后 {} / {}）。请显式选择：--overwrite 覆盖，或 --keep-both 并存保留",
                same.len(),
                args.issuer,
                args.account
            )));
        }
    }

    let secret = SecretKey::from_base32(&args.secret)
        .map_err(|e| CliError::Generic(format!("密钥无效：{e}")))?;
    let entry = Entry::new(
        args.issuer.clone(),
        args.account.clone(),
        secret,
        parse_algorithm(args.algorithm.as_deref())?,
        args.digits.unwrap_or(6),
        args.period.unwrap_or(30),
        parse_tags(args.tags.as_deref()),
    )
    .map_err(|e| CliError::Generic(e.to_string()))?;

    if args.overwrite && !same.is_empty() {
        let removed = same.len();
        body.entries.retain(|e| {
            let key = (entries_normalize(&e.issuer), entries_normalize(&e.account));
            let target = (
                entries_normalize(&args.issuer),
                entries_normalize(&args.account),
            );
            key != target
        });
        println!("已覆盖 {removed} 条同标识条目。");
    }
    let id8 = entry.id.to_string()[..8].to_string();
    body.entries.push(entry);

    // 变更类命令持文件锁读写
    let _lock = acquire_lock(vault)?;
    entries::save(&vault.path, key, body).map_err(map_entry_err)?;
    echo_vault(vault);
    log::info!(
        "已添加条目（ID 前缀 {id8}）：{} / {}",
        args.issuer,
        args.account
    );
    println!(
        "已添加条目（ID 前缀 {id8}）：{} / {}",
        args.issuer, args.account
    );
    Ok(())
}

/// 归一化（转发 core，避免 CLI 直接依赖内部路径的冗长书写）。
fn entries_normalize(text: &str) -> String {
    two_fa_core::vault::normalize_id(text)
}

/// 获取文件锁（变更类命令）。
fn acquire_lock(vault: &ResolvedVault) -> Result<VaultLock, CliError> {
    VaultLock::acquire(&vault.path).map_err(|e| match e {
        LockError::Busy { pid } => CliError::Generic(format!(
            "另一个 2FA 进程（PID {pid}）正在编辑此保险库，请稍后再试"
        )),
        LockError::Io(err) => CliError::Generic(format!("文件锁操作失败：{err}")),
    })
}

/// 条目操作错误 → CLI 错误。
fn map_entry_err(err: EntryOpError) -> CliError {
    CliError::Generic(err.to_string())
}

/// `edit` 参数（全部可选，仅更新给出的字段）。
#[derive(Debug, Default)]
pub struct EditArgs {
    /// 新服务商名。
    pub issuer: Option<String>,
    /// 新账号名。
    pub account: Option<String>,
    /// 新 Base32 密钥。
    pub secret: Option<String>,
    /// 新算法。
    pub algorithm: Option<String>,
    /// 新位数。
    pub digits: Option<u8>,
    /// 新周期秒。
    pub period: Option<u32>,
    /// 新标签（整组替换）。
    pub tags: Option<String>,
}

/// `edit <id前缀>`：更新条目字段。
pub fn cmd_edit(
    vault: &ResolvedVault,
    stdin_password: bool,
    prefix: &str,
    args: &EditArgs,
) -> Result<(), CliError> {
    let (key, mut body) = load_unlocked(vault, stdin_password)?;
    op_edit(vault, &key, &mut body, prefix, args)
}

/// 共享操作：更新条目字段（供 REPL 复用）。
pub fn op_edit(
    vault: &ResolvedVault,
    key: &VaultKey,
    body: &mut VaultBody,
    prefix: &str,
    args: &EditArgs,
) -> Result<(), CliError> {
    let idx = entries::find_index_by_prefix(body, prefix).map_err(map_entry_err)?;
    {
        let entry = &mut body.entries[idx];
        if let Some(issuer) = &args.issuer {
            entry.issuer = issuer.clone();
        }
        if let Some(account) = &args.account {
            entry.account = account.clone();
        }
        if let Some(secret) = &args.secret {
            entry.secret = SecretKey::from_base32(secret)
                .map_err(|e| CliError::Generic(format!("密钥无效：{e}")))?;
        }
        if let Some(algorithm) = &args.algorithm {
            entry.algorithm = parse_algorithm(Some(algorithm))?;
        }
        if let Some(digits) = args.digits {
            entry.digits = digits;
        }
        if let Some(period) = args.period {
            entry.period = period;
        }
        if let Some(tags) = &args.tags {
            entry.tags = parse_tags(Some(tags));
        }
        entry
            .validate()
            .map_err(|e| CliError::Generic(format!("修改后字段非法：{e}")))?;
    }

    let _lock = acquire_lock(vault)?;
    entries::save(&vault.path, key, body).map_err(map_entry_err)?;
    let entry = &body.entries[idx];
    echo_vault(vault);
    log::info!(
        "已更新条目（ID 前缀 {}）：{} / {}",
        &entry.id.to_string()[..8],
        entry.issuer,
        entry.account
    );
    println!(
        "已更新条目（ID 前缀 {}）：{} / {}",
        &entry.id.to_string()[..8],
        entry.issuer,
        entry.account
    );
    Ok(())
}

/// `del <id前缀>`：删除条目（需确认或 --yes）。
pub fn cmd_del(
    vault: &ResolvedVault,
    stdin_password: bool,
    prefix: &str,
    assume_yes: bool,
    interactive: bool,
) -> Result<(), CliError> {
    let (key, mut body) = load_unlocked(vault, stdin_password)?;
    op_del(vault, &key, &mut body, prefix, assume_yes, interactive)
}

/// 共享操作：删除条目（供 REPL 复用）。
pub fn op_del(
    vault: &ResolvedVault,
    key: &VaultKey,
    body: &mut VaultBody,
    prefix: &str,
    assume_yes: bool,
    interactive: bool,
) -> Result<(), CliError> {
    let idx = entries::find_index_by_prefix(body, prefix).map_err(map_entry_err)?;
    let (issuer, account, id8) = {
        let e = &body.entries[idx];
        (
            e.issuer.clone(),
            e.account.clone(),
            e.id.to_string()[..8].to_string(),
        )
    };

    if !assume_yes {
        if !interactive {
            return Err(CliError::Generic(
                "删除需要确认：非交互环境请加 --yes".to_string(),
            ));
        }
        echo_vault(vault);
        let confirmed = confirm(&format!(
            "将删除条目 {issuer} / {account}（ID 前缀 {id8}），确认？（yes）："
        ))?;
        if !confirmed {
            println!("已取消。");
            return Ok(());
        }
    }

    body.entries.remove(idx);
    let _lock = acquire_lock(vault)?;
    entries::save(&vault.path, key, body).map_err(map_entry_err)?;
    echo_vault(vault);
    log::info!("已删除条目 {issuer} / {account}（ID 前缀 {id8}）");
    println!("已删除条目 {issuer} / {account}（ID 前缀 {id8}）。");
    Ok(())
}

/// `show <id前缀>`：显示条目详情（含明文密钥，需确认或 --yes）。
pub fn cmd_show(
    vault: &ResolvedVault,
    stdin_password: bool,
    prefix: &str,
    assume_yes: bool,
    interactive: bool,
) -> Result<(), CliError> {
    let (_key, body) = load_unlocked(vault, stdin_password)?;
    op_show(vault, &body, prefix, assume_yes, interactive)
}

/// 共享操作：显示条目详情（供 REPL 复用）。
pub fn op_show(
    vault: &ResolvedVault,
    body: &VaultBody,
    prefix: &str,
    assume_yes: bool,
    interactive: bool,
) -> Result<(), CliError> {
    let idx = entries::find_index_by_prefix(body, prefix).map_err(map_entry_err)?;
    let entry = &body.entries[idx];

    if !assume_yes {
        if !interactive {
            return Err(CliError::Generic(
                "显示明文密钥需要确认：非交互环境请加 --yes".to_string(),
            ));
        }
        echo_vault(vault);
        let confirmed =
            confirm("即将在终端显示明文密钥（截图、录屏、旁观都会泄露），确认？（yes）：")?;
        if !confirmed {
            println!("已取消。");
            return Ok(());
        }
    }

    let now = now_unix()?;
    echo_vault(vault);
    println!("条目 {}：", entry.id);
    println!("  服务商：{}", entry.issuer);
    println!("  账号：{}", entry.account);
    println!(
        "  算法：{}  位数：{}  周期：{}s",
        entry.algorithm.label(),
        entry.digits,
        entry.period
    );
    if entry.tags.is_empty() {
        println!("  标签：（无）");
    } else {
        println!("  标签：{}", entry.tags.join("、"));
    }
    if let Some(code) = current_code(entry, now) {
        println!(
            "  当前验证码：{}（剩余 {}s）",
            code,
            remaining_secs(entry, now)
        );
    }
    println!("  密钥（明文）：{}", entry.secret.as_text());
    Ok(())
}

// ---------------------------------------------------------------------------
// watch 倒计时（M3-5）
// ---------------------------------------------------------------------------

/// 进程内单调时钟毫秒（基准为首次调用时刻，仅供 [`two_fa_core::usecase::watch::Ticker`] 使用）。
fn monotonic_ms() -> u64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    let base = BASE.get_or_init(Instant::now);
    base.elapsed().as_millis() as u64
}

/// watch 单行渲染：服务商 / 账号 / 当前验证码 / 剩余秒数（同一条目行宽恒定，
/// 回车重写不会残留旧字符）。密钥绝不进入此行。
fn watch_line(entry: &Entry, now: u64) -> Option<String> {
    let code = current_code(entry, now)?;
    Some(format!(
        "{} / {}  {}  剩余 {:>3}s（Ctrl-C 退出）",
        entry.issuer,
        entry.account,
        code,
        remaining_secs(entry, now)
    ))
}

/// watch 倒计时循环：回车原位刷新单行，Ctrl-C 退出。
///
/// 刷新点由 core 的 [`two_fa_core::usecase::watch::Ticker`] 以固定增量推进
/// （单调时钟对齐周期边界，唤醒误差不累积）；睡眠按至多 100ms 分段，
/// 保证 Ctrl-C 在一个分段内被响应。
pub fn op_watch(entry: &Entry) -> Result<(), CliError> {
    if !std::io::stdout().is_terminal() {
        return Err(CliError::Generic(
            "watch 需要交互终端（原位刷新输出，不支持重定向）".to_string(),
        ));
    }
    let stop = Arc::new(AtomicBool::new(false));
    let handler_stop = Arc::clone(&stop);
    ctrlc::set_handler(move || handler_stop.store(true, Ordering::Relaxed))
        .map_err(|e| CliError::Generic(format!("注册 Ctrl-C 处理失败：{e}")))?;

    let period = entry.period;
    let start_unix = now_unix()?;
    let mut ticker = two_fa_core::usecase::watch::Ticker::start(
        0,
        two_fa_core::usecase::watch::secs_to_boundary(start_unix, period) * 1000,
        period,
    );

    let mut last_rendered = String::new();
    // 首帧立即显示（否则启动后要等到第一个边界才有输出）；
    // 不换行，后续刷新用回车原位重写同一行
    let now = now_unix()?;
    if let Some(line) = watch_line(entry, now) {
        print!("{line}");
        if let Err(e) = std::io::stdout().flush() {
            return Err(CliError::Generic(format!("输出失败：{e}")));
        }
        last_rendered = line;
    }

    let result = loop {
        if stop.load(Ordering::Relaxed) {
            break Ok(());
        }
        // 分段睡眠：睡到刷新点，但至多 100ms 以便及时响应 Ctrl-C；
        // 抵达刷新点后以固定增量推进（不参考当前时刻，防漂移累积）
        let wait = ticker.wait_ms(monotonic_ms());
        if wait == 0 {
            ticker.advance();
        } else {
            sleep(Duration::from_millis(wait.min(100)));
        }
        // 每轮检查渲染内容：剩余秒数每秒变化 → 每秒一次原位重绘
        let now = now_unix()?;
        let Some(line) = watch_line(entry, now) else {
            break Err(CliError::Generic(
                "条目密钥无法解码，无法生成验证码".to_string(),
            ));
        };
        if line != last_rendered {
            print!("\r{line}");
            if let Err(e) = std::io::stdout().flush() {
                break Err(CliError::Generic(format!("输出失败：{e}")));
            }
            last_rendered = line;
        }
    };
    println!();
    result
}

// ---------------------------------------------------------------------------
// 恢复码恢复与轮换（M3-6）
// ---------------------------------------------------------------------------

/// `recover`：忘记主密码时的恢复流程。
///
/// 交互式提示输入恢复码（不经行内参数，避免凭据进入 shell 历史与终端回滚），
/// 验证通过后强制轮换：生成新恢复码、重写恢复码封套、打印并强制确认已保存；
/// 轮换后旧恢复码作废，轮换中断时原文件完好、旧码仍可用。
pub fn cmd_recover(vault: &ResolvedVault) -> Result<(), CliError> {
    if !vault.path.is_file() {
        return Err(CliError::Generic(format!(
            "保险库文件不存在：{}（可先运行 2fa init 创建）",
            vault.path.display()
        )));
    }
    if !std::io::stdin().is_terminal() {
        return Err(CliError::Generic(
            "recover 需要交互式终端输入恢复码（避免凭据进入 shell 历史与终端回滚）".to_string(),
        ));
    }
    echo_vault(vault);

    let old_input = rpassword::prompt_password("输入当前恢复码：")
        .map_err(|e| CliError::Generic(format!("读取恢复码失败：{e}")))?;
    let new_code = recovery::generate().map_err(|e| CliError::Generic(e.to_string()))?;

    // 持文件锁执行轮换；core 内部先备份 .bak 再原子回写，中断时旧码仍可用
    let rotated = {
        let _lock = acquire_lock(vault)?;
        rotate_recovery(
            &vault.path,
            &recovery::normalize(&old_input),
            &recovery::normalize(&new_code),
        )
    };
    if let Err(err) = rotated {
        return Err(match err {
            RotateError::AuthFailed => CliError::AuthFailed,
            other => CliError::Generic(other.to_string()),
        });
    }

    println!();
    println!("════════════════════════════════════════════");
    println!("已轮换恢复码，旧恢复码即刻作废。新恢复码");
    println!("（丢失主密码时的唯一恢复手段，请抄写到纸上");
    println!("并妥善保存，不要存入联网设备）：");
    println!();
    println!("    {new_code}");
    println!();
    println!("════════════════════════════════════════════");

    // 强制确认：未确认已保存不允许结束
    loop {
        print!("确认已保存新恢复码？（输入 yes 继续）：");
        std::io::stdout()
            .flush()
            .map_err(|e| CliError::Generic(format!("输出失败：{e}")))?;
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(|e| CliError::Generic(format!("读取输入失败：{e}")))?;
        match answer.trim() {
            "yes" | "y" | "Y" | "是" => break,
            _ => println!("未确认保存前无法结束，新恢复码只显示这一次。"),
        }
    }
    println!("恢复完成。今后请使用主密码或新恢复码解锁保险库。");
    log::info!("已轮换恢复码");
    Ok(())
}

// ---------------------------------------------------------------------------
// 日志与辅助命令（M3-7）
// ---------------------------------------------------------------------------

/// KDF 基准测试固定盐（仅为计时用途，不承载任何安全语义）。
const BENCH_SALT: [u8; 16] = [0x5A; 16];
/// TOTP 基准测试重复次数。
const BENCH_TOTP_ITERS: u32 = 1000;

/// `logs purge`：手动清理超过保留期（7 天）的日志文件。
pub fn cmd_logs_purge(log_dir: Option<PathBuf>) -> Result<(), CliError> {
    let Some(dir) = log_dir else {
        return Err(CliError::Generic(
            "无法确定平台日志目录（缺少 LOCALAPPDATA / XDG_STATE_HOME / HOME 环境变量）"
                .to_string(),
        ));
    };
    println!("日志目录：{}", dir.display());
    if !dir.is_dir() {
        println!("日志目录不存在（从未开启 --log-to-file），无需清理。");
        return Ok(());
    }
    let today = chrono::Local::now().date_naive();
    let removed = crate::logging::purge_expired(&dir, today)
        .map_err(|e| CliError::Generic(format!("清理日志失败：{e}")))?;
    println!(
        "已清理 {removed} 个过期日志文件（保留最近 {} 天）。",
        crate::logging::RETAIN_DAYS
    );
    log::info!("已清理 {removed} 个过期日志文件");
    Ok(())
}

/// `bench`：报告 KDF 派生（含 Argon2id）与单次 TOTP 计算耗时，
/// 供 PRD 性能指标复核（M2-7 / M6-4）。不访问保险库，无副作用。
pub fn cmd_bench() -> Result<(), CliError> {
    use std::time::Instant;

    let params = two_fa_core::vault::kdf_params(two_fa_core::vault::CURRENT_VERSION)
        .map_err(|e| CliError::Generic(e.to_string()))?;
    let kdf_runs = 3;
    let mut kdf_total = Duration::ZERO;
    for _ in 0..kdf_runs {
        let start = Instant::now();
        let _key = two_fa_core::vault::kdf_derive(
            "bench 专用一次性口令",
            &BENCH_SALT,
            two_fa_core::vault::CURRENT_VERSION,
        )
        .map_err(|e| CliError::Generic(e.to_string()))?;
        kdf_total += start.elapsed();
    }

    // 固定密钥与计数器仅为计时，不承载任何安全语义
    let secret = [0x31u8; 20];
    let mut totp_total = Duration::ZERO;
    for i in 0..u64::from(BENCH_TOTP_ITERS) {
        let start = Instant::now();
        let _code = totp::compute(&secret, i, Algorithm::Sha1, 6)
            .map_err(|e| CliError::Generic(e.to_string()))?;
        totp_total += start.elapsed();
    }

    println!("基准测试（本机数值，供性能复核参考）：");
    println!(
        "  KDF 派生（Argon2id v{}：{} MiB / t={} / p={}）：{kdf_runs} 次平均 {:.1} ms",
        params.version,
        params.m_cost_kib / 1024,
        params.t_cost,
        params.p_cost,
        kdf_total.as_secs_f64() / f64::from(kdf_runs) * 1000.0
    );
    println!(
        "  TOTP 计算（SHA1 / 6 位）：{BENCH_TOTP_ITERS} 次平均 {:.2} µs",
        totp_total.as_secs_f64() / f64::from(BENCH_TOTP_ITERS) * 1e6
    );
    log::debug!(
        "bench 完成：KDF {} 次均值 {:.1} ms，TOTP {BENCH_TOTP_ITERS} 次均值 {:.2} µs",
        kdf_runs,
        kdf_total.as_secs_f64() / f64::from(kdf_runs) * 1000.0,
        totp_total.as_secs_f64() / f64::from(BENCH_TOTP_ITERS) * 1e6
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// 导入导出（M4）
// ---------------------------------------------------------------------------

/// `import <文件>`：导入条目（当前支持 otpauth 纯文本，M4-1）。
pub fn cmd_import(
    vault: &ResolvedVault,
    stdin_password: bool,
    file: &Path,
    overwrite: bool,
    keep_both: bool,
    interactive: bool,
) -> Result<(), CliError> {
    if overwrite && keep_both {
        return Err(CliError::Generic(
            "--overwrite 与 --keep-both 互斥，请只选择其一".to_string(),
        ));
    }
    if !file.is_file() {
        return Err(CliError::Generic(format!(
            "导入文件不存在：{}",
            file.display()
        )));
    }
    let (key, mut body) = load_unlocked(vault, stdin_password)?;
    let text = std::fs::read_to_string(file).map_err(|e| {
        CliError::Generic(format!(
            "读取导入文件失败（请确认是 UTF-8 的 otpauth 文本）：{e}"
        ))
    })?;
    op_import(
        vault,
        &key,
        &mut body,
        &text,
        overwrite,
        keep_both,
        interactive,
    )
}

/// 共享操作：导入 otpauth 文本（供 REPL 复用会话密钥与已加载正文）。
///
/// 重复条目（归一化同标识且密钥相同）跳过并提示；同标识不同密钥时
/// 交互逐条询问覆盖 / 并存 / 跳过，非交互须以 `--overwrite` / `--keep-both`
/// 显式选择（否则默认跳过）。整批只在有变更时持锁回写一次。
pub fn op_import(
    vault: &ResolvedVault,
    key: &VaultKey,
    body: &mut VaultBody,
    text: &str,
    overwrite: bool,
    keep_both: bool,
    interactive: bool,
) -> Result<(), CliError> {
    let items = otpauth_text::parse_batch(text).map_err(|e| CliError::Generic(e.to_string()))?;
    if items.is_empty() {
        return Err(CliError::Generic(
            "导入文件中没有可导入的条目（只含空行或注释行）".to_string(),
        ));
    }

    let mut added = 0usize;
    let mut replaced = 0usize;
    let mut kept_both = 0usize;
    let mut skipped_dup = 0usize;
    let mut skipped_conflict = 0usize;
    let mut failed = 0usize;
    let mut changed = false;

    for item in items {
        match item {
            BatchItem::Failed { line, error } => {
                failed += 1;
                eprintln!("第 {line} 行导入失败：{error}");
            }
            BatchItem::Ok {
                line,
                entry,
                warnings,
            } => {
                for warning in &warnings {
                    eprintln!("第 {line} 行警告：{warning}");
                }
                let same = body.find_same_identity(&entry.issuer, &entry.account);
                if let Some(existing) = same.first() {
                    if existing.secret.as_text() == entry.secret.as_text() {
                        skipped_dup += 1;
                        eprintln!(
                            "第 {line} 行与既有条目重复（{} / {}），已跳过",
                            entry.issuer, entry.account
                        );
                        continue;
                    }
                    let action = if interactive {
                        ask_import_conflict(line, &entry)?
                    } else if overwrite {
                        "o"
                    } else if keep_both {
                        "b"
                    } else {
                        skipped_conflict += 1;
                        eprintln!(
                            "第 {line} 行与既有条目同标识但密钥不同（{} / {}），已跳过；非交互请用 --overwrite 或 --keep-both 显式选择",
                            entry.issuer, entry.account
                        );
                        continue;
                    };
                    match action {
                        // 覆盖：移除全部同标识既有条目后写入（与 add 语义一致）
                        "o" => {
                            let target = entry.identity_key();
                            body.entries.retain(|e| e.identity_key() != target);
                            replaced += 1;
                            changed = true;
                            body.entries.push(entry);
                        }
                        "b" => {
                            kept_both += 1;
                            changed = true;
                            body.entries.push(entry);
                        }
                        _ => skipped_conflict += 1,
                    }
                    continue;
                }
                added += 1;
                changed = true;
                body.entries.push(entry);
            }
        }
    }

    if changed {
        let _lock = acquire_lock(vault)?;
        entries::save(&vault.path, key, body).map_err(map_entry_err)?;
    }
    echo_vault(vault);
    println!(
        "导入完成：新增 {added}，覆盖 {replaced}，并存 {kept_both}，跳过重复 {skipped_dup}，跳过冲突 {skipped_conflict}，失败 {failed}。"
    );
    log::info!(
        "导入 otpauth 文本完成：新增 {added}，覆盖 {replaced}，并存 {kept_both}，跳过重复 {skipped_dup}，跳过冲突 {skipped_conflict}，失败 {failed}"
    );
    Ok(())
}

/// 交互询问同标识不同密钥的处理方式。
fn ask_import_conflict(line: usize, entry: &Entry) -> Result<&'static str, CliError> {
    println!(
        "第 {line} 行与既有条目同标识但密钥不同（{} / {}）",
        entry.issuer, entry.account
    );
    loop {
        print!("选择：覆盖(o) / 并存保留(b) / 跳过(s)？");
        std::io::stdout()
            .flush()
            .map_err(|e| CliError::Generic(format!("输出失败：{e}")))?;
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(|e| CliError::Generic(format!("读取输入失败：{e}")))?;
        match answer.trim() {
            "o" | "O" => return Ok("o"),
            "b" | "B" => return Ok("b"),
            "s" | "S" => return Ok("s"),
            _ => println!("请输入 o、b 或 s。"),
        }
    }
}
