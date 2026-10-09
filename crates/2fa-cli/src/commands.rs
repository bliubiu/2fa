//! 单次命令模式：凭据读取、解锁、加载保险库正文。
//!
//! 每条子命令独立进程执行：本模块提供命令共用的「解锁 + 加载」流程，
//! 命令结束进程退出，主密钥随 `Drop` 清零。
//!
//! stdout 纪律：stdout 只放命令输出（可被管道解析）；
//! 警告与日志一律走 stderr。

use std::io::{IsTerminal as _, Write as _};
use std::time::{SystemTime, UNIX_EPOCH};

use two_fa_core::domain::totp::{self, Algorithm};
use two_fa_core::usecase::entries::{self, EntryOpError};
use two_fa_core::vault::{
    Entry, LockError, SecretKey, UnlockError, UpgradeOutcome, VaultBody, VaultKey, VaultLock,
    load_and_migrate, unlock,
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
            if let UpgradeOutcome::Failed(err) = outcome {
                eprintln!("警告：KDF 自动升级失败（不影响本次使用）：{err}");
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
