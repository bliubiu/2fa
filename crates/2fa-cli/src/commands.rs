//! 单次命令模式：凭据读取、解锁、加载保险库正文。
//!
//! 每条子命令独立进程执行：本模块提供命令共用的「解锁 + 加载」流程，
//! 命令结束进程退出，主密钥随 `Drop` 清零。
//!
//! stdout 纪律：stdout 只放命令输出（可被管道解析）；
//! 警告与日志一律走 stderr。

use std::io::IsTerminal as _;

use two_fa_core::vault::{
    UnlockError, UpgradeOutcome, VaultBody, VaultKey, load_and_migrate, unlock,
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
