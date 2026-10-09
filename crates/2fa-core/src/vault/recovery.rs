//! 恢复码轮换：用旧恢复码换新恢复码（忘记主密码后的强制流程）。
//!
//! 恢复码用一次就必须轮换（`docs/adr/0002`）：本模块用旧码逐封套试解，
//! 命中的封套（正常恰为恢复码封套一枚；若旧码恰与主密码相同则全部命中）
//! 按新码重新封存，并因头部在正文 GCM 的 AAD 内而按新头部重算正文密文
//! ——条目明文不变。
//!
//! 中断安全：回写前先把原始字节备份到 `<保险库>.bak`，再走 [`atomic_write`]
//! ——轮换中途进程被杀或写入失败，原文件完好、旧码仍可用。
//!
//! 并发说明：调用方应持有文件锁（[`super::storage::VaultLock`]）后再调用；
//! 未持锁时并发轮换的双写结果等价，`atomic_write` 保证不产生中间态文件。

use std::fs;
use std::path::Path;

use zeroize::Zeroizing;

use super::envelope::{Envelope, EnvelopeError};
use super::format::{self, FormatError, SCHEMA_VERSION, VaultFile};
use super::kdf::{self, KdfVersion};
use super::key::VaultKey;
use super::migrate::probe_schema_version;
use super::storage::atomic_write;
use super::unlock::backup_path;

/// 轮换错误。
#[derive(Debug, thiserror::Error)]
pub enum RotateError {
    /// 旧恢复码解不开任何封套：恢复码错误。
    #[error("认证失败：恢复码错误")]
    AuthFailed,
    /// 封套使用的 KDF 版本比程序新——提示升级，绝不降级尝试。
    #[error("封套使用的 KDF 版本为 {found}，当前程序支持到 {supported}，请升级程序后再打开")]
    KdfTooNew {
        found: KdfVersion,
        supported: KdfVersion,
    },
    /// 正文 schema 版本比程序新——提示升级，不触碰文件。
    #[error("保险库 schema 版本为 {found}，当前程序支持到 {supported}，请升级程序后再打开")]
    SchemaTooNew { found: u16, supported: u16 },
    /// 重新封存封套失败。
    #[error("重新封存封套失败：{0}")]
    Envelope(#[from] EnvelopeError),
    /// 文件格式错误（魔数、布局、正文认证失败等）。
    #[error("保险库格式错误：{0}")]
    Format(#[from] FormatError),
    /// 正文 JSON 解析失败。
    #[error("保险库正文编解码失败：{0}")]
    Json(#[from] serde_json::Error),
    /// 备份或回写失败。
    #[error("恢复码轮换回写失败：{0}")]
    Io(#[from] std::io::Error),
}

/// 用旧恢复码轮换新恢复码。
///
/// `old_code` 与 `new_code` 必须是**归一化后**的凭据（见
/// `usecase::recovery::normalize`）。轮换成功后旧码解不开任何封套；
/// 轮换失败或中断时原文件完好、旧码仍可用。
pub fn rotate_recovery(
    vault_path: &Path,
    old_code: &str,
    new_code: &str,
) -> Result<(), RotateError> {
    let raw = fs::read(vault_path)?;
    let file = VaultFile::parse(&raw)?;

    // 逐封套用旧码试解：命中的封套即要轮换的对象。
    // 主密钥取首个命中封套解出的那份（各封套封存的本就是同一把钥匙，
    // 多余的解出副本随作用域 drop 清零）
    let mut vault_key: Option<VaultKey> = None;
    let mut new_envelopes = Vec::with_capacity(file.envelopes.len());
    for envelope in &file.envelopes {
        match envelope.unseal(old_code) {
            Ok(key) => {
                let stored = vault_key.get_or_insert(key);
                new_envelopes.push(Envelope::seal(stored, new_code)?);
            }
            Err(EnvelopeError::Kdf(kdf::KdfError::Unknown(found))) => {
                return Err(RotateError::KdfTooNew {
                    found,
                    supported: kdf::CURRENT_VERSION,
                });
            }
            // 凭据与本封套不匹配（或封套被篡改）：原样保留
            Err(_) => new_envelopes.push(envelope.clone()),
        }
    }
    let Some(vault_key) = vault_key else {
        return Err(RotateError::AuthFailed);
    };

    // 解出正文：既验证文件完整性，也为重封装备料
    let body_bytes = format::open(&vault_key, &file)?;
    let body_json = Zeroizing::new(
        String::from_utf8(body_bytes).map_err(|_| FormatError::Corrupt("正文不是合法 UTF-8"))?,
    );

    // 正文 schema 比程序新：不动文件，让上层给出升级提示
    let schema = probe_schema_version(&body_json)?;
    if schema > SCHEMA_VERSION {
        return Err(RotateError::SchemaTooNew {
            found: schema,
            supported: SCHEMA_VERSION,
        });
    }

    // 新封套列表 + 新 nonce 重封装正文：头部整体在 AAD 内，
    // 封套字节一变正文必须重加密，条目明文不变
    let new_file = format::seal(&vault_key, new_envelopes, body_json.as_bytes())?;

    // 先备份原始字节，再原子回写：轮换中断时原文件完好、旧码仍可用
    let backup = backup_path(vault_path);
    atomic_write(&backup, &raw)?;
    atomic_write(vault_path, &new_file.to_bytes())?;
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::totp::Algorithm;
    use crate::vault::entries::{Entry, VaultBody};
    use crate::vault::key::SecretKey;
    use std::env;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let base = env::temp_dir().join(format!("2fa-rotate-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        base
    }

    fn sample_body() -> VaultBody {
        let mut body = VaultBody::empty(1_700_000_000);
        body.entries.push(
            Entry::new(
                "GitHub".into(),
                "alice".into(),
                SecretKey::from_base32("MZXW6YTBOI").unwrap(),
                Algorithm::Sha1,
                6,
                30,
                Vec::new(),
            )
            .unwrap(),
        );
        body
    }

    /// 写入主密码 / 恢复码双封套保险库（均为当前 KDF 版本）。
    fn write_vault(
        dir: &Path,
        main_cred: &str,
        recovery_cred: &str,
        body: &VaultBody,
    ) -> std::path::PathBuf {
        let vault = dir.join("vault.json");
        let key = VaultKey::new([0x2A; 32]);
        let envelopes = vec![
            Envelope::seal(&key, main_cred).unwrap(),
            Envelope::seal(&key, recovery_cred).unwrap(),
        ];
        let file = format::seal(&key, envelopes, body.to_json().unwrap().as_bytes()).unwrap();
        fs::write(&vault, file.to_bytes()).unwrap();
        vault
    }

    /// 解密正文并解析，用于验证条目内容未变。
    fn read_body(vault: &Path, credential: &str) -> VaultBody {
        let raw = fs::read(vault).unwrap();
        let file = VaultFile::parse(&raw).unwrap();
        let mut key = None;
        for envelope in &file.envelopes {
            if let Ok(k) = envelope.unseal(credential) {
                key = Some(k);
                break;
            }
        }
        let body = format::open(&key.unwrap(), &file).unwrap();
        VaultBody::from_json(std::str::from_utf8(&body).unwrap()).unwrap()
    }

    /// 轮换后：旧码解封必失败、新码成功、主密码封套不受影响、.bak 保存原始字节。
    #[test]
    fn 轮换后旧码失效新码可用() {
        let dir = temp_dir("rotate");
        let body = sample_body();
        let vault = write_vault(&dir, "主密码", "旧恢复码", &body);
        let original = fs::read(&vault).unwrap();

        rotate_recovery(&vault, "旧恢复码", "新恢复码").unwrap();

        let raw = fs::read(&vault).unwrap();
        assert_ne!(raw, original, "保险库文件应被重写");
        assert_eq!(
            fs::read(backup_path(&vault)).unwrap(),
            original,
            ".bak 应保存轮换前的原始字节"
        );

        let file = VaultFile::parse(&raw).unwrap();
        // 旧码对所有封套解封必失败
        for envelope in &file.envelopes {
            assert!(
                envelope.unseal("旧恢复码").is_err(),
                "旧码不应再能解封任何封套"
            );
        }
        // 新码成功且解出同一主密钥
        let key = file.envelopes[1].unseal("新恢复码").unwrap();
        assert_eq!(key.expose(), &[0x2A; 32]);
        // 主密码封套不受影响
        let key_main = file.envelopes[0].unseal("主密码").unwrap();
        assert_eq!(key_main.expose(), &[0x2A; 32]);
    }

    /// 轮换只触及恢复码封套与正文重封装：主密码封套字节不变、条目明文不变。
    #[test]
    fn 轮换只触及恢复码封套条目明文不变() {
        let dir = temp_dir("scope");
        let body = sample_body();
        let vault = write_vault(&dir, "主密码", "旧恢复码", &body);
        let before = VaultFile::parse(&fs::read(&vault).unwrap()).unwrap();

        rotate_recovery(&vault, "旧恢复码", "新恢复码").unwrap();

        let after = VaultFile::parse(&fs::read(&vault).unwrap()).unwrap();
        assert_eq!(after.envelopes.len(), before.envelopes.len());
        assert_eq!(
            after.envelopes[0], before.envelopes[0],
            "主密码封套字节不应改变"
        );
        assert_ne!(
            after.envelopes[1], before.envelopes[1],
            "恢复码封套应被重写"
        );
        let body_after = read_body(&vault, "主密码");
        assert_eq!(body_after.entries.len(), 1);
        assert_eq!(body_after.entries[0].issuer, "GitHub");
        assert_eq!(body_after.entries[0].account, "alice");
        assert_eq!(body_after.entries[0].secret.as_text(), "MZXW6YTBOI");
        assert_eq!(body_after.created_at, 1_700_000_000);
    }

    /// 轮换中断（回写失败）：原文件完好、旧码仍可解封。
    #[test]
    fn 轮换中断原文件完好旧码仍可用() {
        let dir = temp_dir("interrupt");
        let body = sample_body();
        let vault = write_vault(&dir, "主密码", "旧恢复码", &body);
        let original = fs::read(&vault).unwrap();
        // 占用 .bak 路径：备份写入必然失败，轮换在触碰保险库前中止
        fs::create_dir(backup_path(&vault)).unwrap();

        let err = rotate_recovery(&vault, "旧恢复码", "新恢复码").unwrap_err();

        assert!(matches!(err, RotateError::Io(_)), "实际 {err:?}");
        assert_eq!(fs::read(&vault).unwrap(), original, "原文件应完好");
        // 旧码仍可解封
        let file = VaultFile::parse(&original).unwrap();
        let key = file.envelopes[1].unseal("旧恢复码").unwrap();
        assert_eq!(key.expose(), &[0x2A; 32]);
    }

    /// 错误旧码：认证失败，文件不变，不产生 .bak。
    #[test]
    fn 错误旧码认证失败且文件不变() {
        let dir = temp_dir("wrong");
        let body = sample_body();
        let vault = write_vault(&dir, "主密码", "旧恢复码", &body);
        let original = fs::read(&vault).unwrap();

        let err = rotate_recovery(&vault, "错误恢复码", "新恢复码").unwrap_err();

        assert!(matches!(err, RotateError::AuthFailed), "实际 {err:?}");
        assert_eq!(fs::read(&vault).unwrap(), original);
        assert!(!backup_path(&vault).exists());
    }
}
