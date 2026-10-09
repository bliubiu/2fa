//! 解锁入口与 KDF 自动升级。
//!
//! 解锁：逐个尝试封套，首个解封成功者胜出（凭据可以是主密码或恢复码）。
//!
//! KDF 自动升级：被使用的封套若 `kdf_version` 低于当前版本，则用同一凭据
//! 按当前版本重新封存（重写其他封套需要其凭据，本层拿不到也不该拿），
//! 随后按新头部重算正文密文——头部整体是正文 GCM 的 AAD，封套字节一变
//! 正文必须重加密，但保险库主密钥与条目明文不变。
//!
//! 失败语义：
//! - 重写失败**不阻断解锁**，以 [`UpgradeOutcome::Failed`] 返回，由上层输出警告
//! - 回写前先把原始字节备份到 `<保险库>.bak`，再走 [`atomic_write`]，可中断可回滚
//! - 正文 schema 高于当前支持版本时不触碰文件（程序太旧不应改写读不懂的文件）

use std::fs;
use std::path::Path;

use zeroize::Zeroizing;

use super::envelope::{Envelope, EnvelopeError};
use super::format::{self, FormatError, SCHEMA_VERSION, VaultFile};
use super::kdf::{self, KdfVersion};
use super::key::VaultKey;
use super::migrate::probe_schema_version;
use super::storage::atomic_write;

/// 解锁错误。
#[derive(Debug, thiserror::Error)]
pub enum UnlockError {
    /// 全部封套均认证失败：凭据不正确。
    #[error("认证失败：密码或恢复码错误")]
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
    /// 文件格式错误（魔数、布局、正文认证失败等）。
    #[error("保险库格式错误：{0}")]
    Format(#[from] FormatError),
    /// 正文 JSON 解析失败。
    #[error("保险库正文编解码失败：{0}")]
    Json(#[from] serde_json::Error),
    /// 文件系统操作失败。
    #[error("读取保险库文件失败：{0}")]
    Io(#[from] std::io::Error),
}

/// KDF 自动升级的结果。
#[derive(Debug)]
pub enum UpgradeOutcome {
    /// 封套已是当前 KDF 版本，无需升级。
    NotNeeded,
    /// 封套已升级并回写成功。
    Upgraded,
    /// 升级尝试失败（解锁本身不受影响），上层应输出警告。
    Failed(UpgradeError),
}

/// 升级过程中的错误（不影响解锁结果）。
#[derive(Debug, thiserror::Error)]
pub enum UpgradeError {
    /// 重新封存封套失败。
    #[error("重新封存封套失败：{0}")]
    Envelope(#[from] EnvelopeError),
    /// 升级后文件重封装失败。
    #[error("升级后文件重封装失败：{0}")]
    Format(#[from] FormatError),
    /// 备份或回写失败。
    #[error("升级回写失败：{0}")]
    Io(#[from] std::io::Error),
}

/// 用凭据解锁保险库，并对被使用封套执行 KDF 自动升级。
///
/// 返回 `(保险库主密钥, 升级结果)`。正文内容（含条目）由调用方随后经
/// [`super::migrate::load_and_migrate`] 加载；本函数只保证主密钥正确、
/// 封套与文件结构一致。
///
/// 并发说明：调用方应持有文件锁（[`super::storage::VaultLock`]）后再调用；
/// 未持锁时并发升级的双写结果等价，`atomic_write` 保证不产生中间态文件。
pub fn unlock(
    vault_path: &Path,
    credential: &str,
) -> Result<(VaultKey, UpgradeOutcome), UnlockError> {
    let raw = fs::read(vault_path)?;
    let file = VaultFile::parse(&raw)?;

    // 逐个尝试封套：认证失败换下一个；KDF 版本比程序新则立即报错不降级
    let mut used = None;
    for (idx, envelope) in file.envelopes.iter().enumerate() {
        match envelope.unseal(credential) {
            Ok(key) => {
                used = Some((idx, key));
                break;
            }
            Err(EnvelopeError::Kdf(kdf::KdfError::Unknown(found))) => {
                return Err(UnlockError::KdfTooNew {
                    found,
                    supported: kdf::CURRENT_VERSION,
                });
            }
            Err(_) => continue, // 凭据与本封套不匹配（或封套被篡改），尝试下一个
        }
    }
    let (used_idx, vault_key) = used.ok_or(UnlockError::AuthFailed)?;

    // 解出正文：既验证文件完整性，也为升级后的重封装备料
    let body_bytes = format::open(&vault_key, &file)?;
    let body_json = Zeroizing::new(
        String::from_utf8(body_bytes).map_err(|_| FormatError::Corrupt("正文不是合法 UTF-8"))?,
    );

    // 正文 schema 比程序新：不动文件，让上层给出升级提示
    let schema = probe_schema_version(&body_json)?;
    if schema > SCHEMA_VERSION {
        return Err(UnlockError::SchemaTooNew {
            found: schema,
            supported: SCHEMA_VERSION,
        });
    }

    if file.envelopes[used_idx].kdf_version >= kdf::CURRENT_VERSION {
        return Ok((vault_key, UpgradeOutcome::NotNeeded));
    }

    // 升级：按当前版本重新封存被使用的封套 → 新头部下重算正文密文 → 备份 → 原子回写
    match upgrade_envelope(&vault_key, credential, file.envelopes, used_idx, &body_json) {
        Ok(new_file) => {
            let backup = backup_path(vault_path);
            if let Err(err) = atomic_write(&backup, &raw).map_err(UpgradeError::Io) {
                return Ok((vault_key, UpgradeOutcome::Failed(err)));
            }
            match atomic_write(vault_path, &new_file.to_bytes()).map_err(UpgradeError::Io) {
                Ok(()) => Ok((vault_key, UpgradeOutcome::Upgraded)),
                Err(err) => Ok((vault_key, UpgradeOutcome::Failed(err))),
            }
        }
        Err(err) => Ok((vault_key, UpgradeOutcome::Failed(err))),
    }
}

/// 重新封存第 `used_idx` 个封套并按新头部重封装正文。
///
/// 条目明文不变；正文 nonce 重新随机，认证标签覆盖新头部。
fn upgrade_envelope(
    vault_key: &VaultKey,
    credential: &str,
    mut envelopes: Vec<Envelope>,
    used_idx: usize,
    body_json: &str,
) -> Result<VaultFile, UpgradeError> {
    let fresh = Envelope::seal(vault_key, credential)?;
    envelopes[used_idx] = fresh;
    let new_file = format::seal(vault_key, envelopes, body_json.as_bytes())?;
    Ok(new_file)
}

/// `.bak` 备份路径（恢复码轮换与 schema 迁移共用同一命名规则）。
pub(crate) fn backup_path(vault_path: &Path) -> std::path::PathBuf {
    let mut name = vault_path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".bak");
    vault_path.with_file_name(name)
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
        let base = env::temp_dir().join(format!("2fa-unlock-{tag}-{}", std::process::id()));
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

    /// 写入一枚封套版本可指定的双封套保险库。
    fn write_vault(
        dir: &Path,
        main_version: KdfVersion,
        recovery_version: KdfVersion,
        body: &VaultBody,
    ) -> std::path::PathBuf {
        let vault = dir.join("vault.json");
        let key = VaultKey::new([0x2A; 32]);
        let envelopes = vec![
            Envelope::seal_at(&key, "主密码", main_version).unwrap(),
            Envelope::seal_at(&key, "恢复码", recovery_version).unwrap(),
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

    /// 已是当前 KDF 版本：解锁成功、文件字节不变、无 .bak。
    #[test]
    fn 已是当前版本不回写() {
        let dir = temp_dir("current");
        let body = sample_body();
        let vault = write_vault(&dir, 1, 1, &body);
        let original = fs::read(&vault).unwrap();

        let (key, outcome) = unlock(&vault, "主密码").unwrap();

        assert_eq!(key.expose(), &[0x2A; 32]);
        assert!(matches!(outcome, UpgradeOutcome::NotNeeded));
        assert_eq!(fs::read(&vault).unwrap(), original, "文件字节不应改变");
        assert!(!backup_path(&vault).exists(), "未升级不应产生 .bak");
    }

    /// 低版本封套解锁后自动升级：被封套升级到当前版本、条目不变、
    /// 另一枚封套不受影响、.bak 保存原始字节、二次解锁不再升级。
    #[test]
    fn 低版本封套解锁后自动升级() {
        let dir = temp_dir("upgrade");
        let body = sample_body();
        let vault = write_vault(&dir, 0, 1, &body);
        let original = fs::read(&vault).unwrap();

        let (key, outcome) = unlock(&vault, "主密码").unwrap();

        assert_eq!(key.expose(), &[0x2A; 32]);
        assert!(
            matches!(outcome, UpgradeOutcome::Upgraded),
            "实际 {outcome:?}"
        );

        // .bak 保存升级前的原始字节，可回滚
        let backup = backup_path(&vault);
        assert_eq!(fs::read(&backup).unwrap(), original);

        // 升级后：被使用的封套为当前版本，另一封套保持原版本且仍可用
        let raw = fs::read(&vault).unwrap();
        let file = VaultFile::parse(&raw).unwrap();
        assert_eq!(file.envelopes[0].kdf_version, kdf::CURRENT_VERSION);
        assert_eq!(file.envelopes[1].kdf_version, 1);
        let recovered = file.envelopes[1].unseal("恢复码").unwrap();
        assert_eq!(recovered.expose(), &[0x2A; 32]);

        // 条目明文不变
        let body_after = read_body(&vault, "主密码");
        assert_eq!(body_after.entries.len(), 1);
        assert_eq!(body_after.entries[0].issuer, "GitHub");
        assert_eq!(body_after.entries[0].secret.as_text(), "MZXW6YTBOI");

        // 二次解锁：已是当前版本，不再升级
        let (_, outcome) = unlock(&vault, "主密码").unwrap();
        assert!(matches!(outcome, UpgradeOutcome::NotNeeded));
    }

    /// 用当前版本的恢复码封套解锁：不升级、不触碰低版本的主密码封套。
    #[test]
    fn 恢复码解锁不触碰其他封套() {
        let dir = temp_dir("recovery");
        let body = sample_body();
        let vault = write_vault(&dir, 0, 1, &body);
        let original = fs::read(&vault).unwrap();

        let (key, outcome) = unlock(&vault, "恢复码").unwrap();

        assert_eq!(key.expose(), &[0x2A; 32]);
        assert!(
            matches!(outcome, UpgradeOutcome::NotNeeded),
            "恢复码封套已是当前版本"
        );
        assert_eq!(fs::read(&vault).unwrap(), original, "文件不应被改动");
    }

    /// 错误凭据报认证失败，文件不变。
    #[test]
    fn 错误凭据认证失败且文件不变() {
        let dir = temp_dir("wrong-cred");
        let body = sample_body();
        let vault = write_vault(&dir, 0, 1, &body);
        let original = fs::read(&vault).unwrap();

        let err = unlock(&vault, "错误密码").unwrap_err();

        assert!(matches!(err, UnlockError::AuthFailed));
        assert_eq!(fs::read(&vault).unwrap(), original);
        assert!(!backup_path(&vault).exists());
    }

    /// 备份失败（.bak 被目录占用）不阻断解锁：拿到主密钥，升级报 Failed，原文件完好。
    #[test]
    fn 重写失败不阻断解锁() {
        let dir = temp_dir("write-fail");
        let body = sample_body();
        let vault = write_vault(&dir, 0, 1, &body);
        let original = fs::read(&vault).unwrap();
        // 占用 .bak 路径：备份写入必然失败
        fs::create_dir(backup_path(&vault)).unwrap();

        let (key, outcome) = unlock(&vault, "主密码").unwrap();

        assert_eq!(key.expose(), &[0x2A; 32]);
        assert!(
            matches!(outcome, UpgradeOutcome::Failed(UpgradeError::Io(_))),
            "实际 {outcome:?}"
        );
        assert_eq!(fs::read(&vault).unwrap(), original, "原文件应完好");
    }

    /// 正文 schema 比程序新：报错且不触碰文件。
    #[test]
    fn 正文schema过新不触碰文件() {
        let dir = temp_dir("too-new");
        let mut body = sample_body();
        body.schema_version = SCHEMA_VERSION + 1;
        let vault = write_vault(&dir, 1, 1, &body);
        let original = fs::read(&vault).unwrap();

        let err = unlock(&vault, "主密码").unwrap_err();

        assert!(
            matches!(
                err,
                UnlockError::SchemaTooNew {
                    found: 2,
                    supported: 1
                }
            ),
            "实际 {err:?}"
        );
        assert_eq!(fs::read(&vault).unwrap(), original, "文件不应被改动");
    }

    /// 封套 KDF 版本比程序新：立即报错，绝不降级尝试，文件不变。
    #[test]
    fn 封套kdf版本过新报错() {
        let dir = temp_dir("kdf-too-new");
        let body = sample_body();
        let vault = write_vault(&dir, 1, 1, &body);
        let original = fs::read(&vault).unwrap();

        // 伪造未来版本：把封套 kdf_version 改成 99（字段在 AAD 内，
        // 此处只为驱动「未知版本」分支，解封会在 KDF 查表处报错）
        let mut file = VaultFile::parse(&original).unwrap();
        file.envelopes[0].kdf_version = 99;
        fs::write(&vault, file.to_bytes()).unwrap();

        let err = unlock(&vault, "主密码").unwrap_err();

        assert!(
            matches!(
                err,
                UnlockError::KdfTooNew {
                    found: 99,
                    supported: 1
                }
            ),
            "实际 {err:?}"
        );
    }

    /// `.bak` 备份路径命名正确。
    #[test]
    fn 备份路径命名() {
        assert_eq!(
            backup_path(Path::new("D:/x/vault.json")),
            Path::new("D:/x/vault.json.bak")
        );
    }
}
