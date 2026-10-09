//! 保险库初始化：生成随机主密钥与双封套（主密码 + 恢复码），封装空正文。
//!
//! 文件写出由调用方完成（本层不感知路径与文件系统）；
//! `created_at` 由调用方传入，本层不读时钟。

use crate::vault::{
    Envelope, EnvelopeError, FormatError, KeyError, ModelError, VaultBody, VaultKey, format,
};

/// 初始化错误。
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    /// 主密钥生成失败。
    #[error("初始化失败：{0}")]
    Key(#[from] KeyError),
    /// 封套封存失败。
    #[error("初始化失败：{0}")]
    Envelope(#[from] EnvelopeError),
    /// 正文序列化失败。
    #[error("初始化失败：{0}")]
    Model(#[from] ModelError),
    /// 文件封装失败。
    #[error("初始化失败：{0}")]
    Format(#[from] FormatError),
}

/// 创建新保险库的完整文件字节。
///
/// 主密钥来自操作系统 CSPRNG；`recovery_code` 必须是归一化后的凭据
/// （见 [`super::recovery::normalize`]）；返回字节交由调用方原子写出。
pub fn create_vault(
    master_password: &str,
    recovery_code: &str,
    created_at: u64,
) -> Result<Vec<u8>, InitError> {
    let vault_key = VaultKey::generate()?;
    let envelopes = vec![
        Envelope::seal(&vault_key, master_password)?,
        Envelope::seal(&vault_key, recovery_code)?,
    ];
    let body = VaultBody::empty(created_at);
    let file = format::seal(&vault_key, envelopes, body.to_json()?.as_bytes())?;
    Ok(file.to_bytes())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::vault::{SCHEMA_VERSION, VaultFile};

    /// 创建的保险库：主密码与恢复码两个封套均可解封出同一主密钥，正文为空。
    #[test]
    fn 双封套均可解封且正文为空() {
        let bytes = create_vault("主密码", "RECOVERYCODE", 1_700_000_000).unwrap();
        let file = VaultFile::parse(&bytes).unwrap();

        assert_eq!(file.schema_version, SCHEMA_VERSION);
        assert_eq!(file.envelopes.len(), 2);

        let key_main = file.envelopes[0].unseal("主密码").unwrap();
        let key_rec = file.envelopes[1].unseal("RECOVERYCODE").unwrap();
        assert_eq!(key_main.expose(), key_rec.expose());

        let body = VaultBody::from_json(
            std::str::from_utf8(&crate::vault::format::open(&key_main, &file).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(body.entries.len(), 0);
        assert_eq!(body.created_at, 1_700_000_000);
    }

    /// 两次创建产出不同字节（主密钥、盐、nonce 全部随机）。
    #[test]
    fn 两次创建字节不同() {
        let a = create_vault("同密码", "同恢复码", 1).unwrap();
        let b = create_vault("同密码", "同恢复码", 1).unwrap();
        assert_ne!(a, b);
    }

    /// 错误恢复码解封必失败（凭据进入封套而非明文存储）。
    #[test]
    fn 错误恢复码解封失败() {
        let bytes = create_vault("主密码", "RECOVERYCODE", 1).unwrap();
        let file = VaultFile::parse(&bytes).unwrap();
        let err = file.envelopes[1].unseal("WRONGCODE").unwrap_err();
        assert!(matches!(err, crate::vault::EnvelopeError::AuthFailed));
    }
}
