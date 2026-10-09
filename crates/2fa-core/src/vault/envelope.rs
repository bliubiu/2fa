//! 封套：用一段人类可记忆的凭据（主密码或恢复码）封存保险库主密钥。
//!
//! 封套 = `salt[16] + kdf_version(2 字节大端) + nonce[12] + ciphertext[48]`，
//! 共 78 字节，随机量全部来自操作系统 CSPRNG。
//!
//! AAD 纪律（`docs/adr/0003`）：
//! - 封套 AAD **只覆盖本封套自身**的 salt 与 kdf_version 字节，不含另一封套与全局字段，
//!   因此重写任一封套都不影响另一封套的认证
//! - `kdf_version` 位于 AAD 内，不可被降级篡改
//!
//! 失败语义区分「认证失败（凭据不正确）」与「数据损坏」两种文案。

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};

use super::kdf;
use super::key::VaultKey;

/// 封套中盐的长度。
const SALT_LEN: usize = 16;
/// 封套 GCM nonce 长度。
const NONCE_LEN: usize = 12;
/// 封套 AAD 长度：salt + kdf_version。
const AAD_LEN: usize = SALT_LEN + 2;
/// 保险库主密钥长度 + GCM 认证标签。
const CIPHERTEXT_LEN: usize = 32 + 16;
/// 封套序列化后的总长度。
pub const ENVELOPE_LEN: usize = SALT_LEN + 2 + NONCE_LEN + CIPHERTEXT_LEN;

/// 封套操作错误。
#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    /// 认证失败：凭据不正确，或封套数据被篡改（二者在密码学上不可区分）。
    #[error("认证失败：凭据不正确（密码或恢复码错误），或封套数据已被篡改")]
    AuthFailed,
    /// KDF 相关错误（含未知版本——被篡改或由更新版本的程序写入）。
    #[error("封套 KDF 处理失败：{0}")]
    Kdf(#[from] kdf::KdfError),
    /// AEAD 运算失败（正常情况下不可达，类型上必须处理）。
    #[error("AEAD 运算失败：{0}")]
    Aead(#[from] aes_gcm::Error),
    /// AEAD 密钥构造失败（密钥长度恒为 32 字节，正常不可达，类型上必须处理）。
    #[error("AEAD 密钥构造失败")]
    InvalidKey,
    /// 操作系统 CSPRNG 读取失败。
    #[error("操作系统 CSPRNG 读取失败：{0}")]
    RandomSource(#[from] getrandom::Error),
    /// 封套数据损坏（长度或布局不符合预期）。
    #[error("封套数据损坏：{0}")]
    Corrupt(&'static str),
}

/// 封套：一段凭据对保险库主密钥的加密封装。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// KDF 盐，16 字节随机。
    pub salt: [u8; SALT_LEN],
    /// KDF 版本号（AAD 覆盖内，不可降级篡改）。
    pub kdf_version: kdf::KdfVersion,
    /// 本封套 GCM 的随机 nonce。
    pub nonce: [u8; NONCE_LEN],
    /// 加密后的保险库主密钥（含 16 字节 GCM 标签）。
    pub ciphertext: [u8; CIPHERTEXT_LEN],
}

/// 封套 AAD：仅本封套的 salt 与 kdf_version。
fn aad_bytes(salt: &[u8; SALT_LEN], version: kdf::KdfVersion) -> [u8; AAD_LEN] {
    let mut aad = [0u8; AAD_LEN];
    aad[..SALT_LEN].copy_from_slice(salt);
    aad[SALT_LEN..].copy_from_slice(&version.to_be_bytes());
    aad
}

impl Envelope {
    /// 用凭据封存保险库主密钥（KDF 版本取当前最高版本）。
    pub fn seal(vault_key: &VaultKey, credential: &str) -> Result<Self, EnvelopeError> {
        Self::seal_at(vault_key, credential, kdf::CURRENT_VERSION)
    }

    /// 用凭据按指定 KDF 版本封存保险库主密钥。
    ///
    /// 供 KDF 自动升级的测试构造历史版本封套使用；版本必须存在于参数表中。
    pub(crate) fn seal_at(
        vault_key: &VaultKey,
        credential: &str,
        kdf_version: kdf::KdfVersion,
    ) -> Result<Self, EnvelopeError> {
        let mut salt = [0u8; SALT_LEN];
        getrandom::fill(&mut salt)?;
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::fill(&mut nonce)?;

        let kek = kdf::derive(credential, &salt, kdf_version)?;
        let cipher =
            Aes256Gcm::new_from_slice(kek.expose()).map_err(|_| EnvelopeError::InvalidKey)?;
        let mut ciphertext = [0u8; CIPHERTEXT_LEN];
        let sealed = cipher.encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: vault_key.expose().as_slice(),
                aad: &aad_bytes(&salt, kdf_version),
            },
        )?;
        ciphertext.copy_from_slice(&sealed);

        Ok(Self {
            salt,
            kdf_version,
            nonce,
            ciphertext,
        })
    }

    /// 用凭据解封，得到保险库主密钥。
    ///
    /// KEK 只在本函数作用域内存在，成功或失败后均随 drop 零化。
    pub fn unseal(&self, credential: &str) -> Result<VaultKey, EnvelopeError> {
        let kek = kdf::derive(credential, &self.salt, self.kdf_version)?;
        let cipher =
            Aes256Gcm::new_from_slice(kek.expose()).map_err(|_| EnvelopeError::InvalidKey)?;
        let plaintext = cipher
            .decrypt(
                &Nonce::from(self.nonce),
                Payload {
                    msg: self.ciphertext.as_slice(),
                    aad: &aad_bytes(&self.salt, self.kdf_version),
                },
            )
            .map_err(|_| EnvelopeError::AuthFailed)?;
        let mut key = [0u8; 32];
        key.copy_from_slice(&plaintext);
        Ok(VaultKey::new(key))
    }

    /// 序列化为固定 78 字节布局。
    pub fn to_bytes(&self) -> [u8; ENVELOPE_LEN] {
        let mut out = [0u8; ENVELOPE_LEN];
        out[..SALT_LEN].copy_from_slice(&self.salt);
        out[SALT_LEN..SALT_LEN + 2].copy_from_slice(&self.kdf_version.to_be_bytes());
        out[SALT_LEN + 2..SALT_LEN + 2 + NONCE_LEN].copy_from_slice(&self.nonce);
        out[SALT_LEN + 2 + NONCE_LEN..].copy_from_slice(&self.ciphertext);
        out
    }

    /// 从固定 78 字节布局解析封套；长度不符即「数据损坏」。
    pub fn parse(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        if bytes.len() != ENVELOPE_LEN {
            return Err(EnvelopeError::Corrupt("长度不符：封套应为 78 字节"));
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&bytes[..SALT_LEN]);
        let kdf_version = kdf::KdfVersion::from_be_bytes(
            bytes[SALT_LEN..SALT_LEN + 2]
                .try_into()
                .map_err(|_| EnvelopeError::Corrupt("kdf_version 字段读取失败"))?,
        );
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[SALT_LEN + 2..SALT_LEN + 2 + NONCE_LEN]);
        let mut ciphertext = [0u8; CIPHERTEXT_LEN];
        ciphertext.copy_from_slice(&bytes[SALT_LEN + 2 + NONCE_LEN..]);
        Ok(Self {
            salt,
            kdf_version,
            nonce,
            ciphertext,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn sample_key() -> VaultKey {
        VaultKey::new([0x42; 32])
    }

    /// 正确凭据解封得到与封存时一致的保险库主密钥。
    #[test]
    fn 密封后解封还原主密钥() {
        let vk = sample_key();
        let envelope = Envelope::seal(&vk, "主密码").unwrap();
        let recovered = envelope.unseal("主密码").unwrap();
        assert_eq!(recovered.expose(), vk.expose());
    }

    /// 错误凭据必定认证失败，错误文案属于「认证失败」类。
    #[test]
    fn 错误凭据认证失败() {
        let envelope = Envelope::seal(&sample_key(), "主密码").unwrap();
        let err = envelope.unseal("错误密码").unwrap_err();
        assert!(matches!(err, EnvelopeError::AuthFailed));
    }

    /// 篡改密文任一字节必被拒（首、中、尾三处抽样）。
    #[test]
    fn 篡改密文被拒() {
        let envelope = Envelope::seal(&sample_key(), "主密码").unwrap();
        for idx in [0usize, 24, CIPHERTEXT_LEN - 1] {
            let mut tampered = envelope.clone();
            tampered.ciphertext[idx] ^= 0x01;
            let err = tampered.unseal("主密码").unwrap_err();
            assert!(
                matches!(err, EnvelopeError::AuthFailed),
                "篡改位置 {idx} 未被拒"
            );
        }
    }

    /// 篡改盐必被拒（盐在 AAD 内且参与 KEK 派生）。
    #[test]
    fn 篡改盐被拒() {
        let envelope = Envelope::seal(&sample_key(), "主密码").unwrap();
        let mut tampered = envelope.clone();
        tampered.salt[0] ^= 0x01;
        let err = tampered.unseal("主密码").unwrap_err();
        assert!(matches!(err, EnvelopeError::AuthFailed));
    }

    /// 篡改封套内 kdf_version 必被拒：改出未知版本报 KDF 错误，绝不静默按旧参数解。
    #[test]
    fn 篡改kdf版本被拒() {
        let envelope = Envelope::seal(&sample_key(), "主密码").unwrap();
        assert_eq!(envelope.kdf_version, 1);
        let mut tampered = envelope.clone();
        tampered.kdf_version = 2;
        let err = tampered.unseal("主密码").unwrap_err();
        assert!(matches!(err, EnvelopeError::Kdf(kdf::KdfError::Unknown(2))));
    }

    /// 封套 AAD 只覆盖自身：封套间相互独立，重写其一不影响另一封套解封。
    /// 这是「主密码封套 / 恢复码封套」可独立轮换的结构保证。
    #[test]
    fn 重写一个封套不影响另一个() {
        let vk = sample_key();
        let main = Envelope::seal(&vk, "主密码").unwrap();
        let recovery = Envelope::seal(&vk, "恢复码").unwrap();

        // 模拟轮换：恢复码封套重写（新盐、新 nonce）
        let rotated = Envelope::seal(&vk, "新恢复码").unwrap();
        let _ = recovery;

        // 主密码封套不受影响
        let recovered = main.unseal("主密码").unwrap();
        assert_eq!(recovered.expose(), vk.expose());
        // 新恢复码封套可用
        let recovered = rotated.unseal("新恢复码").unwrap();
        assert_eq!(recovered.expose(), vk.expose());
    }

    /// 同一密钥同一凭据两次封存产出不同字节（盐与 nonce 均随机）。
    #[test]
    fn 两次封存字节不同() {
        let vk = sample_key();
        let a = Envelope::seal(&vk, "主密码").unwrap();
        let b = Envelope::seal(&vk, "主密码").unwrap();
        assert_ne!(a.salt, b.salt);
        assert_ne!(a.nonce, b.nonce);
        assert_ne!(a.ciphertext, b.ciphertext);
    }

    /// 序列化与解析往返一致；总长 78 字节。
    #[test]
    fn 字节往返一致() {
        assert_eq!(ENVELOPE_LEN, 78);
        let envelope = Envelope::seal(&sample_key(), "主密码").unwrap();
        let bytes = envelope.to_bytes();
        let parsed = Envelope::parse(&bytes).unwrap();
        assert_eq!(parsed, envelope);
    }

    /// 长度不符的封套字节报「数据损坏」，不与「认证失败」混淆。
    #[test]
    fn 解析长度不符报损坏() {
        for len in [0usize, 77, 79, 200] {
            let bytes = vec![0u8; len];
            let err = Envelope::parse(&bytes).unwrap_err();
            assert!(
                matches!(err, EnvelopeError::Corrupt(_)),
                "长度 {len} 应报 Corrupt"
            );
        }
    }

    /// 字节布局：salt + 2 字节大端版本 + nonce + 密文依次排列。
    #[test]
    fn 字节布局顺序正确() {
        let envelope = Envelope {
            salt: [0xAA; 16],
            kdf_version: 1,
            nonce: [0xBB; 12],
            ciphertext: [0xCC; 48],
        };
        let bytes = envelope.to_bytes();
        assert_eq!(&bytes[..16], &[0xAA; 16]);
        assert_eq!(&bytes[16..18], &[0x00, 0x01]);
        assert_eq!(&bytes[18..30], &[0xBB; 12]);
        assert_eq!(&bytes[30..78], &[0xCC; 48]);
    }
}
