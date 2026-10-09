//! 保险库密钥类型与操作系统 CSPRNG 随机源。
//!
//! 安全约束（见 `docs/01` 安全红线）：
//! - 全部密钥类型禁止 `Clone`/`Copy`——一个派生副本会产生 `Drop` 零化覆盖不到的残留
//! - `Debug` 固定输出 `«已隐藏»`，使密钥在类型层面不可被打印（含日志与错误路径）
//! - 随机数一律来自操作系统 CSPRNG（`getrandom`），禁止任何伪随机或退化实现

use core::fmt;
use zeroize::Zeroizing;

use crate::domain::base32;

/// 密钥相关操作错误。
#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    /// 操作系统 CSPRNG 读取失败（正常系统上不可达，但类型上必须处理）。
    #[error("操作系统 CSPRNG 读取失败：{0}")]
    RandomSource(#[from] getrandom::Error),
    /// 密钥 Base32 解码失败（非法字符或非法长度）。
    #[error("密钥 Base32 解码失败：{0}")]
    Base32(#[from] base32::Base32Error),
    /// 密钥解码后为空。
    #[error("密钥不能为空")]
    EmptySecret,
}

/// 保险库主密钥：解锁后的对称密钥，用于加解密保险库正文。
///
/// 32 字节（AES-256），`Zeroizing` 包装、禁止 `Clone`。
pub struct VaultKey(Zeroizing<[u8; 32]>);

impl VaultKey {
    /// 从操作系统 CSPRNG 生成随机主密钥。
    pub fn generate() -> Result<Self, KeyError> {
        let mut bytes = [0u8; 32];
        getrandom::fill(&mut bytes)?;
        Ok(Self(Zeroizing::new(bytes)))
    }

    /// 包装既有 32 字节（如 KDF 派生结果），字节随之进入零化管辖。
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    /// 暴露密钥字节。仅供加密原语使用，调用方不得复制或打印。
    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for VaultKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // 类型层面禁止泄露：任何 Debug/日志路径只会得到这个占位串
        write!(f, "«已隐藏»")
    }
}

/// 账号 OTP 密钥：Base32 文本的零化包装，禁止 `Clone`/`Copy`。
///
/// 内部恒为规范形式（大写、无填充、无空白），序列化与展示直接可用。
pub struct SecretKey(Zeroizing<String>);

impl SecretKey {
    /// 从真实世界的 Base32 文本构造（宽容解析：接受小写、空白、`=` 填充）。
    pub fn from_base32(text: &str) -> Result<Self, KeyError> {
        let raw = base32::decode_lenient(text)?;
        if raw.is_empty() {
            return Err(KeyError::EmptySecret);
        }
        Ok(Self(Zeroizing::new(base32::encode(&raw))))
    }

    /// 规范 Base32 文本（大写、无填充），供序列化与 otpauth 序列化使用。
    pub fn as_text(&self) -> &str {
        &self.0
    }

    /// 解码后的原始字节，供 TOTP 计算使用；缓冲零化。
    pub fn to_bytes(&self) -> Result<Zeroizing<Vec<u8>>, KeyError> {
        Ok(Zeroizing::new(base32::decode_lenient(&self.0)?))
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "«已隐藏»")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// 连续生成 100 个密钥无重复。
    #[test]
    fn 生成一百个密钥无重复() {
        let keys: HashSet<[u8; 32]> = (0..100)
            .map(|_| VaultKey::generate().unwrap().expose().to_owned())
            .collect();
        assert_eq!(keys.len(), 100);
    }

    /// 生成的密钥非全零（退化实现的最低检出线）。
    #[test]
    fn 生成密钥非全零() {
        let key = VaultKey::generate().unwrap();
        assert!(key.expose().iter().any(|&b| b != 0));
    }

    /// `Debug` 固定输出 `«已隐藏»`，不泄露任何密钥字节。
    #[test]
    fn vault_key_debug不泄露() {
        let key = VaultKey::new([0xAA; 32]);
        let text = format!("{key:?}");
        assert_eq!(text, "«已隐藏»");
    }

    /// `SecretKey` 的 `Debug` 同样固定输出 `«已隐藏»`。
    #[test]
    fn secret_key_debug不泄露() {
        let key = SecretKey::from_base32("mzxw6ytboi").unwrap();
        assert_eq!(format!("{key:?}"), "«已隐藏»");
    }

    /// 宽容解析：小写、空白、填充统一归一化为大写无填充。
    #[test]
    fn secret_key_规范化() {
        let key = SecretKey::from_base32(" mzxw 6YTB oi====== ").unwrap();
        assert_eq!(key.as_text(), "MZXW6YTBOI");
    }

    /// 解码字节与原文本一致（供 TOTP 计算使用）。
    #[test]
    fn secret_key_解码字节() {
        let key = SecretKey::from_base32("MZXW6YTBOI").unwrap();
        assert_eq!(key.to_bytes().unwrap().as_slice(), b"foobar");
    }

    /// 空密钥（空串或只含填充）必须拒绝。
    #[test]
    fn secret_key_拒绝空密钥() {
        let err = SecretKey::from_base32("======").unwrap_err();
        assert!(matches!(err, KeyError::EmptySecret));
        assert!(SecretKey::from_base32("").is_err());
    }

    /// 非法 Base32 字符必须拒绝。
    #[test]
    fn secret_key_拒绝非法字符() {
        assert!(SecretKey::from_base32("MZXW6Y!1").is_err());
    }

    /// 包装既有字节后内容不变（KDF 派生结果入库路径）。
    #[test]
    fn vault_key_包装既有字节() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0x42;
        let key = VaultKey::new(bytes);
        assert_eq!(key.expose()[0], 0x42);
    }
}
