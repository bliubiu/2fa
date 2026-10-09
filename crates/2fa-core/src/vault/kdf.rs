//! KDF 版本查表与主密码派生（Argon2id）。
//!
//! 参数为静态查表：版本号 → 参数，不提供任何运行时自定义入口；
//! 未知版本直接报错，绝不回退到默认参数（防止 KDF 参数被静默降级篡改，
//! 见 `docs/adr/0003`）。

use argon2::{Algorithm, Argon2, Params, Version};

use super::key::VaultKey;

/// KDF 版本号（schema 中随封套存储，位于 GCM AAD 覆盖范围内）。
pub type KdfVersion = u16;

/// 当前最高 KDF 版本。
pub const CURRENT_VERSION: KdfVersion = 1;

/// 单个 KDF 版本的完整参数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KdfParams {
    /// 版本号。
    pub version: KdfVersion,
    /// 内存开销（KiB）。
    pub m_cost_kib: u32,
    /// 时间开销（迭代次数）。
    pub t_cost: u32,
    /// 并行度。
    pub p_cost: u32,
}

/// v1：OWASP 建议的第二档配置（19 MiB / 2 次 / 1 线程），单次解锁约数十毫秒级。
const V1: KdfParams = KdfParams {
    version: 1,
    m_cost_kib: 19_456,
    t_cost: 2,
    p_cost: 1,
};

/// 查询版本对应的 KDF 参数；未知版本报错，不回退默认值。
pub fn params(version: KdfVersion) -> Result<KdfParams, KdfError> {
    match version {
        1 => Ok(V1),
        unknown => Err(KdfError::Unknown(unknown)),
    }
}

/// KDF 派生错误。
#[derive(Debug, thiserror::Error)]
pub enum KdfError {
    /// 未知 KDF 版本——可能是未来版本写的文件被旧程序读取，或参数被篡改。
    #[error("未知的 KDF 版本：{0}（当前支持到 {CURRENT_VERSION}，请升级程序，不做降级尝试）")]
    Unknown(KdfVersion),
    /// Argon2id 参数构造或派生过程失败。
    #[error("Argon2id 派生失败：{0}")]
    Argon2(#[from] argon2::Error),
}

/// 由主密码派生保险库主密钥（AES-256，32 字节），结果零化。
pub fn derive(
    master_password: &str,
    salt: &[u8],
    version: KdfVersion,
) -> Result<VaultKey, KdfError> {
    let p = params(version)?;
    let argon2 = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(p.m_cost_kib, p.t_cost, p.p_cost, Some(32))?,
    );
    let mut out = [0u8; 32];
    argon2.hash_password_into(master_password.as_bytes(), salt, &mut out)?;
    Ok(VaultKey::new(out))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// v1 派生结果长度恒为 32 字节（AES-256 要求）。
    #[test]
    fn v1_派生结果长度正确() {
        let key = derive("主密码测试", &[0u8; 16], 1).unwrap();
        assert_eq!(key.expose().len(), 32);
    }

    /// 同一输入可复现：相同密码与盐必须产出相同密钥。
    #[test]
    fn v1_同一输入可复现() {
        let a = derive("同一密码", &[7u8; 16], 1).unwrap();
        let b = derive("同一密码", &[7u8; 16], 1).unwrap();
        assert_eq!(a.expose(), b.expose());
    }

    /// 不同盐产出不同结果（盐的随机性由调用方保证，此处验证派生不折叠盐）。
    #[test]
    fn v1_不同盐产出不同结果() {
        let a = derive("同一密码", &[7u8; 16], 1).unwrap();
        let b = derive("同一密码", &[8u8; 16], 1).unwrap();
        assert_ne!(a.expose(), b.expose());
    }

    /// 未知版本报错，不回退默认参数。
    #[test]
    fn 未知版本报错() {
        for version in [0u16, 2, 99, u16::MAX] {
            let err = derive("任意", &[0u8; 16], version).unwrap_err();
            assert!(
                matches!(err, KdfError::Unknown(_)),
                "版本 {version} 应报 Unknown"
            );
        }
    }

    /// 派生结果非全零（退化实现的最低检出线）。
    #[test]
    fn v1_派生结果非全零() {
        let key = derive("主密码测试", &[0u8; 16], 1).unwrap();
        assert!(key.expose().iter().any(|&b| b != 0));
    }

    /// 参数表：v1 参数与规格一致；查表返回完整参数副本。
    #[test]
    fn 参数表_v1规格() {
        assert_eq!(
            params(1).unwrap(),
            KdfParams {
                version: 1,
                m_cost_kib: 19_456,
                t_cost: 2,
                p_cost: 1,
            }
        );
        assert_eq!(CURRENT_VERSION, 1);
    }

    /// 与独立参考实现（Python argon2-cffi，绑定参考 C 实现，与 RustCrypto crate
    /// 无共享代码）交叉验证 v1 参数的派生输出。
    ///
    /// 参考向量生成脚本（memory_cost 单位 KiB，version 0x13 = 19）：
    /// ```python
    /// from argon2.low_level import hash_secret_raw, Type
    /// hash_secret_raw(secret="交叉验证密码".encode(), salt=bytes(range(16)),
    ///                 time_cost=2, memory_cost=19456, parallelism=1,
    ///                 hash_len=32, type=Type.ID, version=19).hex()
    /// ```
    #[test]
    fn v1_与参考实现交叉验证() {
        let salt: Vec<u8> = (0u8..16).collect();
        let key = derive("交叉验证密码", &salt, 1).unwrap();
        let expected: [u8; 32] = [
            0x31, 0xbf, 0x15, 0x8d, 0x0e, 0x10, 0x44, 0xaa, 0x1c, 0xa8, 0x6f, 0xac, 0x57, 0xd3,
            0x74, 0x3f, 0x98, 0x69, 0x25, 0xf4, 0xcd, 0x3b, 0xe4, 0xd1, 0x04, 0x95, 0x0c, 0xa7,
            0x34, 0x37, 0x58, 0x98,
        ];
        assert_eq!(key.expose(), &expected);
    }
}
