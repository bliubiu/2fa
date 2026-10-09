//! 保险库文件格式：明文头部 + AAD 认证 + 加密正文。
//!
//! 文件布局（`docs/adr/0003`）：
//!
//! ```text
//! [头部（明文，整体作为正文 GCM 的 AAD）]
//!   magic "2FAVLT\0"（7 字节）
//!   schema_version（u16 大端）
//!   envelope_count（u8）
//!   封套列表（envelope_count × 78 字节，各含盐与 kdf_version）
//!   nonce（12 字节，正文 GCM 专用）
//! [正文（密文）]
//!   JSON 明文的 AES-256-GCM 密文（含 16 字节认证标签）
//! ```
//!
//! AAD 纪律：**整个头部（含 magic 的全部字节）**参与正文认证——
//! 篡改 magic、schema_version、任一封套（含其盐与 kdf_version）或 nonce，
//! 正文解密必然失败。

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};

use super::envelope::{ENVELOPE_LEN, Envelope};
use super::key::VaultKey;

/// 文件魔数：`2FAVLT\0`。
pub const MAGIC: [u8; 7] = *b"2FAVLT\0";
/// 当前 schema 版本（与 KDF 版本相互独立）。
pub const SCHEMA_VERSION: u16 = 1;
/// 正文 GCM nonce 长度。
const NONCE_LEN: usize = 12;
/// 头部中除封套列表外的固定部分长度：magic + version + count + nonce。
const HEADER_FIXED_LEN: usize = 7 + 2 + 1 + NONCE_LEN;
/// 最小合法文件长度：最小头部 + 0 个封套 + 空……正文至少含 16 字节标签。
const MIN_FILE_LEN: usize = HEADER_FIXED_LEN + 16;

/// 文件格式错误。
#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    /// 魔数不符——这不是 2FA 保险库文件（区别于「密码错误」）。
    #[error("这不是 2FA 保险库文件（文件头魔数不符）")]
    NotAVault,
    /// 布局损坏：长度、封套数量或分段边界不符。
    #[error("保险库文件数据损坏：{0}")]
    Corrupt(&'static str),
    /// 正文认证失败：头部被篡改、正文被篡改，或解密密钥不正确。
    #[error("保险库正文认证失败：文件已被篡改，或解密密钥不正确")]
    AuthFailed,
    /// AEAD 运算失败（正常情况下不可达，类型上必须处理）。
    #[error("AEAD 运算失败：{0}")]
    Aead(#[from] aes_gcm::Error),
    /// AEAD 密钥构造失败（密钥长度恒为 32 字节，正常不可达，类型上必须处理）。
    #[error("AEAD 密钥构造失败")]
    InvalidKey,
    /// 操作系统 CSPRNG 读取失败。
    #[error("操作系统 CSPRNG 读取失败：{0}")]
    RandomSource(#[from] getrandom::Error),
    /// 封套处理失败。
    #[error("封套处理失败：{0}")]
    Envelope(#[from] super::envelope::EnvelopeError),
}

/// 已解析结构的保险库文件（正文保持密文，不透明）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultFile {
    /// schema 版本。
    pub schema_version: u16,
    /// 封套列表（主密码封套、恢复码封套等）。
    pub envelopes: Vec<Envelope>,
    /// 正文 GCM nonce。
    pub nonce: [u8; NONCE_LEN],
    /// 正文密文（含 GCM 标签）。
    pub body: Vec<u8>,
}

/// 组装头部字节：magic + schema_version + 封套列表 + nonce。
fn header_bytes(schema_version: u16, envelopes: &[Envelope], nonce: &[u8; NONCE_LEN]) -> Vec<u8> {
    let count = envelopes.len();
    debug_assert!(count <= u8::MAX as usize, "封套数量超出 u8 上限");
    let mut header = Vec::with_capacity(HEADER_FIXED_LEN + count * ENVELOPE_LEN);
    header.extend_from_slice(&MAGIC);
    header.extend_from_slice(&schema_version.to_be_bytes());
    header.push(count as u8);
    for envelope in envelopes {
        header.extend_from_slice(&envelope.to_bytes());
    }
    header.extend_from_slice(nonce);
    header
}

/// 封装完整保险库文件：随机 nonce，正文用保险库主密钥加密，AAD 为整个头部。
pub fn seal(
    vault_key: &VaultKey,
    envelopes: Vec<Envelope>,
    body: &[u8],
) -> Result<VaultFile, FormatError> {
    if envelopes.is_empty() {
        return Err(FormatError::Corrupt("至少需要一个封套"));
    }
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::fill(&mut nonce)?;
    let schema_version = SCHEMA_VERSION;
    let header = header_bytes(schema_version, &envelopes, &nonce);
    let cipher =
        Aes256Gcm::new_from_slice(vault_key.expose()).map_err(|_| FormatError::InvalidKey)?;
    let ciphertext = cipher.encrypt(
        &Nonce::from(nonce),
        Payload {
            msg: body,
            aad: &header,
        },
    )?;
    Ok(VaultFile {
        schema_version,
        envelopes,
        nonce,
        body: ciphertext,
    })
}

/// 用保险库主密钥解出正文 JSON（AAD 为整个头部，认证不过即「正文认证失败」）。
pub fn open(vault_key: &VaultKey, file: &VaultFile) -> Result<Vec<u8>, FormatError> {
    let header = header_bytes(file.schema_version, &file.envelopes, &file.nonce);
    let cipher =
        Aes256Gcm::new_from_slice(vault_key.expose()).map_err(|_| FormatError::InvalidKey)?;
    cipher
        .decrypt(
            &Nonce::from(file.nonce),
            Payload {
                msg: file.body.as_slice(),
                aad: &header,
            },
        )
        .map_err(|_| FormatError::AuthFailed)
}

impl VaultFile {
    /// 序列化为完整文件字节。
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = header_bytes(self.schema_version, &self.envelopes, &self.nonce);
        out.extend_from_slice(&self.body);
        out
    }

    /// 解析文件结构（不认证、不校验 schema 版本——版本治理归迁移链）。
    pub fn parse(bytes: &[u8]) -> Result<Self, FormatError> {
        if bytes.len() < 7 || bytes[..7] != MAGIC {
            return Err(FormatError::NotAVault);
        }
        if bytes.len() < MIN_FILE_LEN {
            return Err(FormatError::Corrupt("文件长度不足以容纳头部与正文"));
        }
        let schema_version = u16::from_be_bytes(
            bytes[7..9]
                .try_into()
                .map_err(|_| FormatError::Corrupt("schema_version 读取失败"))?,
        );
        let envelope_count = bytes[9] as usize;
        let envelopes_end = 10 + envelope_count * ENVELOPE_LEN;
        if bytes.len() < envelopes_end + NONCE_LEN {
            return Err(FormatError::Corrupt("封套列表超出文件边界"));
        }
        let mut envelopes = Vec::with_capacity(envelope_count);
        for i in 0..envelope_count {
            let start = 10 + i * ENVELOPE_LEN;
            let envelope = Envelope::parse(&bytes[start..start + ENVELOPE_LEN])?;
            envelopes.push(envelope);
        }
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&bytes[envelopes_end..envelopes_end + NONCE_LEN]);
        let body = bytes[envelopes_end + NONCE_LEN..].to_vec();
        Ok(Self {
            schema_version,
            envelopes,
            nonce,
            body,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn sample_key() -> VaultKey {
        VaultKey::new([0x5A; 32])
    }

    fn sample_envelopes(vault_key: &VaultKey) -> Vec<Envelope> {
        vec![
            Envelope::seal(vault_key, "主密码").unwrap(),
            Envelope::seal(vault_key, "恢复码").unwrap(),
        ]
    }

    const BODY_JSON: &str = r#"{"schema_version":1,"entries":[]}"#;

    /// 封装 → 序列化 → 解析 → 解封 → 解密，内容逐字段还原。
    #[test]
    fn 文件往返一致() {
        let vk = sample_key();
        let envelopes = sample_envelopes(&vk);
        let file = seal(&vk, envelopes, BODY_JSON.as_bytes()).unwrap();
        let bytes = file.to_bytes();

        let parsed = VaultFile::parse(&bytes).unwrap();
        assert_eq!(parsed.schema_version, SCHEMA_VERSION);
        assert_eq!(parsed.envelopes.len(), 2);

        // 任一封套凭据都能解出主密钥
        let recovered_key = parsed.envelopes[0].unseal("主密码").unwrap();
        assert_eq!(recovered_key.expose(), vk.expose());
        let recovered_key = parsed.envelopes[1].unseal("恢复码").unwrap();
        assert_eq!(recovered_key.expose(), vk.expose());

        // 正文解密
        let body = open(&recovered_key, &parsed).unwrap();
        assert_eq!(body, BODY_JSON.as_bytes());
    }

    /// 完整文件字节级往返：to_bytes → parse → to_bytes 逐字节一致。
    #[test]
    fn 字节级往返() {
        let vk = sample_key();
        let file = seal(&vk, sample_envelopes(&vk), BODY_JSON.as_bytes()).unwrap();
        let bytes = file.to_bytes();
        let reparsed = VaultFile::parse(&bytes).unwrap();
        assert_eq!(reparsed.to_bytes(), bytes);
    }

    /// 篡改 magic 任一字节：解析层即报「这不是 2FA 保险库文件」。
    #[test]
    fn 篡改magic报非保险库文件() {
        let vk = sample_key();
        let file = seal(&vk, sample_envelopes(&vk), BODY_JSON.as_bytes()).unwrap();
        for idx in 0..7 {
            let mut bytes = file.to_bytes();
            bytes[idx] ^= 0x01;
            let err = VaultFile::parse(&bytes).unwrap_err();
            assert!(
                matches!(err, FormatError::NotAVault),
                "magic 位置 {idx} 未识别"
            );
        }
    }

    /// 篡改 schema_version 必被拒：AAD 覆盖头部，正文认证失败。
    #[test]
    fn 篡改schema版本被拒() {
        let vk = sample_key();
        let file = seal(&vk, sample_envelopes(&vk), BODY_JSON.as_bytes()).unwrap();
        let mut bytes = file.to_bytes();
        bytes[8] ^= 0x02; // schema_version 低位字节翻转
        let parsed = VaultFile::parse(&bytes).unwrap();
        let err = open(&vk, &parsed).unwrap_err();
        assert!(matches!(err, FormatError::AuthFailed));
    }

    /// 篡改封套（盐 / kdf_version 字节）必被拒：正文认证失败。
    #[test]
    fn 篡改封套字段被拒() {
        let vk = sample_key();
        let file = seal(&vk, sample_envelopes(&vk), BODY_JSON.as_bytes()).unwrap();
        let bytes = file.to_bytes();
        // 头部固定部分 10 字节，第 0 个封套从偏移 10 开始：盐 [0..16]，kdf_version [16..18]
        for idx in [10usize, 17, 25] {
            let mut tampered = bytes.clone();
            tampered[idx] ^= 0x01;
            let parsed = VaultFile::parse(&tampered).unwrap();
            let err = open(&vk, &parsed).unwrap_err();
            assert!(
                matches!(err, FormatError::AuthFailed),
                "封套偏移 {idx} 未被拒"
            );
        }
    }

    /// 篡改正文 nonce 必被拒。
    #[test]
    fn 篡改正文nonce被拒() {
        let vk = sample_key();
        let file = seal(&vk, sample_envelopes(&vk), BODY_JSON.as_bytes()).unwrap();
        let mut bytes = file.to_bytes();
        // nonce 位于头部末尾：10 + 2*78 = 166，共 12 字节
        bytes[166] ^= 0x01;
        let parsed = VaultFile::parse(&bytes).unwrap();
        let err = open(&vk, &parsed).unwrap_err();
        assert!(matches!(err, FormatError::AuthFailed));
    }

    /// 篡改正文密文必被拒。
    #[test]
    fn 篡改正文被拒() {
        let vk = sample_key();
        let file = seal(&vk, sample_envelopes(&vk), BODY_JSON.as_bytes()).unwrap();
        let mut bytes = file.to_bytes();
        *bytes.last_mut().unwrap() ^= 0x01;
        let parsed = VaultFile::parse(&bytes).unwrap();
        let err = open(&vk, &parsed).unwrap_err();
        assert!(matches!(err, FormatError::AuthFailed));
    }

    /// 错误密码解封封套失败——文件层不产生误导性的「文件损坏」提示。
    #[test]
    fn 错误密码封套认证失败() {
        let vk = sample_key();
        let file = seal(&vk, sample_envelopes(&vk), BODY_JSON.as_bytes()).unwrap();
        let parsed = VaultFile::parse(&file.to_bytes()).unwrap();
        let err = parsed.envelopes[0].unseal("错误密码").unwrap_err();
        assert!(matches!(
            err,
            super::super::envelope::EnvelopeError::AuthFailed
        ));
    }

    /// 过短文件与空文件解析被拒。
    #[test]
    fn 过短文件被拒() {
        for len in [0usize, 5, 7, 10, MIN_FILE_LEN - 1] {
            let bytes = vec![0u8; len];
            let err = VaultFile::parse(&bytes).unwrap_err();
            assert!(
                matches!(err, FormatError::NotAVault | FormatError::Corrupt(_)),
                "长度 {len} 应被拒"
            );
        }
    }

    /// 魔数正确但封套列表越界 → 数据损坏。
    #[test]
    fn 封套越界报损坏() {
        let vk = sample_key();
        let file = seal(&vk, sample_envelopes(&vk), BODY_JSON.as_bytes()).unwrap();
        let mut bytes = file.to_bytes();
        bytes[9] = 200; // envelope_count 改大，越过正文边界
        let err = VaultFile::parse(&bytes).unwrap_err();
        assert!(matches!(err, FormatError::Corrupt(_)));
    }

    /// 无封套的文件在封装层被拒（格式层防御，调用方必须至少提供一个封套）。
    #[test]
    fn 无封套封装被拒() {
        let vk = sample_key();
        let err = seal(&vk, Vec::new(), BODY_JSON.as_bytes()).unwrap_err();
        assert!(matches!(err, FormatError::Corrupt(_)));
    }
}
