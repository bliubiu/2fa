//! Steam Guard 验证码（TOTP 私有变体，无官方测试向量）。
//!
//! 算法：HMAC-SHA1 + RFC 4226 动态截断 + 自定义字母表（5 次 mod 26 / div 26 映射）。
//! 与 Aegis、steamguard-cli 的实现一致；本项目通过独立参考实现复算样本做交叉验证。

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;

/// Steam 自定义字母表：去掉易混淆字符（0/1/5/6/8/9 中保留数字 2/3/4/7 等）的 26 字符集。
const ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";

/// Steam Guard 计算错误。
#[derive(Debug, thiserror::Error)]
pub enum SteamError {
    /// HMAC 密钥构造失败（正常情况下不可达，类型上必须处理）。
    #[error("密钥长度非法")]
    InvalidKey,
}

/// 计算 Steam Guard 5 位验证码。
///
/// 计数器语义与标准 TOTP 相同：`floor(unix / 30)`，由调用方换算传入。
pub fn compute(key: &[u8], counter: u64) -> Result<String, SteamError> {
    let mut mac =
        <Hmac<Sha1> as KeyInit>::new_from_slice(key).map_err(|_| SteamError::InvalidKey)?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let d = digest.as_slice();
    let offset = (d[d.len() - 1] & 0x0f) as usize;
    let mut full = ((d[offset] & 0x7f) as u32) << 24
        | ((d[offset + 1] as u32) << 16)
        | ((d[offset + 2] as u32) << 8)
        | (d[offset + 3] as u32);
    let mut code = String::with_capacity(5);
    for _ in 0..5 {
        code.push(ALPHABET[(full % 26) as usize] as char);
        full /= 26;
    }
    Ok(code)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // 交叉验证样本来源说明：
    // Steam Guard 无官方测试向量。以下期望值由独立 Python 参考实现复算得出，
    // 算法逻辑与 steamguard-cli 及 Aegis 的 SteamOtpInfo 完全一致
    // （HMAC-SHA1(key, counter_be) → 末字节低 4 位偏移截断 31 位数 → 5 次 mod 26/div 26 取字母表）。
    // 复算脚本与 Rust 实现相互独立；M6 加固阶段如获得 Aegis/steamguard-cli 实机环境，再做一次实机对照。

    /// 样本一：RFC 4226 Appendix D 测试密钥（ASCII "12345678901234567890"，20 字节）。
    const RFC4226_KEY: &[u8] = b"12345678901234567890";
    const RFC4226_EXPECTED: [(&u64, &str); 5] = [
        (&0, "GG5F5"),
        (&1, "PV9M4"),
        (&2, "B26KJ"),
        (&3, "5H85C"),
        (&4, "6Y9J3"),
    ];

    /// 样本二：社区通用演示密钥（Base32 "JBSWY3DPEHPK3PXP"，解码为 10 字节）。
    const DEMO_KEY_B32: &str = "JBSWY3DPEHPK3PXP";
    /// counter 66666666 对应 unix 时间戳 2000000000（RFC 6238 测试时间点之一）。
    const DEMO_EXPECTED: [(&u64, &str); 3] = [(&0, "VH8YJ"), (&1, "2YXGV"), (&66666666, "HNCVQ")];

    #[test]
    fn rfc4226密钥样本() {
        for (&counter, expected) in RFC4226_EXPECTED {
            assert_eq!(
                compute(RFC4226_KEY, counter).unwrap(),
                expected,
                "counter={counter}"
            );
        }
    }

    #[test]
    fn 演示密钥样本() {
        let key = crate::domain::base32::decode_lenient(DEMO_KEY_B32).unwrap();
        for (&counter, expected) in DEMO_EXPECTED {
            assert_eq!(
                compute(&key, counter).unwrap(),
                expected,
                "counter={counter}"
            );
        }
    }

    /// 任意输入下输出恒为 5 位且字符全部落在自定义字母表内。
    #[test]
    fn 输出格式恒定() {
        let alphabet = "23456789BCDFGHJKMNPQRTVWXY";
        for counter in [0u64, 1, 42, u64::MAX] {
            for len in [0usize, 1, 20, 64] {
                let key: Vec<u8> = (0..len as u8)
                    .map(|i| i.wrapping_mul(97).wrapping_add(3))
                    .collect();
                let code = compute(&key, counter).unwrap();
                assert_eq!(code.len(), 5);
                assert!(
                    code.chars().all(|c| alphabet.contains(c)),
                    "counter={counter} len={len} code={code}"
                );
            }
        }
    }
}
