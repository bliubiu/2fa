//! TOTP 计算内核（RFC 6238 / RFC 4226 动态截断）。
//!
//! 纯函数、不读系统时钟：时间步计数器由调用方换算后传入（见 [`super::counter`]），
//! 这样 RFC 测试向量可以直接喂固定值。

use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};

/// OTP 哈希算法。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1,
    Sha256,
    Sha512,
}

/// TOTP 计算错误。
#[derive(Debug, thiserror::Error)]
pub enum TotpError {
    /// 位数为 6 / 8 之外的值；不做静默截断。
    #[error("不支持的位数：{0}（仅支持 6 位与 8 位）")]
    InvalidDigits(u8),
    /// HMAC 密钥构造失败（正常情况下不可达，类型上必须处理）。
    #[error("密钥长度非法")]
    InvalidKey,
}

/// 计算一次 HMAC：输入为大端 8 字节计数器，输出为完整摘要。
macro_rules! digest_with {
    ($ty:ty, $key:expr, $counter:expr) => {{
        let mut m =
            <Hmac<$ty> as KeyInit>::new_from_slice($key).map_err(|_| TotpError::InvalidKey)?;
        m.update(&($counter).to_be_bytes());
        m.finalize().into_bytes().to_vec()
    }};
}

/// 计算验证码：`counter` 为时间步计数器（HOTP 语义，TOTP 即计数器 = floor(unix/period)）。
///
/// 返回十进制数值形式的验证码；展示时按位数前导补零。
pub fn compute(
    key: &[u8],
    counter: u64,
    algorithm: Algorithm,
    digits: u8,
) -> Result<u32, TotpError> {
    match digits {
        6 | 8 => {}
        _ => return Err(TotpError::InvalidDigits(digits)),
    }
    let mac: Vec<u8> = match algorithm {
        Algorithm::Sha1 => digest_with!(Sha1, key, counter),
        Algorithm::Sha256 => digest_with!(Sha256, key, counter),
        Algorithm::Sha512 => digest_with!(Sha512, key, counter),
    };
    Ok(truncate(&mac, digits))
}

/// RFC 4226 §5.3 动态截断：末字节低 4 位为偏移，截取 4 字节、去掉最高符号位后对 `10^位数` 取模。
fn truncate(mac: &[u8], digits: u8) -> u32 {
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let bin = ((mac[offset] as u32) & 0x7f) << 24
        | ((mac[offset + 1] as u32) << 16)
        | ((mac[offset + 2] as u32) << 8)
        | (mac[offset + 3] as u32);
    bin % 10u32.pow(u32::from(digits))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// RFC 4226 Appendix D 测试密钥：ASCII "12345678901234567890"（20 字节）。
    const RFC4226_KEY: &[u8] = b"12345678901234567890";
    /// RFC 4226 Appendix D 全部 10 组向量（6 位）。
    const RFC4226_CODES: [u32; 10] = [
        755224, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
    ];

    /// RFC 6238 Appendix B 的 6 个测试时间点（秒）。
    const TIMES: [i64; 6] = [
        59,
        1111111109,
        1111111111,
        1234567890,
        2000000000,
        20000000000,
    ];
    /// RFC 6238 Appendix B：SHA1（20 字节 seed，与 RFC 4226 密钥相同），8 位展示。
    const SHA1_8: [&str; 6] = [
        "94287082", "07081804", "14050471", "89005924", "69279037", "65353130",
    ];
    /// RFC 6238 Appendix B：SHA256（32 字节 seed——与 SHA1 不同长度，这是最常见实现错误）。
    const SHA256_KEY: &[u8] = b"12345678901234567890123456789012";
    const SHA256_8: [&str; 6] = [
        "46119246", "68084774", "67062674", "91819424", "90698825", "77737706",
    ];
    /// RFC 6238 Appendix B：SHA512（64 字节 seed）。
    const SHA512_KEY: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";
    const SHA512_8: [&str; 6] = [
        "90693936", "25091201", "99943326", "93441116", "38618901", "47863826",
    ];

    /// RFC 4226 Appendix D 全部 8 组向量（10 组含 counter 0..=9，TOTP 内核即带计数器的 HOTP）。
    #[test]
    fn rfc4226_全部向量() {
        for (counter, &expected) in RFC4226_CODES.iter().enumerate() {
            let code = compute(RFC4226_KEY, counter as u64, Algorithm::Sha1, 6).unwrap();
            assert_eq!(code, expected, "计数器 {counter} 的验证码不符");
        }
    }

    #[test]
    fn rfc6238_sha1_全部时间点() {
        for (i, &t) in TIMES.iter().enumerate() {
            let code = compute(RFC4226_KEY, (t / 30) as u64, Algorithm::Sha1, 8).unwrap();
            assert_eq!(format!("{code:08}"), SHA1_8[i], "SHA1 时间点 {} 不符", t);
        }
    }

    #[test]
    fn rfc6238_sha256_全部时间点() {
        for (i, &t) in TIMES.iter().enumerate() {
            let code = compute(SHA256_KEY, (t / 30) as u64, Algorithm::Sha256, 8).unwrap();
            assert_eq!(
                format!("{code:08}"),
                SHA256_8[i],
                "SHA256 时间点 {} 不符",
                t
            );
        }
    }

    #[test]
    fn rfc6238_sha512_全部时间点() {
        for (i, &t) in TIMES.iter().enumerate() {
            let code = compute(SHA512_KEY, (t / 30) as u64, Algorithm::Sha512, 8).unwrap();
            assert_eq!(
                format!("{code:08}"),
                SHA512_8[i],
                "SHA512 时间点 {} 不符",
                t
            );
        }
    }

    /// RFC 6238 的 6 位输出为 8 位展示值的后 6 位（同源模运算关系）。
    #[test]
    fn rfc6238_6位为8位后六位() {
        for (i, &t) in TIMES.iter().enumerate() {
            let code = compute(RFC4226_KEY, (t / 30) as u64, Algorithm::Sha1, 6).unwrap();
            let expected: String = SHA1_8[i][2..].to_string();
            assert_eq!(format!("{code:06}"), expected);
        }
    }

    /// 边界计数器 0 与 u64::MAX 必须可计算且结果落在位数范围内。
    #[test]
    fn 边界计数器不溢出() {
        for counter in [0u64, u64::MAX] {
            for alg in [Algorithm::Sha1, Algorithm::Sha256, Algorithm::Sha512] {
                for digits in [6u8, 8u8] {
                    let code = compute(RFC4226_KEY, counter, alg, digits).unwrap();
                    assert!(code < 10u32.pow(u32::from(digits)));
                }
            }
        }
    }

    /// 非法位数立即报错，不做静默截断。
    #[test]
    fn 非法位数报错() {
        for digits in [0u8, 5, 7, 9, 10, 255] {
            let err = compute(RFC4226_KEY, 0, Algorithm::Sha1, digits).unwrap_err();
            assert!(matches!(err, TotpError::InvalidDigits(_)));
        }
    }
}
