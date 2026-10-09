//! 恢复码生成与归一化。
//!
//! 恢复码 = 80 位 CSPRNG 随机 → Base32（RFC 4648 字母表 `A–Z` / `2–7`，
//! 天然不含易混淆的 `0` / `1` / `8` / `9`）→ 16 字符，展示按 4 字符分组。
//!
//! 封套凭据使用**归一化形式**（大写、无分隔符）；用户输入统一经
//! [`normalize`] 归一后再参与解封，兼容小写、空白与连字符输入。

use data_encoding::BASE32_NOPAD;

/// 恢复码随机字节数（10 字节 = 80 位熵 = 16 个 Base32 字符）。
const RANDOM_BYTES: usize = 10;
/// 展示分组长度。
const GROUP_LEN: usize = 4;

/// 恢复码相关错误。
#[derive(Debug, thiserror::Error)]
pub enum RecoveryError {
    /// 操作系统 CSPRNG 读取失败。
    #[error("操作系统 CSPRNG 读取失败：{0}")]
    RandomSource(#[from] getrandom::Error),
}

/// 生成新恢复码（展示形式：`XXXX-XXXX-XXXX-XXXX`）。
pub fn generate() -> Result<String, RecoveryError> {
    let mut bytes = [0u8; RANDOM_BYTES];
    getrandom::fill(&mut bytes)?;
    Ok(group(&BASE32_NOPAD.encode(&bytes)))
}

/// 归一化用户输入的恢复码：去除空白与连字符、统一大写。
///
/// 归一化结果即封套凭据——[`generate`] 产出经本函数归一后不变。
pub fn normalize(input: &str) -> String {
    input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .flat_map(char::to_uppercase)
        .collect()
}

/// 展示形式分组：每 4 个字符插入一个连字符。
fn group(text: &str) -> String {
    text.chars()
        .collect::<Vec<_>>()
        .chunks(GROUP_LEN)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// 展示形式：4 组、每组 4 字符、连字符分隔。
    #[test]
    fn 展示形式四组四字符() {
        let code = generate().unwrap();
        let groups: Vec<&str> = code.split('-').collect();
        assert_eq!(groups.len(), 4);
        assert!(groups.iter().all(|g| g.len() == 4), "实际 {code}");
    }

    /// 字符全部属于 Base32 字母表（A–Z、2–7）。
    #[test]
    fn 字符属于base32字母表() {
        for _ in 0..20 {
            let code = generate().unwrap();
            for c in code.chars().filter(|c| *c != '-') {
                assert!(
                    c.is_ascii_uppercase() || ('2'..='7').contains(&c),
                    "非法字符 {c}"
                );
            }
        }
    }

    /// 连续生成 100 个恢复码无重复（80 位熵的最低检出线）。
    #[test]
    fn 生成一百个无重复() {
        let codes: HashSet<String> = (0..100).map(|_| generate().unwrap()).collect();
        assert_eq!(codes.len(), 100);
    }

    /// 归一化：小写、空白、连字符统一去除并转大写。
    #[test]
    fn 归一化规则() {
        assert_eq!(normalize("abcd-efgh-jklm-npqr"), "ABCDEFGHJKLMNPQR");
        assert_eq!(normalize(" ABCD EFGH "), "ABCDEFGH");
        assert_eq!(normalize("abcd"), "ABCD");
    }

    /// 生成的恢复码经归一化后等于去除连字符的原串（自洽）。
    #[test]
    fn 生成后归一化自洽() {
        let code = generate().unwrap();
        assert_eq!(normalize(&code), code.replace('-', ""));
    }
}
