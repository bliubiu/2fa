//! Base32 编解码（RFC 4648 无填充变体 + 宽容解析）。
//!
//! 真实世界密钥经常不规范：缺 `=` 填充、混入空白、大小写混杂。
//! [`decode_lenient`] 统一宽容处理；[`encode`] 输出标准无填充大写形式。

use data_encoding::{BASE32_NOPAD, DecodeError};

/// Base32 解码失败（非法字符或非法长度）。
#[derive(Debug, thiserror::Error)]
#[error("Base32 解码失败：{0}")]
pub struct Base32Error(#[from] DecodeError);

/// 编码为 RFC 4648 无填充 Base32（大写）。
pub fn encode(data: &[u8]) -> String {
    BASE32_NOPAD.encode(data)
}

/// 宽容解码：忽略全部空白与 `=` 填充（含多余填充），接受小写；
/// 拒绝非法字符与非法长度（有效字符数 mod 8 ∉ {0, 2, 4, 5, 7}）。
pub fn decode_lenient(text: &str) -> Result<Vec<u8>, Base32Error> {
    let cleaned: String = text
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();
    Ok(BASE32_NOPAD.decode(cleaned.as_bytes())?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// RFC 4648 §10 官方编码向量（无填充变体即去掉 `=`）。
    #[test]
    fn rfc4648_编码向量() {
        assert_eq!(encode(b""), "");
        assert_eq!(encode(b"f"), "MY");
        assert_eq!(encode(b"fo"), "MZXQ");
        assert_eq!(encode(b"foo"), "MZXW6");
        assert_eq!(encode(b"foob"), "MZXW6YQ");
        assert_eq!(encode(b"fooba"), "MZXW6YTB");
        assert_eq!(encode(b"foobar"), "MZXW6YTBOI");
    }

    /// RFC 4648 §10 官方向量的宽容解码（原样输入，不带填充）。
    #[test]
    fn rfc4648_解码向量() {
        assert_eq!(decode_lenient("").unwrap(), b"");
        assert_eq!(decode_lenient("MY").unwrap(), b"f");
        assert_eq!(decode_lenient("MZXQ").unwrap(), b"fo");
        assert_eq!(decode_lenient("MZXW6").unwrap(), b"foo");
        assert_eq!(decode_lenient("MZXW6YQ").unwrap(), b"foob");
        assert_eq!(decode_lenient("MZXW6YTB").unwrap(), b"fooba");
        assert_eq!(decode_lenient("MZXW6YTBOI").unwrap(), b"foobar");
    }

    /// 带标准填充 `=` 的输入应被接受。
    #[test]
    fn 接受标准填充() {
        assert_eq!(decode_lenient("MY======").unwrap(), b"f");
        assert_eq!(decode_lenient("MZXW6YTBOI======").unwrap(), b"foobar");
    }

    /// 多余填充同样被接受（只看有效字符）。
    #[test]
    fn 接受多余填充() {
        assert_eq!(decode_lenient("MZXW6YTB====").unwrap(), b"fooba");
    }

    /// 真实世界密钥常含空格（手动抄写分组的习惯）。
    #[test]
    fn 忽略空白() {
        assert_eq!(decode_lenient("MZXW 6YTB").unwrap(), b"fooba");
        assert_eq!(decode_lenient("MZXW\t6YT\nBOI").unwrap(), b"foobar");
    }

    /// 接受小写输入。
    #[test]
    fn 接受小写() {
        assert_eq!(decode_lenient("mzxw6ytb").unwrap(), b"fooba");
        assert_eq!(decode_lenient("Mzxw6YtB").unwrap(), b"fooba");
    }

    /// 空白与填充混合后只剩合法符号。
    #[test]
    fn 空白与填充混合() {
        assert_eq!(decode_lenient(" m z x w 6 y t b = ").unwrap(), b"fooba");
    }

    /// 非法字符必须报错。
    #[test]
    fn 拒绝非法字符() {
        assert!(decode_lenient("MZXW6Y!1").is_err());
        assert!(decode_lenient("0OIL8Z").is_err());
    }

    /// 非法长度必须报错：无填充 Base32 合法长度 mod 8 ∈ {0,2,4,5,7}。
    #[test]
    fn 拒绝非法长度() {
        assert!(decode_lenient("M").is_err()); // 1 字符
        assert!(decode_lenient("MZX").is_err()); // 3 字符
        assert!(decode_lenient("MZXW6Y").is_err()); // 6 字符
    }

    /// 只含 `=` 的输入解码后为空，视为非法密钥由上层拦截；此处只保证不 panic。
    #[test]
    fn 只含填充字符() {
        assert_eq!(decode_lenient("======").unwrap(), b"");
    }

    /// 非法长度 + 多余填充组合仍要报错（先去填充再校验长度）。
    #[test]
    fn 非法长度带填充() {
        assert!(decode_lenient("M======").is_err());
    }

    /// 编码解码往返。
    #[test]
    fn 往返一致() {
        for len in 0..64usize {
            let data: Vec<u8> = (0..len as u8)
                .map(|i| i.wrapping_mul(37).wrapping_add(11))
                .collect();
            let encoded = encode(&data);
            assert_eq!(
                decode_lenient(&encoded).unwrap(),
                data,
                "长度 {len} 往返失败"
            );
        }
    }
}
