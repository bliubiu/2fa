//! otpauth URI 解析与序列化。
//!
//! 支持 `otpauth://totp/<label>?secret=&issuer=&algorithm=&digits=&period=`。
//! issuer 冲突以 query 为准（与 Google Authenticator 一致）并记录警告；
//! 未知参数一律忽略；不支持 HOTP（`otpauth://hotp/` 直接拒绝）。

use crate::domain::counter::DEFAULT_PERIOD;
use crate::domain::totp::Algorithm;

/// 输入长度上限（字节），防止畸形超长输入拖垮解析。
const MAX_INPUT_LEN: usize = 4096;

/// otpauth URI 解析错误。
#[derive(Debug, thiserror::Error)]
pub enum OtpauthError {
    /// 输入超过长度上限。
    #[error("输入过长（上限 {MAX_INPUT_LEN} 字节）")]
    TooLong,
    /// scheme 不是 `otpauth://`。
    #[error("这不是 otpauth:// URI")]
    NotOtpauth,
    /// 类型不是 totp（本项目刻意不支持 HOTP）。
    #[error("不支持的 otpauth 类型「{0}」（仅支持 totp）")]
    UnsupportedType(String),
    /// 缺少必需的 secret 参数。
    #[error("缺少必需的 secret 参数")]
    MissingSecret,
    /// algorithm 参数非法。
    #[error("algorithm 参数非法：{0}")]
    InvalidAlgorithm(String),
    /// digits 参数非法（仅支持 6 与 8）。
    #[error("digits 参数非法：{0}")]
    InvalidDigits(String),
    /// period 参数非法（必须是正整数）。
    #[error("period 参数非法：{0}")]
    InvalidPeriod(String),
    /// 百分号解码失败或 UTF-8 非法。
    #[error("百分号编码非法")]
    InvalidEncoding,
}

/// 解析出的一枚 TOTP URI 载荷。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpauthUri {
    /// 服务商名（统一后的结果；可能为空）。
    pub issuer: Option<String>,
    /// 账号名（可能为空）。
    pub account: Option<String>,
    /// 密钥的 Base32 文本（原样保留，宽容解码在计算前进行）。
    pub secret: String,
    /// 哈希算法，默认 SHA1。
    pub algorithm: Algorithm,
    /// 位數，默认 6。
    pub digits: u8,
    /// 时间步长（秒），默认 30。
    pub period: u32,
    /// 解析过程中的警告（如 issuer 冲突）。
    pub warnings: Vec<String>,
}

/// 解析 otpauth URI。
pub fn parse(input: &str) -> Result<OtpauthUri, OtpauthError> {
    if input.len() > MAX_INPUT_LEN {
        return Err(OtpauthError::TooLong);
    }
    let (scheme, rest) = input.split_once("://").ok_or(OtpauthError::NotOtpauth)?;
    if !scheme.eq_ignore_ascii_case("otpauth") {
        return Err(OtpauthError::NotOtpauth);
    }
    // 类型与 label 与 query 的切分
    let (typ, rest) = rest.split_once('/').ok_or(OtpauthError::NotOtpauth)?;
    if !typ.eq_ignore_ascii_case("totp") {
        return Err(OtpauthError::UnsupportedType(typ.to_string()));
    }
    let (raw_label, query) = match rest.split_once('?') {
        Some((l, q)) => (l, q),
        None => (rest, ""),
    };
    let label = percent_decode(raw_label)?;

    // label 拆分：第一个冒号分隔「服务商:账号」；无冒号时整个 label 作为服务商
    let (path_issuer, account) = match label.split_once(':') {
        Some((i, a)) => (non_empty(i), non_empty(a)),
        None => (non_empty(&label), None),
    };

    // query 解析：k=v 用 & 分隔；未知参数一律忽略
    let mut secret: Option<String> = None;
    let mut query_issuer: Option<String> = None;
    let mut algorithm: Option<Algorithm> = None;
    let mut digits: Option<u8> = None;
    let mut period: Option<u32> = None;
    for pair in query.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            continue;
        };
        let value = percent_decode(value)?;
        match key.to_ascii_lowercase().as_str() {
            "secret" => secret = non_empty(&value).map(str::to_string),
            "issuer" => query_issuer = non_empty(&value).map(str::to_string),
            "algorithm" => {
                algorithm = Some(match value.to_ascii_uppercase().as_str() {
                    "SHA1" => Algorithm::Sha1,
                    "SHA256" => Algorithm::Sha256,
                    "SHA512" => Algorithm::Sha512,
                    other => return Err(OtpauthError::InvalidAlgorithm(other.to_string())),
                });
            }
            "digits" => {
                let d = value
                    .parse::<u8>()
                    .map_err(|_| OtpauthError::InvalidDigits(value.clone()))?;
                if d != 6 && d != 8 {
                    return Err(OtpauthError::InvalidDigits(value));
                }
                digits = Some(d);
            }
            "period" => {
                let p = value
                    .parse::<u32>()
                    .map_err(|_| OtpauthError::InvalidPeriod(value.clone()))?;
                if p == 0 {
                    return Err(OtpauthError::InvalidPeriod(value));
                }
                period = Some(p);
            }
            _ => {}
        }
    }

    let secret = secret.ok_or(OtpauthError::MissingSecret)?;

    // issuer 冲突统一：query 优先于路径前缀，不一致时记录警告
    let mut warnings = Vec::new();
    let issuer = match (&query_issuer, &path_issuer) {
        (Some(q), Some(p)) => {
            if q != p {
                warnings.push(format!(
                    "服务商名冲突：路径「{p}」与 query「{q}」不一致，已采用 query 值"
                ));
            }
            Some(q.clone())
        }
        (Some(q), None) => Some(q.clone()),
        (None, p) => p.map(str::to_string),
    };

    Ok(OtpauthUri {
        issuer,
        account: account.map(str::to_string),
        secret,
        algorithm: algorithm.unwrap_or(Algorithm::Sha1),
        digits: digits.unwrap_or(6),
        period: period.unwrap_or(DEFAULT_PERIOD),
        warnings,
    })
}

impl std::fmt::Display for Algorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Algorithm::Sha1 => "SHA1",
            Algorithm::Sha256 => "SHA256",
            Algorithm::Sha512 => "SHA512",
        })
    }
}

/// 序列化为 otpauth URI（供明文导出使用）。
///
/// issuer 同时写入 label 前缀与 query（与主流实现输出习惯一致）。
pub fn to_uri(uri: &OtpauthUri) -> String {
    let mut out = String::from("otpauth://totp/");
    match (&uri.issuer, &uri.account) {
        (Some(i), Some(a)) => {
            out.push_str(&percent_encode(i));
            out.push(':');
            out.push_str(&percent_encode(a));
        }
        (Some(i), None) => out.push_str(&percent_encode(i)),
        // 无 issuer 时的空前缀「:账号」保证往返：解析规则把无冒号 label 整体视为服务商
        (None, Some(a)) => {
            out.push(':');
            out.push_str(&percent_encode(a));
        }
        (None, None) => {}
    }
    out.push_str("?secret=");
    out.push_str(&uri.secret);
    if let Some(i) = &uri.issuer {
        out.push_str("&issuer=");
        out.push_str(&percent_encode(i));
    }
    out.push_str("&algorithm=");
    out.push_str(&uri.algorithm.to_string());
    out.push_str("&digits=");
    out.push_str(&uri.digits.to_string());
    out.push_str("&period=");
    out.push_str(&uri.period.to_string());
    out
}

/// 空白trim后非空才返回 Some。
fn non_empty(s: &str) -> Option<&str> {
    let t = s.trim();
    if t.is_empty() { None } else { Some(t) }
}

/// 百分号解码，失败（非法转义或非 UTF-8）报错。
fn percent_decode(s: &str) -> Result<String, OtpauthError> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len() {
                return Err(OtpauthError::InvalidEncoding);
            }
            let hi = (bytes[i + 1] as char)
                .to_digit(16)
                .ok_or(OtpauthError::InvalidEncoding)?;
            let lo = (bytes[i + 2] as char)
                .to_digit(16)
                .ok_or(OtpauthError::InvalidEncoding)?;
            out.push((hi * 16 + lo) as u8);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| OtpauthError::InvalidEncoding)
}

/// 百分号编码：仅保留 unreserved 字符（RFC 3986），其余按 UTF-8 字节转义。
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*b as char)
            }
            other => out.push_str(&format!("%{other:02X}")),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// 标准样例：全参数齐全。
    #[test]
    fn 标准样例() {
        let uri = parse("otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60").unwrap();
        assert_eq!(uri.issuer.as_deref(), Some("GitHub"));
        assert_eq!(uri.account.as_deref(), Some("alice"));
        assert_eq!(uri.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(uri.algorithm, Algorithm::Sha256);
        assert_eq!(uri.digits, 8);
        assert_eq!(uri.period, 60);
        assert!(uri.warnings.is_empty());
    }

    /// 默认值：只给 secret 时 algorithm=SHA1、digits=6、period=30。
    #[test]
    fn 默认值() {
        let uri = parse("otpauth://totp/GitHub:alice?secret=ABC").unwrap();
        assert_eq!(uri.algorithm, Algorithm::Sha1);
        assert_eq!(uri.digits, 6);
        assert_eq!(uri.period, DEFAULT_PERIOD);
    }

    /// issuer 冲突：query 优先于路径前缀，并记录警告。
    #[test]
    fn issuer冲突_query优先() {
        let uri = parse("otpauth://totp/GitHub:alice?secret=ABC&issuer=GitHub2").unwrap();
        assert_eq!(uri.issuer.as_deref(), Some("GitHub2"));
        assert_eq!(uri.warnings.len(), 1);
        assert!(uri.warnings[0].contains("GitHub"));
        assert!(uri.warnings[0].contains("GitHub2"));
    }

    /// issuer 仅路径前缀存在时直接采用，且不产生警告。
    #[test]
    fn issuer单边存在() {
        let only_path = parse("otpauth://totp/GitHub:alice?secret=ABC").unwrap();
        assert_eq!(only_path.issuer.as_deref(), Some("GitHub"));
        assert!(only_path.warnings.is_empty());
        // label 无冒号时整个 label 视为服务商（实施计划 M1-5），
        // 因此与 query issuer 形成冲突，query 胜出并记录警告
        let conflict = parse("otpauth://totp/alice?secret=ABC&issuer=GitHub").unwrap();
        assert_eq!(conflict.issuer.as_deref(), Some("GitHub"));
        assert_eq!(conflict.account, None);
        assert_eq!(conflict.warnings.len(), 1);
    }

    /// 中文服务商名的百分号解码。
    #[test]
    fn 中文服务商名() {
        let uri = parse("otpauth://totp/%E7%BD%91%E6%98%93:alice@163.com?secret=ABC").unwrap();
        assert_eq!(uri.issuer.as_deref(), Some("网易"));
        assert_eq!(uri.account.as_deref(), Some("alice@163.com"));
    }

    /// label 无冒号：整个 label 作为服务商，账号为空。
    #[test]
    fn label无冒号() {
        let uri = parse("otpauth://totp/GitHub?secret=ABC").unwrap();
        assert_eq!(uri.issuer.as_deref(), Some("GitHub"));
        assert_eq!(uri.account, None);
    }

    /// label 含多个冒号：以第一个冒号分隔。
    #[test]
    fn label多冒号() {
        let uri = parse("otpauth://totp/Example:user:extra?secret=ABC").unwrap();
        assert_eq!(uri.issuer.as_deref(), Some("Example"));
        assert_eq!(uri.account.as_deref(), Some("user:extra"));
    }

    /// 未知参数一律忽略，不报错。
    #[test]
    fn 未知参数忽略() {
        let uri = parse("otpauth://totp/GitHub:alice?secret=ABC&lockscreen=1&device=x").unwrap();
        assert_eq!(uri.secret, "ABC");
    }

    /// 缺 secret 报错。
    #[test]
    fn 缺secret报错() {
        let err = parse("otpauth://totp/GitHub:alice?issuer=GitHub").unwrap_err();
        assert!(matches!(err, OtpauthError::MissingSecret));
    }

    /// 非法 period 报错（非数字或 0）。
    #[test]
    fn 非法period报错() {
        assert!(parse("otpauth://totp/a?secret=ABC&period=abc").is_err());
        assert!(parse("otpauth://totp/a?secret=ABC&period=0").is_err());
    }

    /// 非法 algorithm 与 digits 报错。
    #[test]
    fn 非法算法与位数报错() {
        assert!(matches!(
            parse("otpauth://totp/a?secret=ABC&algorithm=MD5"),
            Err(OtpauthError::InvalidAlgorithm(_))
        ));
        assert!(parse("otpauth://totp/a?secret=ABC&digits=7").is_err());
    }

    /// 空字符串与错误 scheme 报错。
    #[test]
    fn 空串与错误scheme() {
        assert!(parse("").is_err());
        assert!(parse("https://totp/a?secret=ABC").is_err());
    }

    /// HOTP 类型直接拒绝（刻意不支持）。
    #[test]
    fn 拒绝hotp() {
        let err = parse("otpauth://hotp/a?secret=ABC&counter=1").unwrap_err();
        assert!(matches!(err, OtpauthError::UnsupportedType(_)));
    }

    /// 超长输入报错而非拖垮解析。
    #[test]
    fn 超长输入报错() {
        let long = format!(
            "otpauth://totp/a?secret=ABC&pad={}",
            "x".repeat(MAX_INPUT_LEN)
        );
        assert!(matches!(parse(&long), Err(OtpauthError::TooLong)));
    }

    /// 非法百分号转义报错。
    #[test]
    fn 非法百分号转义() {
        assert!(parse("otpauth://totp/%ZZ:alice?secret=ABC").is_err());
        assert!(parse("otpauth://totp/a%2?secret=ABC").is_err());
    }

    /// 序列化往返：parse(to_uri(x)) 与 x 语义一致。
    #[test]
    fn 序列化往返() {
        let original = OtpauthUri {
            issuer: Some("网易".to_string()),
            account: Some("alice@163.com".to_string()),
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            algorithm: Algorithm::Sha512,
            digits: 8,
            period: 60,
            warnings: Vec::new(),
        };
        let reparsed = parse(&to_uri(&original)).unwrap();
        assert_eq!(reparsed, original);
        assert!(
            reparsed.warnings.is_empty(),
            "自己序列化的 URI 不应有冲突警告"
        );
    }

    /// 无 issuer 条目的序列化往返。
    #[test]
    fn 无issuer序列化往返() {
        let original = OtpauthUri {
            issuer: None,
            account: Some("alice".to_string()),
            secret: "ABC".to_string(),
            algorithm: Algorithm::Sha1,
            digits: 6,
            period: DEFAULT_PERIOD,
            warnings: Vec::new(),
        };
        assert_eq!(parse(&to_uri(&original)).unwrap(), original);
    }
}
