//! otpauth 纯文本批量导入（M4-1）。
//!
//! 一行一条 `otpauth://`，忽略空行与 `#` 注释行；单行解析失败不中断
//! 整批，逐行报告成功与失败。重复条目（归一化同标识且密钥相同）与
//! 同标识不同密钥的归并决策由调用方结合既有条目完成。

use crate::domain::otpauth;
use crate::vault::{Entry, SecretKey};

/// 行数上限：防超大输入拖垮解析（5000 条目的导出也远低于此）。
const MAX_LINES: usize = 10_000;

/// 批量解析错误。
#[derive(Debug, thiserror::Error)]
pub enum BatchError {
    /// 行数超过上限。
    #[error("输入超过 {MAX_LINES} 行上限，疑似非 otpauth 文本")]
    TooManyLines,
}

/// 单行解析结果。
#[derive(Debug)]
pub enum BatchItem {
    /// 解析成功。
    Ok {
        /// 1 起始的行号。
        line: usize,
        /// 解析出的条目（id 已生成，标签为空）。
        entry: Entry,
        /// 解析警告（如 issuer 冲突），由调用方逐行提示。
        warnings: Vec<String>,
    },
    /// 解析失败。
    Failed {
        /// 1 起始的行号。
        line: usize,
        /// 失败原因。
        error: String,
    },
}

/// 批量解析 otpauth 文本。
///
/// 空行与 `#` 注释行直接忽略（不出现在结果中）；其余每行产出
/// [`BatchItem::Ok`] 或 [`BatchItem::Failed`]，失败不中断整批。
pub fn parse_batch(text: &str) -> Result<Vec<BatchItem>, BatchError> {
    if text.lines().count() > MAX_LINES {
        return Err(BatchError::TooManyLines);
    }
    let mut items = Vec::new();
    for (idx, raw) in text.lines().enumerate() {
        let line = idx + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let uri = match otpauth::parse(trimmed) {
            Ok(uri) => uri,
            Err(err) => {
                items.push(BatchItem::Failed {
                    line,
                    error: err.to_string(),
                });
                continue;
            }
        };
        let secret = match SecretKey::from_base32(&uri.secret) {
            Ok(secret) => secret,
            Err(err) => {
                items.push(BatchItem::Failed {
                    line,
                    error: format!("密钥解码失败：{err}"),
                });
                continue;
            }
        };
        match Entry::new(
            uri.issuer.unwrap_or_default(),
            uri.account.unwrap_or_default(),
            secret,
            uri.algorithm,
            uri.digits,
            uri.period,
            Vec::new(),
        ) {
            Ok(entry) => items.push(BatchItem::Ok {
                line,
                entry,
                warnings: uri.warnings,
            }),
            Err(err) => items.push(BatchItem::Failed {
                line,
                error: err.to_string(),
            }),
        }
    }
    Ok(items)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::totp::Algorithm;

    /// 混合批次：注释与空行被忽略，失败行不中断整批，行号准确。
    #[test]
    fn 混合批次逐行报告() {
        let text = "# 导出自其他工具\n\
                    \n\
                    otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP\n\
                    这不是一行 URI\n\
                    otpauth://totp/Example:bob?secret=JBSWY3DPEHPK3PXP&digits=7\n\
                    otpauth://totp/网易:carol?secret=MZXW6YTBOI\n";
        let items = parse_batch(text).unwrap();

        assert_eq!(items.len(), 4, "注释与空行不计入结果");
        match &items[0] {
            BatchItem::Ok {
                line,
                entry,
                warnings,
            } => {
                assert_eq!(*line, 3);
                assert_eq!(entry.issuer, "GitHub");
                assert_eq!(entry.account, "alice");
                assert_eq!(entry.secret.as_text(), "JBSWY3DPEHPK3PXP");
                assert_eq!(entry.algorithm, Algorithm::Sha1);
                assert_eq!(entry.digits, 6);
                assert_eq!(entry.period, 30);
                assert!(warnings.is_empty());
            }
            other => panic!("第 3 行应为成功项，实际 {other:?}"),
        }
        match &items[1] {
            BatchItem::Failed { line, error } => {
                assert_eq!(*line, 4);
                assert!(error.contains("otpauth"), "错误应可理解：{error}");
            }
            other => panic!("第 4 行应为失败项，实际 {other:?}"),
        }
        match &items[2] {
            BatchItem::Failed { line, error } => {
                assert_eq!(*line, 5);
                assert!(error.contains("digits"), "错误应指出位数问题：{error}");
            }
            other => panic!("第 5 行应为失败项，实际 {other:?}"),
        }
        match &items[3] {
            BatchItem::Ok { line, entry, .. } => {
                assert_eq!(*line, 6);
                assert_eq!(entry.issuer, "网易");
                assert_eq!(entry.account, "carol");
            }
            other => panic!("第 6 行应为成功项，实际 {other:?}"),
        }
    }

    /// 重复条目（同标识同密钥）逐行都解析成功——重复判定由调用方完成。
    #[test]
    fn 重复行都解析成功待调用方归并() {
        let text = "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP\n\
                    otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP\n";
        let items = parse_batch(text).unwrap();
        assert_eq!(items.len(), 2);
        assert!(items.iter().all(|i| matches!(i, BatchItem::Ok { .. })));
    }

    /// 密钥非法（非 Base32）报解码失败而非泛化解析错误。
    #[test]
    fn 非法密钥报解码失败() {
        let text = "otpauth://totp/GitHub:alice?secret=!!!非Base32!!!\n";
        let items = parse_batch(text).unwrap();
        match &items[0] {
            BatchItem::Failed { error, .. } => {
                assert!(error.contains("密钥"), "错误应指明密钥问题：{error}");
            }
            other => panic!("应为失败项，实际 {other:?}"),
        }
    }

    /// 全部为注释与空行时结果为空，不报错。
    #[test]
    fn 全注释结果为空() {
        let items = parse_batch("# 只有注释\n\n   \n# 另一条注释\n").unwrap();
        assert!(items.is_empty());
    }

    /// 超过行数上限直接拒绝整批。
    #[test]
    fn 超行上限拒绝() {
        let line = "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP\n";
        let text = line.repeat(MAX_LINES + 1);
        assert!(matches!(parse_batch(&text), Err(BatchError::TooManyLines)));
    }

    /// 大小写与带填充的密钥被宽容解码并归一化为规范 Base32。
    #[test]
    fn 密钥宽容解码归一化() {
        let text = "otpauth://totp/GitHub:alice?secret=jbswy3dpehpk3pxp======\n";
        let items = parse_batch(text).unwrap();
        match &items[0] {
            BatchItem::Ok { entry, .. } => {
                assert_eq!(entry.secret.as_text(), "JBSWY3DPEHPK3PXP");
            }
            other => panic!("应为成功项，实际 {other:?}"),
        }
    }

    /// issuer 冲突警告随行传递（query 优先），条目按 query 值落地。
    #[test]
    fn issuer冲突警告随行传递() {
        let text = "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub2\n";
        let items = parse_batch(text).unwrap();
        match &items[0] {
            BatchItem::Ok {
                entry, warnings, ..
            } => {
                assert_eq!(entry.issuer, "GitHub2");
                assert_eq!(warnings.len(), 1);
            }
            other => panic!("应为成功项，实际 {other:?}"),
        }
    }
}
