//! 明文 otpauth 导出序列化（危险出口）。
//!
//! 纯数据处理：每个条目序列化为一行 otpauth URI，首行为中文警告注释。
//! 确认门槛与文件写入由调用方（CLI）完成；输出与自家导入器兼容
//! （`#` 注释行在导入时被忽略），可无损往返。
//!
//! 标签字段不包含在 otpauth URI 中，导出后不可还原——这是格式固有限制。

use crate::domain::otpauth::{self, OtpauthUri};
use crate::vault::{Entry, VaultBody};

/// 导出文件首行的警告注释（`#` 开头，导入时被忽略）。
pub const WARNING_LINE: &str = "# 警告：本文件包含未加密的明文 OTP 密钥，任何人拿到它即可生成你的验证码并接管账号。用完请立即安全删除。";

/// 把保险库全部条目序列化为明文 otpauth 文本（警告注释 + 每条目一行 URI）。
pub fn serialize(body: &VaultBody) -> String {
    let mut out = String::from(WARNING_LINE);
    out.push('\n');
    for entry in &body.entries {
        out.push_str(&entry_uri(entry));
        out.push('\n');
    }
    out
}

/// 单条目 → otpauth URI。
fn entry_uri(entry: &Entry) -> String {
    let uri = OtpauthUri {
        issuer: non_empty(&entry.issuer).map(str::to_string),
        account: non_empty(&entry.account).map(str::to_string),
        secret: entry.secret.as_text().to_string(),
        algorithm: entry.algorithm,
        digits: entry.digits,
        period: entry.period,
        warnings: Vec::new(),
    };
    otpauth::to_uri(&uri)
}

/// trim 后非空才返回 Some（空 issuer / 账号在 URI 中按缺失处理）。
fn non_empty(s: &str) -> Option<&str> {
    let t = s.trim();
    if t.is_empty() { None } else { Some(t) }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::totp::Algorithm;
    use crate::vault::SecretKey;

    fn sample_body() -> VaultBody {
        let mut body = VaultBody::empty(1_700_000_000);
        body.entries.push(
            Entry::new(
                "GitHub".into(),
                "alice".into(),
                SecretKey::from_base32("MZXW6YTBOI").unwrap(),
                Algorithm::Sha1,
                6,
                30,
                vec!["工作".into()],
            )
            .unwrap(),
        );
        body.entries.push(
            Entry::new(
                String::new(),
                "bob@example.com".into(),
                SecretKey::from_base32("JBSWY3DPEHPK3PXP").unwrap(),
                Algorithm::Sha256,
                8,
                60,
                Vec::new(),
            )
            .unwrap(),
        );
        body
    }

    /// 序列化：首行警告注释，其后每条目一行 URI，含算法/位数/周期。
    #[test]
    fn 序列化含警告行与条目行() {
        let text = serialize(&sample_body());
        let lines: Vec<&str> = text.lines().collect();

        assert_eq!(lines[0], WARNING_LINE, "首行必须是警告注释");
        assert_eq!(lines.len(), 3, "警告行 + 2 个条目行");
        assert!(lines[1].starts_with("otpauth://totp/GitHub:alice?"));
        assert!(lines[1].contains("secret=MZXW6YTBOI"));
        assert!(lines[1].contains("issuer=GitHub"));
        assert!(lines[1].contains("algorithm=SHA1"));
        assert!(lines[1].contains("digits=6"));
        assert!(lines[1].contains("period=30"));
    }

    /// 无 issuer 条目：label 用空前缀「:账号」保证往返（与导入器一致）。
    #[test]
    fn 无issuer条目用空前缀() {
        let body = sample_body();
        let text = serialize(&body);
        let line = text.lines().nth(2).unwrap();

        assert!(
            line.starts_with("otpauth://totp/:bob%40example.com?"),
            "{line}"
        );
        assert!(line.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(line.contains("algorithm=SHA256"));
        assert!(line.contains("digits=8"));
        assert!(line.contains("period=60"));
    }

    /// 导出文本可被自家导入器解析：警告注释被忽略，条目级往返一致
    /// （标签除外——otpauth URI 无标签字段）。
    #[test]
    fn 导出文本可被自家导入器解析() {
        let text = serialize(&sample_body());
        let items = crate::importexport::otpauth_text::parse_batch(&text).unwrap();

        assert_eq!(items.len(), 2, "警告注释行不应产生条目");
        let first = match &items[0] {
            crate::importexport::BatchItem::Ok { entry, .. } => entry,
            other => panic!("应为成功条目：{other:?}"),
        };
        assert_eq!(first.issuer, "GitHub");
        assert_eq!(first.account, "alice");
        assert_eq!(first.secret.as_text(), "MZXW6YTBOI");
        assert_eq!(first.algorithm, Algorithm::Sha1);
        assert_eq!(first.digits, 6);
        assert_eq!(first.period, 30);

        let second = match &items[1] {
            crate::importexport::BatchItem::Ok { entry, .. } => entry,
            other => panic!("应为成功条目：{other:?}"),
        };
        assert_eq!(second.issuer, "");
        assert_eq!(second.account, "bob@example.com");
        assert_eq!(second.secret.as_text(), "JBSWY3DPEHPK3PXP");
        assert_eq!(second.algorithm, Algorithm::Sha256);
        assert_eq!(second.digits, 8);
        assert_eq!(second.period, 60);
    }

    /// 空保险库：只有警告行。
    #[test]
    fn 空保险库只有警告行() {
        let body = VaultBody::empty(1_700_000_000);
        let text = serialize(&body);
        assert_eq!(text, format!("{WARNING_LINE}\n"));
    }
}
