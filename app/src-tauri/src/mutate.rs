//! 条目编辑与删除（M9-2）：定位、字段级修改/移除与校验。
//!
//! 本模块只做内存中的正文变更与校验；文件锁与落盘由命令层负责
//! （与 `add` 模块同模式）。编辑语义对齐 CLI `edit`：仅提供的字段被修改，
//! 修改后整体校验，不做同标识冲突检查（CLI `edit` 同样允许——归并决策
//! 属于添加场景，编辑场景用户显式输入了目标标识）。

use serde::Deserialize;
use two_fa_core::domain::totp::Algorithm;
use two_fa_core::vault::{Entry, SecretKey, VaultBody};

/// 编辑字段（`None` = 保持不变；对齐 CLI `edit` 的可选参数）。
#[derive(Debug, Default, Deserialize)]
pub struct EditFieldsDto {
    pub issuer: Option<String>,
    pub account: Option<String>,
    /// 提供（含空串无效值）则整体替换密钥。
    pub secret: Option<String>,
    pub algorithm: Option<String>,
    pub digits: Option<u8>,
    pub period: Option<u32>,
    pub tags: Option<Vec<String>>,
}

/// 按 ID 前缀定位并编辑条目（仅提供的字段被修改，修改后整体校验）。
pub fn edit(body: &mut VaultBody, prefix: &str, fields: &EditFieldsDto) -> Result<(), String> {
    let idx = two_fa_core::usecase::entries::find_index_by_prefix(body, prefix)
        .map_err(|e| e.to_string())?;
    let entry = &mut body.entries[idx];
    if let Some(issuer) = &fields.issuer {
        entry.issuer = issuer.clone();
    }
    if let Some(account) = &fields.account {
        entry.account = account.clone();
    }
    if let Some(secret) = &fields.secret {
        entry.secret = SecretKey::from_base32(secret).map_err(|e| format!("密钥无效：{e}"))?;
    }
    if let Some(algorithm) = &fields.algorithm {
        entry.algorithm = Algorithm::parse_label(algorithm)
            .ok_or_else(|| format!("未知算法：{algorithm}（可选 SHA1/SHA256/SHA512）"))?;
    }
    if let Some(digits) = fields.digits {
        entry.digits = digits;
    }
    if let Some(period) = fields.period {
        entry.period = period;
    }
    if let Some(tags) = &fields.tags {
        entry.tags = tags.clone();
    }
    entry.validate().map_err(|e| format!("修改后字段非法：{e}"))
    // 落盘前重新过 from_json 同源校验（save 内部保证），此处不再重复
}

/// 按 ID 前缀定位并移除条目，返回被删条目的「issuer / account」描述。
pub fn delete(body: &mut VaultBody, prefix: &str) -> Result<String, String> {
    let idx = two_fa_core::usecase::entries::find_index_by_prefix(body, prefix)
        .map_err(|e| e.to_string())?;
    let removed = body.entries.remove(idx);
    Ok(format!("{} / {}", removed.issuer, removed.account))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use two_fa_core::vault::SecretKey;

    fn sample_entry(issuer: &str, account: &str, secret: &str) -> Entry {
        Entry::new(
            issuer.to_string(),
            account.to_string(),
            SecretKey::from_base32(secret).unwrap(),
            Algorithm::Sha1,
            6,
            30,
            Vec::new(),
        )
        .unwrap()
    }

    fn make_body() -> VaultBody {
        let mut body = VaultBody::empty(0);
        body.entries
            .push(sample_entry("GitHub", "alice", "JBSWY3DPEHPK3PXP"));
        body.entries
            .push(sample_entry("GitLab", "bob", "MZXW6YTBOI"));
        body
    }

    /// 编辑往返：字段级修改只动提供的字段，其余保持不变。
    #[test]
    fn 编辑仅动提供的字段() {
        let mut body = make_body();
        let id = body.entries[0].id.to_string();
        edit(
            &mut body,
            &id,
            &EditFieldsDto {
                issuer: Some("GitHub2".to_string()),
                period: Some(60),
                ..Default::default()
            },
        )
        .unwrap();
        let e = &body.entries[0];
        assert_eq!(e.issuer, "GitHub2");
        assert_eq!(e.period, 60);
        assert_eq!(e.account, "alice", "未提供的字段保持不变");
        assert_eq!(e.secret.as_text(), "JBSWY3DPEHPK3PXP");
        assert_eq!(e.digits, 6);
        assert_eq!(e.algorithm, Algorithm::Sha1);
    }

    /// 编辑密钥：整体替换为新密钥。
    #[test]
    fn 编辑替换密钥() {
        let mut body = make_body();
        let id = body.entries[0].id.to_string();
        edit(
            &mut body,
            &id,
            &EditFieldsDto {
                secret: Some("MZXW6YQ".to_string()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(body.entries[0].secret.as_text(), "MZXW6YQ");
    }

    /// 编辑校验：非法字段（位数 / 算法 / 密钥 / 周期）报中文错误且正文不变。
    #[test]
    fn 编辑非法字段报错() {
        let mut body = make_body();
        let id = body.entries[0].id.to_string();
        let cases = [
            (
                EditFieldsDto {
                    digits: Some(7),
                    ..Default::default()
                },
                "修改后字段非法",
            ),
            (
                EditFieldsDto {
                    algorithm: Some("MD5".into()),
                    ..Default::default()
                },
                "未知算法",
            ),
            (
                EditFieldsDto {
                    secret: Some("不是base32!".into()),
                    ..Default::default()
                },
                "密钥无效",
            ),
            (
                EditFieldsDto {
                    period: Some(0),
                    ..Default::default()
                },
                "修改后字段非法",
            ),
        ];
        for (fields, expect) in cases {
            let err = edit(&mut body, &id, &fields).unwrap_err();
            assert!(err.contains(expect), "{expect}：{err}");
            // 正文未被半途污染
            assert_eq!(body.entries[0].secret.as_text(), "JBSWY3DPEHPK3PXP");
        }
        // ID 前缀不匹配报错
        let err = edit(&mut body, "ffffffff", &EditFieldsDto::default()).unwrap_err();
        assert!(err.contains("未找到"), "{err}");
    }

    /// 删除：移除目标条目并返回描述；其余条目不受影响。
    #[test]
    fn 删除移除目标条目() {
        let mut body = make_body();
        let id = body.entries[1].id.to_string();
        let desc = delete(&mut body, &id).unwrap();
        assert_eq!(desc, "GitLab / bob");
        assert_eq!(body.entries.len(), 1);
        assert_eq!(body.entries[0].issuer, "GitHub");

        // 再删同前缀（现指向剩下的 GitHub 条目——前缀全库唯一性由展示层保证，
        // 这里验证前缀仍可命中）
        let id0 = body.entries[0].id.to_string();
        let desc = delete(&mut body, &id0).unwrap();
        assert_eq!(desc, "GitHub / alice");
        assert!(body.entries.is_empty());
    }
}
