//! 添加条目（M9-1）：三种来源（otpauth 文本 / 手填 / 图片扫码）的解析、
//! 冲突预检与落盘应用。
//!
//! 两段式设计——密钥不离开 Rust 进程：
//! 1. `parse_source`：解析来源产出预览视图（不含密钥）与待提交条目
//!    （[`PendingAdd`]，由会话暂存）；与库内同标识的条目标记
//!    「重复」（同密钥，将自动跳过）或「冲突」（不同密钥，须用户显式决策）。
//! 2. `apply`：按用户决策把待提交条目并入正文。冲突条目未决策即报错
//!    （不得静默，与 CLI `add`/`import` 同语义）。
//!
//! 本模块不含 Tauri 依赖，可完整单元测试；解析复用 core 的
//! `parse_any_batch`（otpauth 文本与 GA 迁移统一分派，HOTP 条目由 core 拒绝）。
//! `Entry` 禁止 `Clone`（零化语义），待提交条目经 `mem::take` 独占消费——
//! 因此 [`apply`] 先整体预检决策完备性，预检通过后不再有失败路径。

use serde::{Deserialize, Serialize};
use two_fa_core::domain::totp::Algorithm;
use two_fa_core::importexport::{self, BatchItem};
use two_fa_core::vault::{Entry, SecretKey, VaultBody};

/// 添加来源（前端传入，serde 标签分派）。
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AddSourceDto {
    /// 粘贴文本：一行一条 `otpauth://`，或 `otpauth-migration://` 迁移 URI。
    Text { text: String },
    /// 手填表单（algorithm 缺省 SHA1，digits 缺省 6，period 缺省 30）。
    Manual {
        issuer: String,
        account: String,
        secret: String,
        algorithm: Option<String>,
        digits: Option<u8>,
        period: Option<u32>,
        tags: Option<Vec<String>>,
    },
    /// 图片文件字节（Base64）：解码二维码后走迁移/otpauth 分派。
    Image { bytes_b64: String },
}

/// 用户对冲突条目的决策。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecisionAction {
    /// 移除全部同标识既有条目后写入（与 CLI `add --overwrite` 同语义）。
    Overwrite,
    /// 同标识并存保留（与 CLI `add --keep-both` 同语义）。
    KeepBoth,
}

/// 冲突决策（按预览条目下标）。
#[derive(Debug, Deserialize)]
pub struct DecisionDto {
    pub index: usize,
    pub action: DecisionAction,
}

/// 单条预览视图（**不含密钥**——密钥留在后端待提交区）。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AddItemView {
    /// 待提交条目下标（决策时回传）。
    pub index: usize,
    pub issuer: String,
    pub account: String,
    pub algorithm: String,
    pub digits: u8,
    pub period: u32,
    pub tags: Vec<String>,
    /// 与库内同标识且密钥不同：须用户显式选择覆盖 / 并存。
    pub conflict: bool,
    /// 与库内同标识且密钥相同：将自动跳过（与 CLI 导入语义一致）。
    pub duplicate: bool,
}

/// 解析失败行（不进入待提交区，仅报告）。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct FailedLine {
    pub line: usize,
    pub error: String,
}

/// 预览视图。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AddPreview {
    /// 待提交区令牌（提交时回传校验，防止陈旧预览错配）。
    pub token: u64,
    pub items: Vec<AddItemView>,
    pub failed: Vec<FailedLine>,
    /// GA 迁移多批次提示（batch_size > 1 时 GA 会导出多张二维码）。
    pub notes: Vec<String>,
    /// 来源含 GA 迁移载荷（前端据此提示删除原始迁移二维码）。
    pub migration_used: bool,
}

/// 落盘摘要。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AddSummary {
    pub added: usize,
    pub replaced: usize,
    pub kept_both: usize,
    /// 同标识同密钥自动跳过数。
    pub skipped_dup: usize,
    /// 是否有变更（无变更不落盘）。
    pub changed: bool,
}

/// 待提交区（会话暂存，锁定即清空；`apply` 成功后由调用方清空）。
#[derive(Debug)]
pub struct PendingAdd {
    pub token: u64,
    pub entries: Vec<Entry>,
}

/// 解析结果：预览视图 + 待提交区（令牌由 `set_token` 填充）。
#[derive(Debug)]
pub struct Parsed {
    pub view: AddPreview,
    pub pending: PendingAdd,
}

/// 解析添加来源并对照库内既有条目做冲突预检。
pub fn parse_source(source: &AddSourceDto, existing: &VaultBody) -> Result<Parsed, String> {
    match source {
        AddSourceDto::Manual {
            issuer,
            account,
            secret,
            algorithm,
            digits,
            period,
            tags,
        } => {
            let entry = manual_entry(
                issuer,
                account,
                secret,
                algorithm.as_deref(),
                *digits,
                *period,
                tags.as_deref(),
            )?;
            let item = item_view(0, &entry, existing);
            Ok(Parsed {
                view: AddPreview {
                    token: 0,
                    items: vec![item],
                    failed: Vec::new(),
                    notes: Vec::new(),
                    migration_used: false,
                },
                pending: PendingAdd {
                    token: 0,
                    entries: vec![entry],
                },
            })
        }
        AddSourceDto::Text { text } => parse_batch_text(text, false, existing),
        AddSourceDto::Image { bytes_b64 } => {
            let payload = decode_image(bytes_b64)?;
            parse_batch_text(&payload, true, existing)
        }
    }
}

/// 填充令牌（commands 层生成唯一 token 后调用；视图与待提交区保持一致）。
pub fn set_token(parsed: &mut Parsed, token: u64) {
    parsed.view.token = token;
    parsed.pending.token = token;
}

/// 批量文本（otpauth / 迁移 URI）→ 预览与待提交区。
fn parse_batch_text(text: &str, from_image: bool, existing: &VaultBody) -> Result<Parsed, String> {
    let parsed = importexport::parse_any_batch(text).map_err(|e| format!("解析失败：{e}"))?;
    let mut items = Vec::new();
    let mut failed = Vec::new();
    let mut entries = Vec::new();
    for item in parsed.items {
        match item {
            BatchItem::Ok { entry, .. } => {
                let index = entries.len();
                items.push(item_view(index, &entry, existing));
                entries.push(entry);
            }
            BatchItem::Failed { line, error } => failed.push(FailedLine { line, error }),
        }
    }
    if items.is_empty() && failed.is_empty() {
        return Err("输入中没有可添加的条目（只含空行或注释行）".to_string());
    }
    Ok(Parsed {
        view: AddPreview {
            token: 0,
            items,
            failed,
            notes: parsed
                .migration_notes
                .iter()
                .map(|(_, n)| n.clone())
                .collect(),
            migration_used: from_image || parsed.migration_used,
        },
        pending: PendingAdd { token: 0, entries },
    })
}

/// 图片字节（Base64）→ 二维码载荷。
fn decode_image(bytes_b64: &str) -> Result<String, String> {
    let bytes = data_encoding::BASE64
        .decode(bytes_b64.as_bytes())
        .map_err(|_| "图片数据不是有效的 Base64".to_string())?;
    let payload = two_fa_core::qrcode::decode_first(&bytes)
        .and_then(|t| two_fa_core::qrcode::validate_payload(&t).map(str::to_string))
        .map_err(|e| format!("二维码解码失败：{e}"))?;
    Ok(payload)
}

/// 预览视图 + 与既有条目的冲突/重复判定。
fn item_view(index: usize, entry: &Entry, existing: &VaultBody) -> AddItemView {
    let same = existing.find_same_identity(&entry.issuer, &entry.account);
    // 与 CLI 导入语义一致：按首条同标识条目判定
    let (conflict, duplicate) = match same.first() {
        Some(prev) if prev.secret.as_text() == entry.secret.as_text() => (false, true),
        Some(_) => (true, false),
        None => (false, false),
    };
    AddItemView {
        index,
        issuer: entry.issuer.clone(),
        account: entry.account.clone(),
        algorithm: entry.algorithm.label().to_string(),
        digits: entry.digits,
        period: entry.period,
        tags: entry.tags.clone(),
        conflict,
        duplicate,
    }
}

/// 手填表单 → 条目（字段校验与缺省值对齐 CLI `add`）。
#[allow(clippy::too_many_arguments)]
fn manual_entry(
    issuer: &str,
    account: &str,
    secret: &str,
    algorithm: Option<&str>,
    digits: Option<u8>,
    period: Option<u32>,
    tags: Option<&[String]>,
) -> Result<Entry, String> {
    let issuer = issuer.trim();
    let account = account.trim();
    if issuer.is_empty() || account.is_empty() {
        return Err("服务商与账号不能为空".to_string());
    }
    let algorithm = match algorithm {
        None => Algorithm::Sha1,
        Some(text) => Algorithm::parse_label(text)
            .ok_or_else(|| format!("未知算法：{text}（可选 SHA1/SHA256/SHA512）"))?,
    };
    let secret = SecretKey::from_base32(secret)
        .map_err(|e| format!("密钥无效：{e}（应为 Base32 文本，可缺省填充）"))?;
    Entry::new(
        issuer.to_string(),
        account.to_string(),
        secret,
        algorithm,
        digits.unwrap_or(6),
        period.unwrap_or(30),
        tags.unwrap_or_default().to_vec(),
    )
    .map_err(|e| e.to_string())
}

/// 把待提交条目按决策并入正文。
///
/// 先整体预检：全部冲突条目（同标识不同密钥）必须有显式决策，否则报错且
/// 正文不变（不得静默）。预检通过后逐条消费待提交条目（无失败路径）：
///
/// - 非冲突条目直接加入（`added`）
/// - 重复条目（同标识同密钥）自动跳过（`skipped_dup`）
/// - 冲突条目：覆盖移除全部同标识既有条目后写入（`replaced`）；并存追加（`kept_both`）
pub fn apply(
    pending: &mut PendingAdd,
    body: &mut VaultBody,
    decisions: &[(usize, DecisionAction)],
) -> Result<AddSummary, String> {
    for (index, entry) in pending.entries.iter().enumerate() {
        let decided = decisions.iter().any(|(i, _)| *i == index);
        if let Some(prev) = body
            .find_same_identity(&entry.issuer, &entry.account)
            .first()
        {
            if prev.secret.as_text() != entry.secret.as_text() && !decided {
                return Err(format!(
                    "条目 {}（{} / {}）与既有条目同标识但密钥不同，请先选择覆盖或并存",
                    index + 1,
                    entry.issuer,
                    entry.account
                ));
            }
        }
    }

    let mut added = 0usize;
    let mut replaced = 0usize;
    let mut kept_both = 0usize;
    let mut skipped_dup = 0usize;
    // 预检已通过，独占消费待提交条目（Entry 禁 Clone）
    let entries = std::mem::take(&mut pending.entries);
    for (index, entry) in entries.into_iter().enumerate() {
        let conflict = body
            .find_same_identity(&entry.issuer, &entry.account)
            .first()
            .map(|prev| prev.secret.as_text() != entry.secret.as_text());
        match conflict {
            Some(false) => skipped_dup += 1,
            Some(true) => match decisions.iter().find(|(i, _)| *i == index).map(|(_, a)| *a) {
                Some(DecisionAction::Overwrite) => {
                    let target = entry.identity_key();
                    body.entries.retain(|e| e.identity_key() != target);
                    replaced += 1;
                    body.entries.push(entry);
                }
                _ => {
                    kept_both += 1;
                    body.entries.push(entry);
                }
            },
            None => {
                added += 1;
                body.entries.push(entry);
            }
        }
    }

    let changed = added + replaced + kept_both > 0;
    Ok(AddSummary {
        added,
        replaced,
        kept_both,
        skipped_dup,
        changed,
    })
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

    const URI: &str = "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";

    /// 文本来源：单条 otpauth URI 解析成功且无冲突。
    #[test]
    fn 文本来源单条解析() {
        let body = VaultBody::empty(0);
        let parsed = parse_source(
            &AddSourceDto::Text {
                text: URI.to_string(),
            },
            &body,
        )
        .unwrap();
        assert_eq!(parsed.view.items.len(), 1);
        assert_eq!(parsed.view.items[0].issuer, "GitHub");
        assert_eq!(parsed.view.items[0].account, "alice");
        assert!(!parsed.view.items[0].conflict);
        assert!(!parsed.view.items[0].duplicate);
        assert_eq!(parsed.pending.entries.len(), 1);
        // 预览视图不含密钥：序列化文本不得出现 Base32 密钥
        let json = serde_json::to_string(&parsed.view).unwrap();
        assert!(
            !json.contains("JBSWY3DPEHPK3PXP"),
            "预览不得泄漏密钥：{json}"
        );
    }

    /// 手填来源：缺省值（SHA1 / 6 位 / 30 秒）与空白修剪、宽容 Base32。
    #[test]
    fn 手填来源缺省值() {
        let body = VaultBody::empty(0);
        let parsed = parse_source(
            &AddSourceDto::Manual {
                issuer: "  GitLab ".to_string(),
                account: "bob".to_string(),
                secret: "mzxw6yq".to_string(), // 小写缺填充：宽容解析
                algorithm: None,
                digits: None,
                period: None,
                tags: Some(vec!["工作".to_string()]),
            },
            &body,
        )
        .unwrap();
        let item = &parsed.view.items[0];
        assert_eq!(item.issuer, "GitLab", "首尾空白应去除");
        assert_eq!(item.algorithm, "SHA1");
        assert_eq!(item.digits, 6);
        assert_eq!(item.period, 30);
        assert_eq!(item.tags, vec!["工作".to_string()]);
    }

    /// 手填来源：无效密钥报中文错误。
    #[test]
    fn 手填无效密钥报错() {
        let body = VaultBody::empty(0);
        let err = parse_source(
            &AddSourceDto::Manual {
                issuer: "A".to_string(),
                account: "a".to_string(),
                secret: "不是base32!".to_string(),
                algorithm: None,
                digits: None,
                period: None,
                tags: None,
            },
            &body,
        )
        .unwrap_err();
        assert!(err.contains("密钥无效"), "{err}");
    }

    /// 手填来源：服务商或账号为空、未知算法报错。
    #[test]
    fn 手填字段校验() {
        let body = VaultBody::empty(0);
        let manual = |issuer: &str, algorithm: Option<String>| AddSourceDto::Manual {
            issuer: issuer.to_string(),
            account: "a".to_string(),
            secret: "JBSWY3DPEHPK3PXP".to_string(),
            algorithm,
            digits: None,
            period: None,
            tags: None,
        };
        let err = parse_source(&manual("  ", None), &body).unwrap_err();
        assert!(err.contains("不能为空"), "{err}");
        let err = parse_source(&manual("A", Some("MD5".to_string())), &body).unwrap_err();
        assert!(err.contains("未知算法"), "{err}");
    }

    /// 冲突与重复标记：同标识不同密钥 → conflict；同标识同密钥 → duplicate。
    #[test]
    fn 冲突与重复标记() {
        let mut body = VaultBody::empty(0);
        body.entries
            .push(sample_entry("GitHub", "alice", "JBSWY3DPEHPK3PXP"));

        let parsed = parse_source(
            &AddSourceDto::Text {
                text: URI.to_string(),
            },
            &body,
        )
        .unwrap();
        assert!(parsed.view.items[0].duplicate);
        assert!(!parsed.view.items[0].conflict);

        let other = "otpauth://totp/GitHub:alice?secret=MZXW6YTBOI&issuer=GitHub";
        let parsed = parse_source(
            &AddSourceDto::Text {
                text: other.to_string(),
            },
            &body,
        )
        .unwrap();
        assert!(parsed.view.items[0].conflict);
        assert!(!parsed.view.items[0].duplicate);
    }

    /// HOTP 条目由 core 拒绝：进入 failed 列表且错误说明 HOTP。
    #[test]
    fn hotp条目被拒() {
        let body = VaultBody::empty(0);
        let hotp = "otpauth://hotp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&counter=0";
        let parsed = parse_source(
            &AddSourceDto::Text {
                text: hotp.to_string(),
            },
            &body,
        )
        .unwrap();
        assert!(parsed.view.items.is_empty(), "HOTP 不得进入待提交区");
        assert_eq!(parsed.view.failed.len(), 1);
        let error = parsed.view.failed[0].error.to_ascii_lowercase();
        assert!(
            error.contains("hotp"),
            "错误应说明 HOTP：{}",
            parsed.view.failed[0].error
        );
    }

    /// 图片来源：core 编码 PNG → Base64 → 解码往返（端到端闭环）。
    #[test]
    fn 图片来源往返() {
        let body = VaultBody::empty(0);
        let png = two_fa_core::qrcode::encode_png(URI).unwrap();
        let b64 = data_encoding::BASE64.encode(&png);
        let parsed = parse_source(&AddSourceDto::Image { bytes_b64: b64 }, &body).unwrap();
        assert_eq!(parsed.view.items.len(), 1);
        assert_eq!(parsed.view.items[0].issuer, "GitHub");
    }

    /// 图片来源：非图片字节报中文错误。
    #[test]
    fn 图片无效报错() {
        let body = VaultBody::empty(0);
        let b64 = data_encoding::BASE64.encode(b"not an image");
        let err = parse_source(&AddSourceDto::Image { bytes_b64: b64 }, &body).unwrap_err();
        assert!(err.contains("二维码解码失败"), "{err}");
    }

    /// apply：无冲突条目加入；重复条目自动跳过。
    #[test]
    fn 应用无冲突与重复跳过() {
        let mut body = VaultBody::empty(0);
        body.entries.push(sample_entry("Old", "old", "MZXW6YQ"));

        let mut parsed = parse_source(
            &AddSourceDto::Text {
                text: URI.to_string(),
            },
            &body,
        )
        .unwrap();
        let summary = apply(&mut parsed.pending, &mut body, &[]).unwrap();
        assert_eq!(summary.added, 1);
        assert!(summary.changed);
        assert_eq!(body.entries.len(), 2);
        assert_eq!(body.entries[1].issuer, "GitHub");

        // 再次应用同一来源：与刚加入的条目同标识同密钥 → 跳过
        let mut parsed2 = parse_source(
            &AddSourceDto::Text {
                text: URI.to_string(),
            },
            &body,
        )
        .unwrap();
        let summary2 = apply(&mut parsed2.pending, &mut body, &[]).unwrap();
        assert_eq!(summary2.skipped_dup, 1);
        assert!(!summary2.changed);
        assert_eq!(body.entries.len(), 2);
    }

    /// apply：冲突未决策报错且正文不变；覆盖移除全部同标识；并存保留两条。
    #[test]
    fn 应用覆盖与并存() {
        let mut body = VaultBody::empty(0);
        body.entries
            .push(sample_entry("GitHub", "alice", "MZXW6YQ"));

        let other = "otpauth://totp/GitHub:alice?secret=MZXW6YTBOI&issuer=GitHub";

        // 未决策冲突 → 报错，正文不变
        let mut pending = parse_source(
            &AddSourceDto::Text {
                text: other.to_string(),
            },
            &body,
        )
        .unwrap()
        .pending;
        let err = apply(&mut pending, &mut body, &[]).unwrap_err();
        assert!(err.contains("覆盖或并存"), "{err}");
        assert_eq!(body.entries.len(), 1);

        // 覆盖
        let mut parsed = parse_source(
            &AddSourceDto::Text {
                text: other.to_string(),
            },
            &body,
        )
        .unwrap();
        let summary = apply(
            &mut parsed.pending,
            &mut body,
            &[(0, DecisionAction::Overwrite)],
        )
        .unwrap();
        assert_eq!(summary.replaced, 1);
        assert_eq!(body.entries.len(), 1);
        assert_eq!(body.entries[0].secret.as_text(), "MZXW6YTBOI");

        // 并存（基于覆盖后的状态再引入旧密钥条目）
        let old_uri = "otpauth://totp/GitHub:alice?secret=MZXW6YQ&issuer=GitHub";
        let mut parsed = parse_source(
            &AddSourceDto::Text {
                text: old_uri.to_string(),
            },
            &body,
        )
        .unwrap();
        let summary = apply(
            &mut parsed.pending,
            &mut body,
            &[(0, DecisionAction::KeepBoth)],
        )
        .unwrap();
        assert_eq!(summary.kept_both, 1);
        assert_eq!(body.entries.len(), 2);
    }
}
