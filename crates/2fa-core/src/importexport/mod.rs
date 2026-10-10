//! 导入导出的纯数据变换。
//!
//! 按 PRD 架构分层：本模块只做格式解析与序列化，不碰文件 IO——
//! 文件读写、保险库解锁与冲突交互全部由调用方（CLI / REPL）完成。

pub mod gauth;
pub mod otpauth_text;

pub use otpauth_text::BatchItem;

/// GA 迁移 URI 前缀。
const MIGRATION_PREFIX: &str = "otpauth-migration://";

/// 批量解析结果：逐行条目 + 迁移批次进度说明。
#[derive(Debug)]
pub struct ParsedBatch {
    /// 全部条目结果（成功与失败逐行混合）。
    pub items: Vec<BatchItem>,
    /// 迁移批次进度说明（行号, 描述），供调用方提示多批次进度。
    pub migration_notes: Vec<(usize, String)>,
    /// 是否解析过 GA 迁移 URI（迁移载荷密钥为明文，调用方应提示
    /// 用户删除原始二维码，与是否多批次无关）。
    pub migration_used: bool,
}

/// 统一分派器：自动识别行格式。
///
/// - `otpauth-migration://` 前缀 → GA 迁移通道（一个 URI 可产出多个条目）
/// - 其余非空行 → otpauth 文本通道
/// - 空行与 `#` 注释行忽略
pub fn parse_any_batch(text: &str) -> Result<ParsedBatch, otpauth_text::BatchError> {
    if text.lines().count() > otpauth_text::MAX_LINES {
        return Err(otpauth_text::BatchError::TooManyLines);
    }
    let mut items = Vec::new();
    let mut migration_notes = Vec::new();
    let mut migration_used = false;
    for (idx, raw) in text.lines().enumerate() {
        let line = idx + 1;
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let is_migration = trimmed.len() >= MIGRATION_PREFIX.len()
            && trimmed[..MIGRATION_PREFIX.len()].eq_ignore_ascii_case(MIGRATION_PREFIX);
        if is_migration {
            migration_used = true;
            let out = gauth::parse_uri_line(line, trimmed);
            items.extend(out.items);
            if let Some(note) = out.note {
                migration_notes.push((line, note));
            }
        } else if let Some(item) = otpauth_text::parse_otpauth_line(line, trimmed) {
            items.push(item);
        }
    }
    Ok(ParsedBatch {
        items,
        migration_notes,
        migration_used,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// 混合格式文件：迁移行走迁移通道（一条 URI 多个条目），
    /// otpauth 行走文本通道，空行与注释忽略。
    #[test]
    fn 混合格式分派() {
        // 单条目迁移 URI（Test1/test1@example1.com，TOTP）
        let migration = "otpauth-migration://offline?data=CjMKD6NIo47vL9P5plq8l5KEhRIQcmFwaGFlbEBiYWRpYS5jYxoIQ29pbkxpc3QgASgBMAIQAhgBIAA%3D";
        let text = format!(
            "# 混合导出\n\
             \n\
             {migration}\n\
             otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP\n\
             坏行\n"
        );
        let parsed = parse_any_batch(&text).unwrap();

        assert_eq!(parsed.items.len(), 3, "迁移 1 条 + 文本 1 条 + 坏行 1 条");
        assert!(
            matches!(&parsed.items[0], BatchItem::Ok { entry, .. } if entry.issuer == "CoinList"),
            "第一项应为迁移条目"
        );
        assert!(
            matches!(&parsed.items[1], BatchItem::Ok { entry, .. } if entry.issuer == "GitHub"),
            "第二项应为文本条目"
        );
        assert!(matches!(&parsed.items[2], BatchItem::Failed { .. }));
        assert!(parsed.migration_notes.is_empty(), "单批次不产生进度说明");
        assert!(parsed.migration_used, "解析过迁移 URI 应置标志");
    }

    /// 超行上限沿用 otpauth_text 的上限并直接拒绝。
    #[test]
    fn 超行上限拒绝() {
        let text = "x\n".repeat(otpauth_text::MAX_LINES + 1);
        assert!(matches!(
            parse_any_batch(&text),
            Err(otpauth_text::BatchError::TooManyLines)
        ));
    }
}
