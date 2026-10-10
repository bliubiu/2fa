//! 条目 CRUD 编排：读正文 → 变更 → 重封装回写。
//!
//! 回写只换正文：封套保持原样，正文 nonce 重新随机，
//! 认证标签覆盖新头部（头部整体是正文 GCM 的 AAD）。

use std::io;
use std::path::Path;

use crate::vault::{FormatError, ModelError, VaultBody, VaultFile, VaultKey, atomic_write, format};

/// 条目操作错误。
#[derive(Debug, thiserror::Error)]
pub enum EntryOpError {
    /// 文件系统操作失败。
    #[error("读取保险库失败：{0}")]
    Io(#[from] io::Error),
    /// 保险库格式错误。
    #[error("保险库格式错误：{0}")]
    Format(#[from] FormatError),
    /// 正文编解码或字段校验失败。
    #[error("{0}")]
    Model(#[from] ModelError),
    /// 未找到匹配的条目。
    #[error("未找到条目：{0}")]
    NotFound(String),
    /// id 前缀匹配到多个条目。
    #[error("id 前缀匹配到多个条目，请输入更长前缀或直接使用完整 ID：{0}")]
    Ambiguous(String),
}

/// 将正文重封装回写保险库文件（封套不变，正文 nonce 重随机）。
///
/// 正文经 [`VaultBody::from_json`] 同源校验，写出的文件必然可解析。
pub fn save(vault_path: &Path, key: &VaultKey, body: &VaultBody) -> Result<(), EntryOpError> {
    let raw = std::fs::read(vault_path)?;
    let file = VaultFile::parse(&raw)?;
    let body_json = body.to_json()?;
    let sealed = format::seal(key, file.envelopes, body_json.as_bytes())?;
    atomic_write(vault_path, &sealed.to_bytes())?;
    Ok(())
}

/// 按 id 前缀查找唯一条目，返回其在 `entries` 中的下标。
///
/// 前缀过短（多个匹配）或无匹配时报错；调用方用下标完成读取或变更。
pub fn find_index_by_prefix(body: &VaultBody, prefix: &str) -> Result<usize, EntryOpError> {
    let matches: Vec<usize> = body
        .entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e.id.to_string().starts_with(prefix))
        .map(|(idx, _)| idx)
        .collect();
    match matches.len() {
        1 => Ok(matches[0]),
        0 => Err(EntryOpError::NotFound(prefix.to_string())),
        _ => Err(EntryOpError::Ambiguous(
            matches
                .iter()
                .map(|&idx| body.entries[idx].id.to_string())
                .collect::<Vec<_>>()
                .join("、"),
        )),
    }
}

/// 计算使全部条目 id 互异的最短统一前缀长度（8 起步，上限 32）。
///
/// UUID v7 的前 48 bit 是毫秒时间戳：同毫秒批量创建的条目（如单次导入
/// 多个条目）8 位前缀必然相同，展示层须自动延长到可区分为止。
pub fn unique_prefix_len(body: &VaultBody) -> usize {
    let ids: Vec<String> = body.entries.iter().map(|e| e.id.to_string()).collect();
    for len in 8..=32 {
        let mut seen = std::collections::HashSet::with_capacity(ids.len());
        if ids.iter().all(|id| seen.insert(&id[..len])) {
            return len;
        }
    }
    32
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::domain::totp::Algorithm;
    use crate::vault::Entry;
    use crate::vault::{Envelope, SecretKey, format, unlock};

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

    /// 建一个双封套测试保险库，返回 (路径, 主密钥)。
    fn make_vault(dir: &Path) -> (std::path::PathBuf, VaultKey) {
        let path = dir.join("vault.json");
        let key = VaultKey::generate().unwrap();
        let mut body = VaultBody::empty(1_700_000_000);
        body.entries
            .push(sample_entry("GitHub", "alice", "MZXW6YTBOI"));
        let envelopes = vec![
            Envelope::seal(&key, "主密码").unwrap(),
            Envelope::seal(&key, "恢复码").unwrap(),
        ];
        let file = format::seal(&key, envelopes, body.to_json().unwrap().as_bytes()).unwrap();
        atomic_write(&path, &file.to_bytes()).unwrap();
        (path, key)
    }

    /// 回写后：封套不变（同盐）、条目语义不变、文件仍可正常解锁。
    #[test]
    fn 回写保持封套与条目不变() {
        let dir = std::env::temp_dir().join(format!("2fa-save-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (path, key) = make_vault(&dir);
        let before = VaultFile::parse(&std::fs::read(&path).unwrap()).unwrap();

        let mut body = VaultBody::empty(1_700_000_000);
        body.entries
            .push(sample_entry("GitHub", "alice", "MZXW6YTBOI"));
        body.entries.push(sample_entry("GitLab", "bob", "MZXW6YQ"));
        save(&path, &key, &body).unwrap();

        let after = VaultFile::parse(&std::fs::read(&path).unwrap()).unwrap();
        // 封套不变：盐与密文逐字节一致（同一密钥、同一凭据、未重封）
        assert_eq!(before.envelopes[0].salt, after.envelopes[0].salt);
        assert_eq!(
            before.envelopes[0].ciphertext,
            after.envelopes[0].ciphertext
        );

        // 正文可用新头部解密，条目语义不变
        let body_json = format::open(&key, &after).unwrap();
        let parsed = VaultBody::from_json(std::str::from_utf8(&body_json).unwrap()).unwrap();
        assert_eq!(parsed.entries.len(), 2);
        assert_eq!(parsed.entries[0].issuer, "GitHub");
        assert_eq!(parsed.entries[1].issuer, "GitLab");

        // 解锁路径仍然通畅
        let unlocked = unlock(&path, "主密码");
        assert!(unlocked.is_ok());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// id 前缀查找：唯一命中、多命中报歧义、无命中报未找到。
    #[test]
    fn 前缀查找三种结果() {
        let mut body = VaultBody::empty(0);
        let a = sample_entry("A", "a", "MZXW6YTBOI");
        let b = sample_entry("B", "b", "MZXW6YTBOI");
        let id_a = a.id.to_string();
        body.entries.push(a);
        body.entries.push(b);

        // 同毫秒批量创建的 v7 id 时间戳段相同：8 位（甚至 12 位）都可能歧义，
        // 完整 id 必然唯一
        let idx = find_index_by_prefix(&body, &id_a).unwrap();
        assert_eq!(body.entries[idx].issuer, "A");

        // 8 位前缀在同毫秒场景下可能歧义 → 报错要求更长前缀
        assert!(matches!(
            find_index_by_prefix(&body, &id_a[..8]),
            Err(EntryOpError::Ambiguous(_))
        ));

        // 空前缀匹配全部 → 歧义
        assert!(matches!(
            find_index_by_prefix(&body, ""),
            Err(EntryOpError::Ambiguous(_))
        ));

        // 无人匹配 → 未找到
        assert!(matches!(
            find_index_by_prefix(&body, "ffffffff"),
            Err(EntryOpError::NotFound(_))
        ));
    }

    /// 歧义错误必须给出可区分的更长前缀：同毫秒批量创建的 v7 id
    /// 8 位前缀全同（前 32 bit 全是毫秒时间戳），此时错误消息
    /// 列出的候选必须是完整 UUID，不能把同一个 8 位前缀重复列一遍。
    #[test]
    fn 歧义消息列出完整uuid() {
        let mut body = VaultBody::empty(0);
        let a = sample_entry("A", "a", "MZXW6YTBOI");
        let b = sample_entry("B", "b", "MZXW6YTBOI");
        body.entries.push(a);
        body.entries.push(b);
        let Err(EntryOpError::Ambiguous(msg)) = find_index_by_prefix(&body, "") else {
            panic!("空前缀应歧义");
        };
        // 消息含两个完整 UUID（36 字符带连字符），且互不相同
        let full: Vec<&str> = msg
            .split("、")
            .map(str::trim)
            .filter(|s| s.len() == 36)
            .collect();
        assert_eq!(full.len(), 2, "应列出两个完整 UUID：{msg}");
        assert_ne!(full[0], full[1], "完整 UUID 必然互异：{msg}");
    }

    /// 唯一前缀长度：单条目与空库 8 位；同毫秒批量创建的 v7 id
    /// 时间戳段相同，长度必须自动延长到使全部 id 互异为止。
    #[test]
    fn 唯一前缀长度自适应() {
        // 空库与单条目：8 位足够
        assert_eq!(unique_prefix_len(&VaultBody::empty(0)), 8);
        let mut body = VaultBody::empty(0);
        body.entries.push(sample_entry("A", "a", "MZXW6YTBOI"));
        assert_eq!(unique_prefix_len(&body), 8);

        // 同毫秒批量创建：v7 时间前缀相同 → 长度 > 8 且用该长度截断后互异
        let mut batch = VaultBody::empty(0);
        for i in 0..8 {
            batch
                .entries
                .push(sample_entry(&format!("S{i}"), "u", "MZXW6YTBOI"));
        }
        let len = unique_prefix_len(&batch);
        assert!(len > 8, "同毫秒批量创建的 8 位前缀应冲突：{len}");
        let mut seen = std::collections::HashSet::new();
        for e in &batch.entries {
            let pfx = e.id.to_string()[..len].to_string();
            assert!(seen.insert(pfx), "长度 {len} 下前缀仍冲突");
        }
    }
}
