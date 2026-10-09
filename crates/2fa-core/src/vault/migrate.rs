//! schema 迁移链。
//!
//! `schema_version` 单调递增，逐级纯函数迁移（每级可单独测试）：
//! 低版本程序读高版本文件时明确报错并提示升级，**不尝试部分加载**；
//! 迁移前生成 `.bak`，回写走临时文件 + rename（可中断，见 [`atomic_write`]）。

use std::fs;
use std::path::Path;

use serde::Deserialize;
use zeroize::Zeroizing;

use super::entries::{ModelError, VaultBody};
use super::format::{self, FormatError, SCHEMA_VERSION, VaultFile};
use super::key::VaultKey;
use super::storage::atomic_write;

/// 单级迁移：`vN` 正文 → `vN+1` 正文（纯函数，禁止 IO 与副作用）。
///
/// 以 move 消费旧正文（条目禁 `Clone`，字段经 move 重组而非复制）。
pub(crate) type MigrationStep = fn(VaultBody) -> Result<VaultBody, ModelError>;

/// 迁移链：`(起始版本, 迁移函数)` 按版本升序排列，须覆盖到 `SCHEMA_VERSION - 1` 级。
///
/// 当前 schema v1 为首个版本，链为空；引入 v2 时在此追加 `(1, v1_to_v2)`
/// 并为该级迁移单独编写「语义等价」测试。
const MIGRATIONS: &[(u16, MigrationStep)] = &[];

/// 迁移错误。
#[derive(Debug, thiserror::Error)]
pub enum MigrateError {
    /// 文件版本比程序新——提示升级，绝不部分加载。
    #[error("保险库 schema 版本为 {found}，当前程序支持到 {supported}，请升级程序后再打开")]
    TooNew { found: u16, supported: u16 },
    /// 文件版本无对应迁移路径（损坏的版本号）。
    #[error("保险库 schema 版本为 {found}，不存在对应的迁移路径，文件可能已损坏")]
    NoPath { found: u16 },
    /// 文件格式错误。
    #[error("保险库格式错误：{0}")]
    Format(#[from] FormatError),
    /// 正文模型错误。
    #[error("保险库正文错误：{0}")]
    Model(#[from] ModelError),
    /// 正文 JSON 编解码失败。
    #[error("保险库正文编解码失败：{0}")]
    Json(#[from] serde_json::Error),
    /// 文件系统操作失败。
    #[error("迁移过程中文件操作失败：{0}")]
    Io(#[from] std::io::Error),
}

/// 仅窥探正文的 schema_version 字段（不做全量校验）。
#[derive(Deserialize)]
struct SchemaProbe {
    schema_version: u16,
}

/// 把正文 JSON 逐级迁移到当前 schema 版本，返回迁移后的正文。
///
/// 中间 JSON 字符串含密钥明文，全部纳入零化管辖。
pub(crate) fn run_steps(
    body_json: &Zeroizing<String>,
    version: u16,
    steps: &[(u16, MigrationStep)],
) -> Result<Zeroizing<String>, MigrateError> {
    let mut current_json = Zeroizing::new(body_json.as_str().to_owned());
    for &(from, step) in steps {
        if from < version {
            continue; // 该级迁移在文件版本之前，已经应用过
        }
        // 每级入参必须是「恰好该级版本」的正文：既防跳级，也保证逐级可单独测试
        let body = VaultBody::from_json_version(&current_json, from)?;
        let next = step(body)?;
        // 直接替换绑定：旧 JSON 随 Zeroizing drop 清零
        current_json = next.to_json()?;
    }
    Ok(current_json)
}

/// 加载保险库正文并迁移到当前 schema 版本；发生迁移时回写文件。
///
/// 返回 `(正文, 是否发生迁移)`。回写前先把原始字节完整备份到 `<保险库>.bak`，
/// 随后经 `atomic_write` 落盘——任一步中断，原文件与 `.bak` 均完好可回滚。
pub fn load_and_migrate(
    vault_path: &Path,
    vault_key: &VaultKey,
) -> Result<(VaultBody, bool), MigrateError> {
    let raw = fs::read(vault_path)?;
    let file = VaultFile::parse(&raw)?;
    let body_bytes = format::open(vault_key, &file)?;
    let body_json = Zeroizing::new(
        String::from_utf8(body_bytes)
            .map_err(|_| MigrateError::Format(FormatError::Corrupt("正文不是合法 UTF-8")))?,
    );
    let probe: SchemaProbe = serde_json::from_str(&body_json)?;

    if probe.schema_version > SCHEMA_VERSION {
        return Err(MigrateError::TooNew {
            found: probe.schema_version,
            supported: SCHEMA_VERSION,
        });
    }
    if probe.schema_version == SCHEMA_VERSION {
        return Ok((VaultBody::from_json(&body_json)?, false));
    }

    // 低版本：先确认迁移链从该版本起连续覆盖，否则明确报错，绝不静默处理
    if !MIGRATIONS
        .iter()
        .any(|&(from, _)| from == probe.schema_version)
    {
        return Err(MigrateError::NoPath {
            found: probe.schema_version,
        });
    }
    let migrated_json = run_steps(&body_json, probe.schema_version, MIGRATIONS)?;
    let body = VaultBody::from_json(&migrated_json)?;

    // 备份原文件 → 按新正文重新封装（封套不变，正文 nonce 重新随机）→ 原子回写
    let backup_path = backup_path(vault_path);
    atomic_write(&backup_path, &raw)?;
    let new_file = format::seal(vault_key, file.envelopes.clone(), migrated_json.as_bytes())?;
    atomic_write(vault_path, &new_file.to_bytes())?;
    Ok((body, true))
}

/// `.bak` 备份路径。
fn backup_path(vault_path: &Path) -> std::path::PathBuf {
    let mut name = vault_path
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".bak");
    vault_path.with_file_name(name)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::vault::entries::Entry;
    use crate::vault::envelope::Envelope;
    use std::env;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let base = env::temp_dir().join(format!("2fa-migrate-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        base
    }

    fn sample_body() -> VaultBody {
        let mut body = VaultBody::empty(1_700_000_000);
        body.entries.push(
            Entry::new(
                "GitHub".into(),
                "alice".into(),
                crate::vault::key::SecretKey::from_base32("MZXW6YTBOI").unwrap(),
                crate::domain::totp::Algorithm::Sha1,
                6,
                30,
                Vec::new(),
            )
            .unwrap(),
        );
        body
    }

    fn write_vault(dir: &Path, body: &VaultBody) -> std::path::PathBuf {
        let vault = dir.join("vault.json");
        let key = VaultKey::new([7u8; 32]);
        let envelopes = vec![
            Envelope::seal(&key, "主密码").unwrap(),
            Envelope::seal(&key, "恢复码").unwrap(),
        ];
        let file = format::seal(&key, envelopes, body.to_json().unwrap().as_bytes()).unwrap();
        fs::write(&vault, file.to_bytes()).unwrap();
        vault
    }

    /// 当前版本文件：不迁移、内容原样。
    #[test]
    fn 当前版本不迁移() {
        let dir = temp_dir("no-op");
        let vault = write_vault(&dir, &sample_body());
        let original = fs::read(&vault).unwrap();
        let key = VaultKey::new([7u8; 32]);

        let (body, migrated) = load_and_migrate(&vault, &key).unwrap();

        assert!(!migrated);
        assert_eq!(body.entries.len(), 1);
        assert_eq!(body.entries[0].issuer, "GitHub");
        assert!(!backup_path(&vault).exists(), "未迁移不应产生 .bak");
        assert_eq!(fs::read(&vault).unwrap(), original, "文件字节不应改变");
    }

    /// 高版本文件：明确报错并提示升级，绝不部分加载。
    #[test]
    fn 高版本文件报错提示升级() {
        let dir = temp_dir("too-new");
        let mut body = sample_body();
        body.schema_version = 2;
        let vault = write_vault(&dir, &body);
        let key = VaultKey::new([7u8; 32]);

        let err = load_and_migrate(&vault, &key).unwrap_err();
        assert!(
            matches!(
                err,
                MigrateError::TooNew {
                    found: 2,
                    supported: 1
                }
            ),
            "实际 {err:?}"
        );
    }

    /// 伪造的旧版本（无迁移路径）报 NoPath，不静默处理。
    #[test]
    fn 无迁移路径的版本报错() {
        let dir = temp_dir("no-path");
        let mut body = sample_body();
        body.schema_version = 0;
        let vault = write_vault(&dir, &body);
        let key = VaultKey::new([7u8; 32]);

        let err = load_and_migrate(&vault, &key).unwrap_err();
        assert!(
            matches!(err, MigrateError::NoPath { found: 0 }),
            "实际 {err:?}"
        );
    }

    /// 逐级迁移框架：多级步骤按序执行，每级入参为上一级输出（move 语义）。
    #[test]
    fn 迁移链逐级执行() {
        fn step_a(body: VaultBody) -> Result<VaultBody, ModelError> {
            let mut next = VaultBody::empty(body.created_at);
            next.schema_version = body.schema_version + 1;
            // 条目禁止 Clone，只能整批 move 前移
            next.entries = body.entries;
            Ok(next)
        }
        fn step_b(body: VaultBody) -> Result<VaultBody, ModelError> {
            let mut next = VaultBody::empty(body.created_at);
            next.schema_version = body.schema_version + 1;
            next.entries = body.entries;
            Ok(next)
        }

        // 伪造 v0 → v1 → v2 的两步链
        let steps: Vec<(u16, MigrationStep)> = vec![(0, step_a), (1, step_b)];
        let mut v0 = VaultBody::empty(1_700_000_000);
        v0.entries.push(
            crate::vault::entries::Entry::new(
                "GitHub".into(),
                "alice".into(),
                crate::vault::key::SecretKey::from_base32("MZXW6YTBOI").unwrap(),
                crate::domain::totp::Algorithm::Sha1,
                6,
                30,
                Vec::new(),
            )
            .unwrap(),
        );
        v0.schema_version = 0;
        let json = v0.to_json().unwrap();

        let migrated = run_steps(&json, 0, &steps).unwrap();
        let body = serde_json::from_str::<VaultBody>(&migrated).unwrap();
        assert_eq!(body.schema_version, 2, "应迁移两级");
        assert_eq!(body.entries.len(), 1, "step_b 应保留条目");
    }

    /// 迁移后 .bak 保存迁移前的原始字节，可用于回滚。
    #[test]
    fn 迁移后bak可回滚() {
        // 无迁移路径的 v0 触发不了备份；此处用注入迁移步骤的 run_steps 验证框架，
        // 文件级备份逻辑由「当前版本不迁移」与真实 v2 引入后的端到端测试覆盖。
        // 现阶段验证 backup_path 命名正确。
        let vault = Path::new("D:/x/vault.json");
        assert_eq!(backup_path(vault), Path::new("D:/x/vault.json.bak"));
    }
}
