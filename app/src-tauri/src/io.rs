//! 导入导出（M9-3）：加密备份导出/导入、明文导出（四道门槛）、查看密钥。
//!
//! 语义对齐 CLI（`crates/2fa-cli/src/commands.rs` 的
//! `cmd_export_backup` / `import_backup_bytes` / `op_export_plain` / `op_show`）：
//! - 加密备份是保险库文件的**字节级拷贝**，导出无需解锁；导入整文件覆盖并
//!   把当前保险库的主密码与恢复码替换为备份中的凭据
//! - 明文导出属危险出口，四道门槛缺一不可（见 [`export_plain`]）
//! - 查看密钥的确认弹窗由前端承担（GUI 的 UI 层即确认处），本模块只负责取数
//!
//! 本模块不含 Tauri 依赖，可完整单元测试。

use std::path::Path;

use serde::Serialize;
use two_fa_core::usecase::recovery;
use two_fa_core::vault::{
    Entry, LockError, RotateError, SCHEMA_VERSION, UnlockError, VaultBody, VaultLock, backup_path,
    load_and_migrate, rotate_recovery, unlock_readonly,
};

use crate::commands::{code_of, remaining_secs};

/// 导出结果视图（加密备份与明文导出共用）。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ExportOut {
    /// 导出文件路径（回显——防呆纪律）。
    pub path: String,
    /// 写入字节数。
    pub bytes: usize,
}

/// 备份导入结果两段式：先验证预览（等待用户确认覆盖），确认后执行导入。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "stage", rename_all = "snake_case")]
pub enum ImportOut {
    /// 备份凭据已验证，等待用户确认覆盖（entry_count 为备份内条目数）。
    NeedConfirm {
        entry_count: usize,
        /// 备份 schema 低于当前版本，导入后将自动迁移。
        schema_migrates: bool,
    },
    /// 导入完成（会话已被调用方强制锁定，旧凭据失效）。
    Done { entry_count: usize },
}

/// 查看密钥视图（`show` 等价）：确认弹窗在前端，密钥仅在确认后经此回传。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SecretView {
    pub id: String,
    pub id_prefix: String,
    pub issuer: String,
    pub account: String,
    pub algorithm: &'static str,
    pub digits: u8,
    pub period: u32,
    pub tags: Vec<String>,
    /// 当前验证码（密钥解码失败时为 None）。
    pub code: Option<String>,
    pub remaining_secs: u64,
    /// 明文密钥（Base32）。仅经用户确认后的查看入口回传。
    pub secret: String,
}

/// 拒绝导出目标指向保险库本体（会覆盖保险库，语义同 CLI `ensure_not_vault_path`）。
fn ensure_not_vault_path(vault_path: &Path, target: &Path) -> Result<(), String> {
    let vault_abs =
        std::fs::canonicalize(vault_path).map_err(|e| format!("解析保险库路径失败：{e}"))?;
    if std::fs::canonicalize(target).is_ok_and(|c| c == vault_abs) {
        return Err("导出路径与保险库相同，会覆盖保险库本体，请另选路径".to_string());
    }
    Ok(())
}

/// 获取文件锁（短持，语义同 CLI `acquire_lock`）。
fn acquire(path: &Path) -> Result<VaultLock, String> {
    VaultLock::acquire(path).map_err(|e| match e {
        LockError::Busy { pid } => {
            format!("另一个 2FA 进程（PID {pid}）正在编辑此保险库，请稍后再试")
        }
        LockError::Io(err) => format!("文件锁操作失败：{err}"),
    })
}

/// 解锁错误映射：备份导入的密码错需指明是「备份的主密码」。
fn map_unlock_err(e: UnlockError) -> String {
    match e {
        UnlockError::AuthFailed => "认证失败：备份文件的主密码错误".to_string(),
        other => other.to_string(),
    }
}

/// 加密备份导出核心：字节级拷贝（无需解锁），持文件锁防止拷到并发写的中间态。
/// 保险库不存在时明确报错。
pub fn export_backup(vault_path: &Path, target: &Path) -> Result<ExportOut, String> {
    if !vault_path.is_file() {
        return Err(format!(
            "保险库文件不存在：{}（可先用 CLI 执行 2fa init 创建）",
            vault_path.display()
        ));
    }
    ensure_not_vault_path(vault_path, target)?;
    let _lock = acquire(vault_path)?;
    let raw = std::fs::read(vault_path).map_err(|e| format!("读取保险库失败：{e}"))?;
    two_fa_core::vault::atomic_write(target, &raw).map_err(|e| format!("写入备份失败：{e}"))?;
    Ok(ExportOut {
        path: target.display().to_string(),
        bytes: raw.len(),
    })
}

/// 加密备份导入预览：只读验证备份凭据（绝不触碰当前保险库），返回覆盖确认
/// 所需信息。对应 CLI 导入的「验证 + 显式确认覆盖」前半段。
pub fn import_backup_preview(raw: &[u8], password: &str) -> Result<ImportOut, String> {
    let (_, body, schema) = unlock_readonly(raw, password).map_err(map_unlock_err)?;
    Ok(ImportOut::NeedConfirm {
        entry_count: body.entries.len(),
        schema_migrates: schema < SCHEMA_VERSION,
    })
}

/// 加密备份导入执行（用户已在前端确认覆盖）：验证 → 当前库存入 `.bak`
/// （回滚保障）→ 原子写入备份字节 → 老 schema 走迁移链 → 条目数校验。
/// 返回导入后条目数。**调用方必须随后使旧会话凭据失效**（CLI 是独立进程
/// 无此问题，GUI 会话内的密钥与正文在覆盖后即失效）。
pub fn import_backup_commit(
    vault_path: &Path,
    raw: &[u8],
    password: &str,
) -> Result<usize, String> {
    let (key, body, _schema) = unlock_readonly(raw, password).map_err(map_unlock_err)?;
    let entries_before = body.entries.len();

    let _lock = acquire(vault_path)?;
    if vault_path.is_file() {
        let current = std::fs::read(vault_path).map_err(|e| format!("读取当前保险库失败：{e}"))?;
        two_fa_core::vault::atomic_write(&backup_path(vault_path), &current)
            .map_err(|e| format!("备份当前保险库失败：{e}"))?;
    }
    if let Some(parent) = vault_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| format!("创建保险库目录失败：{e}"))?;
    }
    two_fa_core::vault::atomic_write(vault_path, raw)
        .map_err(|e| format!("写入备份内容失败：{e}"))?;

    let (body_after, _migrated) =
        load_and_migrate(vault_path, &key).map_err(|e| format!("备份导入后迁移失败：{e}"))?;
    // 防御性校验（迁移链保证不丢条目；与 CLI 同语义不阻断，但文案可见）
    let entries_after = body_after.entries.len();
    if entries_after != entries_before {
        return Err(format!(
            "导入后条目数（{entries_after}）与备份时（{entries_before}）不一致，请立即检查保险库！"
        ));
    }
    Ok(entries_after)
}

/// 明文导出第一段（危险出口）：校验门槛 1 与内容序列化，不碰文件系统。
///
/// 四道门槛（对齐 CLI `op_export_plain`）：
/// 1. 二次确认——`confirm_count` 必须等于当前条目数（前端输入框收集，后端校验）
/// 2. 输出路径显式指定（前端系统另存对话框，无默认路径）
/// 3. 文件首行中文警告注释（core 序列化器写入）
/// 4. 完成后强提示删除（前端完成态展示）
pub fn plain_export_text(body: &VaultBody, confirm_count: &str) -> Result<String, String> {
    let count = body.entries.len();
    if count == 0 {
        return Err("保险库为空，没有可导出的条目".to_string());
    }
    if confirm_count.trim() != count.to_string() {
        return Err(format!(
            "确认失败：输入的条目数与当前条目数（{count}）不一致，已取消导出"
        ));
    }
    Ok(two_fa_core::importexport::serialize_plain(body))
}

/// 导出第二段：拒绝写保险库本体 → 持锁原子写入。返回路径与字节数。
pub fn write_export(vault_path: &Path, target: &Path, bytes: &[u8]) -> Result<ExportOut, String> {
    ensure_not_vault_path(vault_path, target)?;
    let _lock = acquire(vault_path)?;
    two_fa_core::vault::atomic_write(target, bytes).map_err(|e| format!("写入导出失败：{e}"))?;
    Ok(ExportOut {
        path: target.display().to_string(),
        bytes: bytes.len(),
    })
}

/// 构造查看密钥视图（`plen` 来自 core 的库内唯一前缀长度）。
pub fn secret_view(entry: &Entry, now: u64, plen: usize) -> SecretView {
    SecretView {
        id: entry.id.to_string(),
        id_prefix: entry.id.to_string()[..plen].to_string(),
        issuer: entry.issuer.clone(),
        account: entry.account.clone(),
        algorithm: entry.algorithm.label(),
        digits: entry.digits,
        period: entry.period,
        tags: entry.tags.clone(),
        code: code_of(entry, now),
        remaining_secs: remaining_secs(entry, now),
        secret: entry.secret.as_text().to_string(),
    }
}

/// 改主密码：旧密码验证通过后换新密码。
///
/// 复用 core 凭据轮换原语 `rotate_recovery`（实现与本语义无关地通用：命中
/// 旧凭据的封套按新凭据重封、按新头部重算正文密文，`.bak` 可回滚，中断时
/// 原文件完好、旧密码仍可用）。主密钥与条目明文不变——成功后会话状态无需
/// 复位。恢复码封套不匹配旧密码时不受影响（若恢复码恰与旧主密码相同则
/// 一并轮换，与 core 文档化的「凭据等价」语义一致）。
pub fn change_password(vault_path: &Path, old: &str, new: &str) -> Result<(), String> {
    if new.trim().is_empty() {
        return Err("新主密码不能为空".to_string());
    }
    if !vault_path.is_file() {
        return Err(format!(
            "保险库文件不存在：{}（可先用 CLI 执行 2fa init 创建）",
            vault_path.display()
        ));
    }
    let _lock = acquire(vault_path)?;
    rotate_recovery(vault_path, old, new).map_err(|e| match e {
        RotateError::AuthFailed => "认证失败：旧主密码错误".to_string(),
        other => other.to_string(),
    })
}

/// 恢复码恢复：验证旧恢复码 → 生成新恢复码 → 强制轮换（旧码即刻作废）。
/// 返回新恢复码（展示形式，只显示这一次）。
///
/// 恢复码通道**不解锁会话**——轮换完成后仍需用主密码或新恢复码解锁
/// （CLI `recover` 同语义：recover 不是登录方式，而是找回手段）。
pub fn recover(vault_path: &Path, old_input: &str) -> Result<String, String> {
    if !vault_path.is_file() {
        return Err(format!(
            "保险库文件不存在：{}（可先用 CLI 执行 2fa init 创建）",
            vault_path.display()
        ));
    }
    let new_code = recovery::generate().map_err(|e| format!("生成新恢复码失败：{e}"))?;
    let _lock = acquire(vault_path)?;
    rotate_recovery(
        vault_path,
        &recovery::normalize(old_input),
        &recovery::normalize(&new_code),
    )
    .map_err(|e| match e {
        RotateError::AuthFailed => "认证失败：恢复码错误".to_string(),
        other => other.to_string(),
    })?;
    Ok(new_code)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use two_fa_core::domain::totp::Algorithm;
    use two_fa_core::usecase::{entries, init};
    use two_fa_core::vault::{SecretKey, atomic_write, unlock};

    /// 临时目录（按用例标签隔离）。
    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("2fa-app-io-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 创建含 count 个条目的测试保险库，返回（路径, 字节）。
    fn make_vault(tag: &str, password: &str, count: usize) -> (std::path::PathBuf, Vec<u8>) {
        let dir = temp_dir(tag);
        let path = dir.join("vault.json");
        let bytes = init::create_vault(password, "RECOVERYCODE1234", 1_700_000_000).unwrap();
        atomic_write(&path, &bytes).unwrap();
        if count > 0 {
            let (key, _) = unlock(&path, password).unwrap();
            let mut body = VaultBody::empty(1_700_000_000);
            for i in 0..count {
                body.entries.push(
                    Entry::new(
                        format!("服务{i}"),
                        format!("acct{i}"),
                        SecretKey::from_base32("JBSWY3DPEHPK3PXP").unwrap(),
                        Algorithm::Sha1,
                        6,
                        30,
                        vec![],
                    )
                    .unwrap(),
                );
            }
            entries::save(&path, &key, &body).unwrap();
        }
        let raw = std::fs::read(&path).unwrap();
        (path, raw)
    }

    /// 加密备份导出：字节级拷贝（与原文件逐字节一致），且原主密码可只读解锁。
    #[test]
    fn 备份导出字节级一致() {
        let (vault, raw) = make_vault("bk-ok", "主密码A", 2);
        let target = temp_dir("bk-ok-out").join("backup.json");

        let out = export_backup(&vault, &target).unwrap();

        assert_eq!(out.bytes, raw.len());
        assert_eq!(std::fs::read(&target).unwrap(), raw, "必须是字节级拷贝");
        let (_, body, _) = unlock_readonly(&std::fs::read(&target).unwrap(), "主密码A").unwrap();
        assert_eq!(body.entries.len(), 2);
        assert_eq!(out.path, target.display().to_string());
    }

    /// 导出目标与保险库相同被拒绝（防覆盖本体）；保险库不存在明确报错。
    #[test]
    fn 备份导出防呆() {
        let (vault, _) = make_vault("bk-same", "主密码A", 1);
        let err = export_backup(&vault, &vault).unwrap_err();
        assert!(err.contains("保险库相同"), "{err}");

        let missing = temp_dir("bk-missing").join("none.json");
        let target = temp_dir("bk-missing").join("o.json");
        let err = export_backup(&missing, &target).unwrap_err();
        assert!(err.contains("不存在"), "{err}");
    }

    /// 导入预览：正确密码返回条目数与迁移标记；错误密码明确指向备份主密码。
    #[test]
    fn 备份导入预览() {
        let (_, raw) = make_vault("pv-src", "主密码B", 3);

        match import_backup_preview(&raw, "主密码B").unwrap() {
            ImportOut::NeedConfirm {
                entry_count,
                schema_migrates,
            } => {
                assert_eq!(entry_count, 3);
                assert!(!schema_migrates, "当前版本备份无需迁移");
            }
            other => panic!("应为 NeedConfirm：{other:?}"),
        }

        let err = import_backup_preview(&raw, "错误密码").unwrap_err();
        assert!(err.contains("备份"), "错误信息应指明是备份的主密码：{err}");
    }

    /// 导入执行：整文件覆盖、主密码替换为备份凭据、旧密码失效、`.bak` 保留旧库。
    #[test]
    fn 备份导入覆盖与凭据替换() {
        let (vault_a, _) = make_vault("im-a", "旧主密码", 1);
        let (_, raw_b) = make_vault("im-b", "备份主密码", 2);

        let imported = import_backup_commit(&vault_a, &raw_b, "备份主密码").unwrap();
        assert_eq!(imported, 2);

        // 当前库的凭据已被替换：旧密码失效、备份密码可用
        let err = unlock(&vault_a, "旧主密码").unwrap_err();
        assert!(matches!(err, UnlockError::AuthFailed));
        let (_, body, _) =
            unlock_readonly(&std::fs::read(&vault_a).unwrap(), "备份主密码").unwrap();
        assert_eq!(body.entries.len(), 2);

        // 回滚保障：覆盖前的旧库存入 .bak
        let bak = backup_path(&vault_a);
        assert!(bak.is_file(), ".bak 必须存在：{}", bak.display());
        let (_, old_body, _) = unlock_readonly(&std::fs::read(&bak).unwrap(), "旧主密码").unwrap();
        assert_eq!(old_body.entries.len(), 1);
    }

    /// 明文导出门槛：确认数不符拒绝、空库拒绝、成功后首行为警告注释且可被
    /// 自家导入器解析（往返无损）。
    #[test]
    fn 明文导出四道门槛() {
        let (vault, _) = make_vault("pl-ok", "主密码A", 2);
        let (key, _) = unlock(&vault, "主密码A").unwrap();
        let (body, _) = load_and_migrate(&vault, &key).unwrap();

        // 门槛 1：确认数不符拒绝（CLI 同语义：输入 trim 后比对）
        let err = plain_export_text(&body, "3").unwrap_err();
        assert!(err.contains("不一致"), "{err}");
        let err = plain_export_text(&body, "").unwrap_err();
        assert!(err.contains("不一致"), "{err}");

        // 空库拒绝
        let empty = VaultBody::empty(1_700_000_000);
        let err = plain_export_text(&empty, "0").unwrap_err();
        assert!(err.contains("为空"), "{err}");

        // 正确确认数（允许首尾空白）：首行警告注释 + 可被导入器解析
        let text = plain_export_text(&body, " 2 ").unwrap();
        assert_eq!(
            text.lines().next().unwrap(),
            two_fa_core::importexport::WARNING_LINE,
            "首行必须是警告注释"
        );
        let parsed = two_fa_core::importexport::parse_any_batch(&text).unwrap();
        assert_eq!(parsed.items.len(), 2);

        // 写入目标与保险库相同被拒绝
        let err = write_export(&vault, &vault, text.as_bytes()).unwrap_err();
        assert!(err.contains("保险库相同"), "{err}");

        // 正常写盘
        let target = temp_dir("pl-out").join("plain.txt");
        let out = write_export(&vault, &target, text.as_bytes()).unwrap();
        assert_eq!(out.bytes, text.len());
    }

    /// 密钥视图：字段完整映射，密钥为 Base32 明文，前缀长度一致。
    #[test]
    fn 密钥视图字段() {
        let (vault, _) = make_vault("sv", "主密码A", 1);
        let (key, _) = unlock(&vault, "主密码A").unwrap();
        let (body, _) = load_and_migrate(&vault, &key).unwrap();
        let plen = entries::unique_prefix_len(&body);
        let entry = &body.entries[0];

        let view = secret_view(entry, 1_800_000_123, plen);

        assert_eq!(view.issuer, "服务0");
        assert_eq!(view.account, "acct0");
        assert_eq!(view.algorithm, "SHA1");
        assert_eq!(view.digits, 6);
        assert_eq!(view.period, 30);
        assert_eq!(view.id_prefix.len(), plen);
        assert_eq!(view.secret, "JBSWY3DPEHPK3PXP");
        assert!(view.code.is_some());
        assert_eq!(view.remaining_secs, 30 - 1_800_000_123 % 30);
    }

    /// 改主密码：旧密码失效、新密码可用、恢复码封套不受影响、条目明文不变。
    #[test]
    fn 改主密码后新旧密码行为() {
        let (vault, _) = make_vault("cp-ok", "旧主密码", 2);

        change_password(&vault, "旧主密码", "新主密码").unwrap();

        let err = unlock(&vault, "旧主密码").unwrap_err();
        assert!(matches!(err, UnlockError::AuthFailed));
        let (key, _) = unlock(&vault, "新主密码").unwrap();
        let (body, _) = load_and_migrate(&vault, &key).unwrap();
        assert_eq!(body.entries.len(), 2);
        assert_eq!(body.entries[0].issuer, "服务0");
        // 恢复码封套不受影响（测试库恢复码 RECOVERYCODE1234 ≠ 旧主密码）
        let (_, rb, _) =
            unlock_readonly(&std::fs::read(&vault).unwrap(), "RECOVERYCODE1234").unwrap();
        assert_eq!(rb.entries.len(), 2);
        // .bak 保存改密前字节
        assert!(backup_path(&vault).is_file());
    }

    /// 改主密码：旧密码错误认证失败且文件不变；新密码为空拒绝。
    #[test]
    fn 改主密码防呆() {
        let (vault, original) = make_vault("cp-wrong", "旧主密码", 1);

        let err = change_password(&vault, "错误密码", "新主密码").unwrap_err();
        assert!(err.contains("旧主密码错误"), "{err}");

        let err = change_password(&vault, "旧主密码", "   ").unwrap_err();
        assert!(err.contains("不能为空"), "{err}");

        assert_eq!(std::fs::read(&vault).unwrap(), original, "文件不应被改动");
        let (key, _) = unlock(&vault, "旧主密码").unwrap();
        let _ = key;
    }

    /// 恢复码恢复：旧码失效、新码（归一化后）可解封、返回展示形式。
    #[test]
    fn 恢复码恢复轮换() {
        let (vault, _) = make_vault("rc-ok", "主密码A", 1);

        let new_code = recover(&vault, "recoverycode1234").unwrap();

        // 返回展示形式：4 组 × 4 字符连字符分隔，Base32 字母表
        let groups: Vec<&str> = new_code.split('-').collect();
        assert_eq!(groups.len(), 4);
        assert!(groups.iter().all(|g| g.len() == 4));
        // 旧码即刻作废、新码可用（输入小写经归一化验证通过）
        let file = two_fa_core::vault::VaultFile::parse(&std::fs::read(&vault).unwrap()).unwrap();
        for envelope in &file.envelopes {
            assert!(envelope.unseal("RECOVERYCODE1234").is_err(), "旧码应作废");
        }
        let key = file
            .envelopes
            .iter()
            .find_map(|e| e.unseal(&recovery::normalize(&new_code)).ok())
            .expect("新恢复码应可解封");
        let _ = key;
        // 主密码不受影响
        let (_, body, _) = unlock_readonly(&std::fs::read(&vault).unwrap(), "主密码A").unwrap();
        assert_eq!(body.entries.len(), 1);
    }

    /// 恢复码恢复：错误旧码认证失败且文件不变。
    #[test]
    fn 恢复码恢复错误旧码() {
        let (vault, original) = make_vault("rc-wrong", "主密码A", 1);

        let err = recover(&vault, "WRONGCODE0000").unwrap_err();

        assert!(err.contains("恢复码错误"), "{err}");
        assert_eq!(std::fs::read(&vault).unwrap(), original, "文件不应被改动");
    }
}
