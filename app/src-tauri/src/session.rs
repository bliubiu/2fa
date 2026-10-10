//! GUI 会话状态机：解锁 / 锁定 / 空闲超时 / 状态查询。
//!
//! 与 CLI REPL 的会话（`crates/2fa-cli/src/session.rs`）同语义：
//! - 主密钥与正文明文仅驻内存，`lock` 即 `drop`（`Zeroizing` 保证字节清零）
//! - 空闲超时自动锁定：取用正文刷新活动时刻，前端心跳定期调用 `check_idle`
//! - 文件锁不做会话级持有——与 CLI 一致，写操作（M9）在落盘时各自处理
//!
//! 本模块不含任何 Tauri 依赖，可完整单元测试。

use std::path::Path;
use std::time::{Duration, Instant};

use serde::Serialize;
use two_fa_core::vault::{
    UnlockError, UpgradeOutcome, VaultBody, VaultFile, VaultKey, kdf_params, load_and_migrate,
    unlock,
};

use crate::paths::ResolvedVault;

/// 状态视图（`status` 命令返回）。
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct StatusView {
    /// 保险库绝对路径（每次回显——防呆最后一道防线）。
    pub path: String,
    /// 路径来源（项目内 / 平台惯例）。
    pub source: String,
    /// 是否已解锁。
    pub unlocked: bool,
    /// 条目数量；锁定时为 None。
    pub entry_count: Option<usize>,
    /// 封套 KDF 版本（去重升序）；锁定时为 None。
    pub kdf_versions: Option<String>,
}

/// 会话级错误：`kind` 供前端分支逻辑，`message` 恒为中文且不含敏感输入。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// 保险库文件不存在（引导用户先用 CLI init 创建）。
    NoVault(String),
    /// 主密码错误。
    Auth,
    /// 未解锁时调用了需要解锁的命令。
    Locked,
    /// 条目 ID 前缀无匹配或多匹配（core 已给出中文候选列表）。
    NotFound(String),
    /// 其他错误（core 错误文本已为中文）。
    Other(String),
}

impl SessionError {
    /// 供前端分支的错误类别。
    pub fn kind(&self) -> &'static str {
        match self {
            Self::NoVault(_) => "no_vault",
            Self::Auth => "auth",
            Self::Locked => "locked",
            Self::NotFound(_) => "not_found",
            Self::Other(_) => "other",
        }
    }

    /// 中文错误消息。
    pub fn message(&self) -> String {
        match self {
            Self::NoVault(msg) | Self::NotFound(msg) | Self::Other(msg) => msg.clone(),
            Self::Auth => "认证失败：主密码错误".to_string(),
            Self::Locked => "保险库处于锁定状态，请先解锁".to_string(),
        }
    }
}

/// GUI 会话。
pub struct Session {
    vault: ResolvedVault,
    /// 解锁后的主密钥；None 表示已锁定（drop 即清零）。
    key: Option<VaultKey>,
    /// 解锁后的正文（条目明文）；与密钥同生共死。
    body: Option<VaultBody>,
    /// 最近一次活动时刻（解锁、取用正文均刷新）。
    last_activity: Instant,
    /// 空闲超时时长（默认 5 分钟，可经环境变量覆盖）。
    idle_timeout: Duration,
}

impl Session {
    /// 新建锁定会话。
    pub fn new(vault: ResolvedVault, idle_timeout: Duration) -> Self {
        Self {
            vault,
            key: None,
            body: None,
            last_activity: Instant::now(),
            idle_timeout,
        }
    }

    /// 解锁：验证主密码、加载正文（含 schema 迁移），返回条目数量。
    ///
    /// KDF 自动升级失败不阻断解锁（与 CLI 同语义），仅向 stderr 警告。
    pub fn unlock(&mut self, password: &str) -> Result<usize, SessionError> {
        let path = &self.vault.path;
        if !path.is_file() {
            return Err(SessionError::NoVault(format!(
                "保险库文件不存在：{}（可先用 CLI 执行 2fa init 创建）",
                path.display()
            )));
        }
        let (key, outcome) = unlock(path, password).map_err(|e| match e {
            UnlockError::AuthFailed => SessionError::Auth,
            other => SessionError::Other(other.to_string()),
        })?;
        match outcome {
            UpgradeOutcome::NotNeeded => {}
            UpgradeOutcome::Upgraded => eprintln!("封套 KDF 已自动升级到当前版本"),
            UpgradeOutcome::Failed(err) => {
                eprintln!("警告：KDF 自动升级失败（不影响本次使用）：{err}")
            }
        }
        let (body, _) = load_and_migrate(path, &key)
            .map_err(|e| SessionError::Other(format!("加载保险库失败：{e}")))?;
        let count = body.entries.len();
        self.key = Some(key);
        self.body = Some(body);
        self.last_activity = Instant::now();
        Ok(count)
    }

    /// 立即锁定：主密钥与正文明文 drop 清零。返回是否确实发生了锁定。
    pub fn lock(&mut self) -> bool {
        let was_unlocked = self.key.is_some();
        self.key = None;
        self.body = None;
        was_unlocked
    }

    /// 取用正文（须已解锁）；取用即视为一次用户活动。
    pub fn require_unlocked(&mut self) -> Result<&VaultBody, SessionError> {
        if self.body.is_none() {
            return Err(SessionError::Locked);
        }
        self.last_activity = Instant::now();
        match self.body.as_ref() {
            Some(body) => Ok(body),
            None => Err(SessionError::Locked),
        }
    }

    /// 空闲超时检查（前端心跳定期调用）：已解锁且超过阈值则自动锁定。
    /// 返回是否因本次检查触发了锁定。
    pub fn check_idle(&mut self) -> bool {
        if self.key.is_some() && self.last_activity.elapsed() > self.idle_timeout {
            return self.lock();
        }
        false
    }

    /// 状态视图：路径与来源始终可见；条目数与 KDF 版本需解锁后提供。
    pub fn status(&self) -> Result<StatusView, SessionError> {
        let unlocked = self.key.is_some();
        Ok(StatusView {
            path: self.vault.path.display().to_string(),
            source: self.vault.source.label().to_string(),
            unlocked,
            entry_count: if unlocked {
                Some(self.body.as_ref().map_or(0, |b| b.entries.len()))
            } else {
                None
            },
            kdf_versions: if unlocked {
                Some(kdf_versions_text(&self.vault.path)?)
            } else {
                None
            },
        })
    }
}

/// 汇总封套 KDF 版本（去重升序、顿号分隔），顺带校验版本可解析。
fn kdf_versions_text(path: &Path) -> Result<String, SessionError> {
    let raw =
        std::fs::read(path).map_err(|e| SessionError::Other(format!("读取保险库文件失败：{e}")))?;
    let file =
        VaultFile::parse(&raw).map_err(|e| SessionError::Other(format!("保险库格式错误：{e}")))?;
    let mut versions: Vec<_> = file.envelopes.iter().map(|env| env.kdf_version).collect();
    versions.sort_unstable();
    versions.dedup();
    for v in &versions {
        if let Err(err) = kdf_params(*v) {
            return Err(SessionError::Other(format!(
                "封套 KDF 版本 {v} 无法解析：{err}"
            )));
        }
    }
    Ok(versions
        .iter()
        .map(|v| format!("v{v}"))
        .collect::<Vec<_>>()
        .join("、"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    use two_fa_core::domain::totp::{self, Algorithm};
    use two_fa_core::usecase::entries as core_entries;
    use two_fa_core::usecase::init;
    use two_fa_core::vault::{Entry, SecretKey, VaultBody, atomic_write, unlock};

    use crate::paths::VaultSource;

    /// 临时目录内创建测试保险库文件（空正文，主密码「测试主密码」）。
    fn temp_vault(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("2fa-app-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("vault.json");
        let bytes = init::create_vault("测试主密码", "RECOVERYCODE1234", 1_700_000_000).unwrap();
        atomic_write(&path, &bytes).unwrap();
        path
    }

    fn resolved(path: PathBuf) -> ResolvedVault {
        ResolvedVault {
            path,
            source: VaultSource::Platform,
        }
    }

    /// 错误密码映射为 auth；正确密码解锁成功并返回条目数。
    #[test]
    fn 解锁错误映射与成功() {
        let path = temp_vault("unlock");
        let mut s = Session::new(resolved(path), Duration::from_secs(300));

        let err = s.unlock("错误密码").unwrap_err();
        assert_eq!(err.kind(), "auth");
        assert_eq!(err.message(), "认证失败：主密码错误");
        assert!(!s.lock(), "失败解锁不改变锁定状态");

        assert_eq!(s.unlock("测试主密码").unwrap(), 0);
        assert!(s.status().unwrap().unlocked);
    }

    /// 保险库文件不存在：明确报错并给出路径（引导 init）。
    #[test]
    fn 保险库不存在() {
        let missing = std::env::temp_dir().join(format!("2fa-app-不存在-{}", std::process::id()));
        let mut s = Session::new(resolved(missing), Duration::from_secs(300));
        let err = s.unlock("任意密码").unwrap_err();
        assert_eq!(err.kind(), "no_vault");
        assert!(err.message().contains("不存在"));
    }

    /// lock 后密钥与正文清零，需重新解锁；重复 lock 无状态变化。
    #[test]
    fn lock后需重新解锁() {
        let path = temp_vault("lock");
        let mut s = Session::new(resolved(path), Duration::from_secs(300));
        s.unlock("测试主密码").unwrap();

        assert!(s.lock(), "已解锁时应发生锁定");
        assert_eq!(s.require_unlocked().unwrap_err().kind(), "locked");
        assert!(!s.lock(), "重复 lock 不再产生状态变化");

        assert_eq!(s.unlock("测试主密码").unwrap(), 0);
    }

    /// 空闲超时自动锁定；取用正文刷新活动时刻、重新计时（与 CLI 会话同语义）。
    #[test]
    fn 空闲超时自动锁定() {
        let path = temp_vault("idle");
        let mut s = Session::new(resolved(path), Duration::from_millis(30));
        s.unlock("测试主密码").unwrap();
        std::thread::sleep(Duration::from_millis(60));
        assert!(s.check_idle(), "超时应触发自动锁定");
        assert!(!s.check_idle(), "再次检查不重复触发");

        // 活动刷新：解锁后立即检查不触发
        let mut s2 = Session::new(resolved(temp_vault("idle2")), Duration::from_millis(30));
        s2.unlock("测试主密码").unwrap();
        assert!(!s2.check_idle(), "刚解锁不应触发");
        s2.require_unlocked().unwrap(); // 取用刷新活动时刻
        assert!(!s2.check_idle(), "取用后重新计时不应触发");
    }

    /// 状态视图：锁定时路径来源可见、条目数与 KDF 版本不可见；解锁后全部可见。
    #[test]
    fn 状态视图随解锁状态变化() {
        let path = temp_vault("status");
        let mut s = Session::new(resolved(path.clone()), Duration::from_secs(300));

        let st = s.status().unwrap();
        assert!(!st.unlocked);
        assert_eq!(st.entry_count, None);
        assert_eq!(st.kdf_versions, None);
        assert_eq!(st.source, "平台惯例");
        assert!(st.path.ends_with("vault.json"));

        s.unlock("测试主密码").unwrap();
        let st = s.status().unwrap();
        assert!(st.unlocked);
        assert_eq!(st.entry_count, Some(0));
        assert_eq!(st.kdf_versions.as_deref(), Some("v1"));
    }

    /// 解锁含条目的库，视图字段与 core 在同一 now 下的计算一致
    /// （校验 counter = floor(now / period) 的接线，算法正确性由 core 的 RFC 向量保证）。
    #[test]
    fn 条目视图与前缀定位() {
        let path = temp_vault("entries");
        // 先用 core 解锁取出主密钥，写入一条条目后重建会话
        let (key, _) = unlock(&path, "测试主密码").unwrap();
        let mut body = VaultBody::empty(1_700_000_000);
        body.entries.push(
            Entry::new(
                "GitHub".to_string(),
                "alice".to_string(),
                SecretKey::from_base32("JBSWY3DPEHPK3PXP").unwrap(),
                Algorithm::Sha1,
                6,
                30,
                vec!["工作".to_string()],
            )
            .unwrap(),
        );
        core_entries::save(&path, &key, &body).unwrap();

        let mut s = Session::new(resolved(path), Duration::from_secs(300));
        assert_eq!(s.unlock("测试主密码").unwrap(), 1);

        let now = 1_800_000_123u64;
        let body = s.require_unlocked().unwrap();
        let plen = core_entries::unique_prefix_len(body);
        let entry = &body.entries[0];
        let view = crate::commands::entry_view(entry, now, plen);

        assert_eq!(view.issuer, "GitHub");
        assert_eq!(view.account, "alice");
        assert_eq!(view.tags, vec!["工作".to_string()]);
        assert_eq!(view.algorithm, "SHA1");
        assert_eq!(view.id_prefix.len(), plen);
        assert_eq!(view.id_prefix, entry.id.to_string()[..plen]);

        // counter 接线：视图验证码 == core 同参数计算结果
        let expected = format!(
            "{:0width$}",
            totp::compute(
                &entry.secret.to_bytes().unwrap(),
                now / 30,
                Algorithm::Sha1,
                6
            )
            .unwrap(),
            width = 6
        );
        assert_eq!(view.code.as_deref(), Some(expected.as_str()));
        assert_eq!(view.remaining_secs, 30 - now % 30);
    }
}
