//! REPL 会话状态机：锁定 / 解锁 / 空闲超时。
//!
//! 会话持有的 [`VaultKey`] 是解锁后的对称密钥：
//! - `lock` 或空闲超时即 `drop`，`Zeroizing` 保证字节清零
//! - 进程任何形式的退出（正常 / Ctrl-C / panic 展开）都经过 `Drop`，无条件归零
//!
//! 本模块只管状态与计时，不含任何 IO，可完整单元测试。

use std::time::{Duration, Instant};

use two_fa_core::vault::VaultKey;

/// 交互会话。
pub struct Session {
    /// 解锁后的主密钥；`None` 表示已锁定。
    key: Option<VaultKey>,
    /// 最近一次活动时刻（解锁、取用密钥均刷新）。
    last_activity: Instant,
    /// 空闲超时时长。
    idle_timeout: Duration,
}

impl Session {
    /// 新建锁定会话。
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            key: None,
            last_activity: Instant::now(),
            idle_timeout,
        }
    }

    /// 是否处于解锁状态。
    pub fn is_unlocked(&self) -> bool {
        self.key.is_some()
    }

    /// 解锁：持有主密钥并刷新活动时间。
    pub fn unlock(&mut self, key: VaultKey) {
        self.key = Some(key);
        self.last_activity = Instant::now();
    }

    /// 取用主密钥（刷新活动时间）。
    // M3-4 的条目命令将取用密钥；当前 REPL 尚未消费
    #[allow(dead_code)]
    pub fn key(&mut self) -> Option<&VaultKey> {
        if self.key.is_some() {
            self.last_activity = Instant::now();
        }
        self.key.as_ref()
    }

    /// 立即锁定：主密钥 `drop` 清零。返回是否确实发生了锁定。
    pub fn lock(&mut self) -> bool {
        if self.key.take().is_some() {
            self.last_activity = Instant::now();
            true
        } else {
            false
        }
    }

    /// 检查空闲超时：已解锁且超过阈值则自动锁定。
    /// 返回是否因本次检查触发了锁定（供上层提示）。
    pub fn check_idle(&mut self) -> bool {
        if self.key.is_some() && self.last_activity.elapsed() > self.idle_timeout {
            return self.lock();
        }
        false
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// 初始为锁定状态。
    #[test]
    fn 初始锁定() {
        let mut session = Session::new(Duration::from_secs(300));
        assert!(!session.is_unlocked());
        assert!(session.key().is_none());
    }

    /// 解锁后持有密钥，lock 后归零且需重新解锁。
    #[test]
    fn lock后需重新解锁() {
        let mut session = Session::new(Duration::from_secs(300));
        session.unlock(VaultKey::generate().unwrap());
        assert!(session.is_unlocked());
        assert!(session.key().is_some());

        assert!(session.lock(), "已解锁时应发生锁定");
        assert!(!session.is_unlocked());
        assert!(session.key().is_none());
        assert!(!session.lock(), "重复 lock 不再产生状态变化");
    }

    /// 空闲超时自动锁定；活动后重新计时。
    #[test]
    fn 空闲超时自动锁定() {
        let mut session = Session::new(Duration::from_millis(20));
        session.unlock(VaultKey::generate().unwrap());
        assert!(session.key().is_some());

        std::thread::sleep(Duration::from_millis(50));
        assert!(session.check_idle(), "超时应触发自动锁定");
        assert!(!session.is_unlocked());

        // 再次检查不重复触发
        assert!(!session.check_idle());
    }

    /// 未超时不会误锁定。
    #[test]
    fn 未超时不锁定() {
        let mut session = Session::new(Duration::from_secs(300));
        session.unlock(VaultKey::generate().unwrap());
        assert!(!session.check_idle());
        assert!(session.is_unlocked());
    }

    /// 取用密钥刷新活动时间（计时基准跟随真实使用）。
    #[test]
    fn 取用密钥刷新活动时间() {
        let mut session = Session::new(Duration::from_millis(30));
        session.unlock(VaultKey::generate().unwrap());
        std::thread::sleep(Duration::from_millis(20));
        assert!(session.key().is_some(), "取用即刷新");
        std::thread::sleep(Duration::from_millis(20));
        assert!(!session.check_idle(), "刷新后 20ms 不应超时");
    }
}
