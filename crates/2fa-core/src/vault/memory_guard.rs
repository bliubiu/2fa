//! 内存保护（尽力而为，见 `docs/adr/0005`）。
//!
//! 当前实现全程无 `unsafe`：不调用 `mlockall` / `VirtualLock`，
//! 密钥字节**可能**被操作系统换出到交换区/页面文件。该风险已被接受，缓解措施：
//! - 全部密钥类型经 `zeroize::Zeroizing` 包装，用后即清（`Drop` 零化）
//! - 密钥类型禁止 `Clone`/`Copy`，不存在零化覆盖不到的副本（人工审查保证）
//! - `Debug` 在类型层面固定输出 `«已隐藏»`，密钥不可经日志路径落盘
//!
//! 本函数是上层启动流程的接入点：未来若引入带 `unsafe` 隔离层的平台 crate，
//! 只需替换本函数实现，调用方语义不变——**失败只警告，绝不因此中断**。

/// 内存锁启用状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryLockStatus {
    /// 当前构建不支持内存锁（未启用平台 FFI），调用方应向 stderr 输出中文警告后继续。
    Unsupported,
}

/// 尽力而为地启用内存锁；失败不构成错误，调用方输出警告后照常运行。
pub fn try_lock_memory() -> MemoryLockStatus {
    MemoryLockStatus::Unsupported
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// 受限环境（无锁页能力）下启动仍可用：调用不 panic 且语义明确。
    #[test]
    fn 受限环境仍可用() {
        assert_eq!(try_lock_memory(), MemoryLockStatus::Unsupported);
    }

    /// 状态类型可安全打印（供日志使用，不含任何敏感内容）。
    #[test]
    fn 状态可安全打印() {
        let text = format!("{:?}", try_lock_memory());
        assert!(text.contains("Unsupported"));
    }
}
