//! 时间步计数器换算（TOTP 时间语义 → HOTP 计数器）。
//!
//! 必须使用整数除法 `floor(unix / period)`；浮点会在大时间戳上精度丢失。

/// 默认时间步长（秒）。
pub const DEFAULT_PERIOD: u32 = 30;

/// 计数器换算错误。
#[derive(Debug, thiserror::Error)]
pub enum CounterError {
    /// 时间步长为 0，会导致除零。
    #[error("时间步长不能为 0")]
    ZeroPeriod,
    /// Unix 时间戳为负（1970 年之前），TOTP 语义未定义。
    #[error("Unix 时间戳不能为负数：{0}")]
    NegativeTimestamp(i64),
}

/// 把 Unix 时间戳换算为时间步计数器：`floor(unix / period)`，整数除法。
pub fn counter_at(unix_seconds: i64, period: u32) -> Result<u64, CounterError> {
    if period == 0 {
        return Err(CounterError::ZeroPeriod);
    }
    if unix_seconds < 0 {
        return Err(CounterError::NegativeTimestamp(unix_seconds));
    }
    Ok(unix_seconds as u64 / u64::from(period))
}

/// 当前时间步剩余秒数：`period - (unix mod period)`。
///
/// 时间戳恰好落在周期边界时剩余为整个周期（新周期刚开始）。
pub fn remaining_seconds(unix_seconds: i64, period: u32) -> Result<u32, CounterError> {
    if period == 0 {
        return Err(CounterError::ZeroPeriod);
    }
    if unix_seconds < 0 {
        return Err(CounterError::NegativeTimestamp(unix_seconds));
    }
    Ok(period - (unix_seconds as u64 % u64::from(period)) as u32)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// 时间戳恰好落在周期边界：0/30/60 归入下一个计数器，剩余秒数为整周期。
    #[test]
    fn 周期边界取整() {
        assert_eq!(counter_at(0, 30).unwrap(), 0);
        assert_eq!(counter_at(29, 30).unwrap(), 0);
        assert_eq!(counter_at(30, 30).unwrap(), 1);
        assert_eq!(counter_at(31, 30).unwrap(), 1);
        assert_eq!(remaining_seconds(0, 30).unwrap(), 30);
        assert_eq!(remaining_seconds(29, 30).unwrap(), 1);
        assert_eq!(remaining_seconds(30, 30).unwrap(), 30);
    }

    /// 不同时间步长下的取整。
    #[test]
    fn 不同时间步长() {
        for (unix, period, expected) in [(60i64, 30u32, 2u64), (59, 30, 1), (60, 60, 1), (59, 60, 0), (45, 15, 3)] {
            assert_eq!(counter_at(unix, period).unwrap(), expected, "unix={unix} period={period}");
        }
        // RFC 6238 测试时间点对应的计数器
        assert_eq!(counter_at(1111111109, 30).unwrap(), 37037036);
        assert_eq!(counter_at(20000000000, 30).unwrap(), 666666666);
    }

    /// 超大时间戳不溢出（整数除法无精度损失）。
    #[test]
    fn 超大时间戳() {
        assert_eq!(counter_at(i64::MAX, 30).unwrap(), (i64::MAX as u64) / 30);
        assert!(remaining_seconds(i64::MAX, 30).is_ok());
    }

    /// 负数时间戳报错。
    #[test]
    fn 负数时间戳报错() {
        assert!(matches!(
            counter_at(-1, 30),
            Err(CounterError::NegativeTimestamp(-1))
        ));
        assert!(remaining_seconds(-1, 30).is_err());
    }

    /// 时间步长为 0 报错（防除零）。
    #[test]
    fn 零时间步长报错() {
        assert!(matches!(counter_at(100, 0), Err(CounterError::ZeroPeriod)));
        assert!(remaining_seconds(100, 0).is_err());
    }
}
