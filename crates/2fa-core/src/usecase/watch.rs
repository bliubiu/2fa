//! watch 倒计时调度：对齐周期边界、吸收唤醒误差。
//!
//! 全部时间量由调用方传入（core 不读时钟）；时刻以「单调毫秒」为基准，
//! 调用方用 `Instant::elapsed()` 之类的单调时钟换算。
//!
//! 防漂移的关键：每次刷新点都是「上一次刷新点 + 周期」的固定增量推进，
//! 而不是「当前时刻 + 周期」重新计算——单次唤醒的迟到误差被吸收，
//! 不会累积到后续周期。

/// 倒计时调度器。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticker {
    /// 刷新周期（毫秒）。
    period_ms: u64,
    /// 下一次刷新时刻（单调毫秒）。
    next_ms: u64,
}

impl Ticker {
    /// 新建调度器：从单调时刻 `now_monotonic_ms` 起步，
    /// 先等待 `wait_ms`（毫秒，通常来自 [`secs_to_boundary`] 换算）再首次刷新。
    pub fn start(now_monotonic_ms: u64, wait_ms: u64, period_secs: u32) -> Self {
        Self {
            period_ms: u64::from(period_secs) * 1000,
            next_ms: now_monotonic_ms.saturating_add(wait_ms),
        }
    }

    /// 距离下一次刷新还需等待的毫秒数（已过点则返回 0，立即刷新）。
    pub fn wait_ms(&self, now_monotonic_ms: u64) -> u64 {
        self.next_ms.saturating_sub(now_monotonic_ms)
    }

    /// 推进到再下一个刷新点（固定增量，不参考当前时刻）。
    ///
    /// 若唤醒迟到（当前时刻已越过推进后的点），下轮 `wait_ms` 返回 0，
    /// 立即补刷并继续按增量追赶，漂移不会累积。
    pub fn advance(&mut self) {
        self.next_ms += self.period_ms;
    }
}

/// 距离下一个周期边界（Unix 秒）的等待时长。
///
/// 恰好在边界上时返回完整周期（下一个边界），保证至少等待 1 秒；
/// 与剩余秒数的语义一致（边界上验证码刚切换，无需立即刷新）。
pub fn secs_to_boundary(now_unix: u64, period_secs: u32) -> u64 {
    let period = u64::from(period_secs);
    let rem = now_unix % period;
    if rem == 0 { period } else { period - rem }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 边界等待：边界上返回整周期，周期中点返回半周期。
    #[test]
    fn 边界等待秒数() {
        assert_eq!(secs_to_boundary(60, 30), 30, "恰在边界：等下一个周期");
        assert_eq!(secs_to_boundary(45, 30), 15, "周期中点：等半周期");
        assert_eq!(secs_to_boundary(61, 30), 29);
        assert_eq!(secs_to_boundary(0, 30), 30);
    }

    /// 连续 3 个周期：每次唤醒都带 13ms 迟到误差，
    /// 固定增量调度使刷新点始终对齐理论边界，无漂移累积。
    #[test]
    fn 三周期无漂移累积() {
        const PERIOD: u32 = 30;
        const ERR_MS: u64 = 13;

        // 单调时钟与 Unix 墙钟分别推进：墙钟 = 起点墙钟 + 单调经过的秒
        let start_mono_ms: u64 = 5_000;
        let start_unix: u64 = 1_700_000_005; // 与单调起点对应的墙钟（% 30 = 25）
        let mut ticker = Ticker::start(
            start_mono_ms,
            secs_to_boundary(start_unix, PERIOD) * 1000,
            PERIOD,
        );

        let mut mono_ms = start_mono_ms;
        let mut refresh_unix = Vec::new();
        for _ in 0..3 {
            mono_ms += ticker.wait_ms(mono_ms); // 睡到计划刷新点
            let unix = start_unix + (mono_ms - start_mono_ms) / 1000;
            // 刷新点必须恰好落在周期边界上
            assert_eq!(unix % u64::from(PERIOD), 0, "刷新点应对齐边界：{unix}");
            refresh_unix.push(unix);
            ticker.advance();
            mono_ms += ERR_MS; // 模拟唤醒与渲染的固定迟到
        }

        // 相邻刷新点间隔恰好一个周期（理论边界间隔）
        assert_eq!(refresh_unix[1] - refresh_unix[0], u64::from(PERIOD));
        assert_eq!(refresh_unix[2] - refresh_unix[1], u64::from(PERIOD));
        // 全部对齐到同一相位
        assert_eq!(refresh_unix[0] % 30, 0);
    }

    /// 迟到唤醒（越过推进后的刷新点）时下轮立即补刷，不丢失节拍。
    #[test]
    fn 迟到唤醒立即补刷() {
        let mut ticker = Ticker::start(0, 1_000, 5);
        // 第一次刷新点在 1000ms
        assert_eq!(ticker.wait_ms(999), 1);
        ticker.advance(); // 计划点推进到 6000ms（周期 5s）
        // 假设进程被挂起 10 秒：醒来时已远超 6000ms
        assert_eq!(ticker.wait_ms(10_000), 0, "已越过计划点：立即刷新");
        ticker.advance(); // 推进到 11000ms
        // 10000ms 距 11000ms 还有 1 秒等待——追赶后续节拍
        assert_eq!(ticker.wait_ms(10_000), 1_000);
    }

    /// 起步时刻在等待期之后越过（饱和语义不 panic）。
    #[test]
    fn 等待时长饱和不为负() {
        let ticker = Ticker::start(2_000, 1_000, 30);
        assert_eq!(ticker.wait_ms(5_000), 0);
    }
}
