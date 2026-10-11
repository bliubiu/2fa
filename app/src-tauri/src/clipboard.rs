//! 剪贴板验证码清除器：复制验证码后延迟自动清除。
//!
//! 安全语义（PRD §10.2 / 实施计划 M8-4）：
//! - 复制后 30 秒自动清除，但**仅当剪贴板内容仍是该验证码**——避免误清用户
//!   后续复制的内容
//! - 锁定动作取消未决的清除计时并立即清除（同样仅当内容仍是验证码）
//! - 再次复制会作废上一次的未决计时（按代数判定）
//!
//! 清除时机判定在 [`ClipboardOps`] 抽象之后，系统剪贴板（arboard）仅是默认
//! 实现；单元测试注入内存 fake，不依赖真实剪贴板，CI 无显示环境可跑。

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// 剪贴板读写抽象。
pub trait ClipboardOps: Send + Sync + 'static {
    fn set_text(&self, text: &str) -> Result<(), String>;
    fn get_text(&self) -> Result<String, String>;
}

/// 系统剪贴板（arboard 封装，错误文本转中文）。
struct SystemClipboard;

impl ClipboardOps for SystemClipboard {
    fn set_text(&self, text: &str) -> Result<(), String> {
        arboard::Clipboard::new()
            .and_then(|mut c| c.set_text(text))
            .map_err(|e| format!("写入剪贴板失败：{e}"))
    }

    fn get_text(&self) -> Result<String, String> {
        arboard::Clipboard::new()
            .and_then(|mut c| c.get_text())
            .map_err(|e| format!("读取剪贴板失败：{e}"))
    }
}

/// 剪贴板清除器。内部代数（generation）判定未决计时的有效性：
/// 每次「新复制」或「锁定」都使旧计时作废。
pub struct ClipboardCleaner {
    ops: Arc<dyn ClipboardOps>,
    /// 当前代数；计时器到期时代数不一致即作废。
    /// （Rust 2024 中 `gen` 是保留关键字，故用全称 `generation`。）
    generation: Arc<AtomicU64>,
    /// 最近复制的验证码（锁定时的立即清除依据）。
    copied: Mutex<Option<String>>,
    /// 延迟等待实现：生产用真实睡眠；测试注入可控时钟（阻塞到测试放行），
    /// 使「到期前后」的断言与时钟抖动无关——睡眠窗口在并行负载下会漂移，
    /// 真实睡眠是本模块测试历史上唯一的偶发失败源。
    wait: Waiter,
}

/// 延迟等待函数类型：参数为延迟时长与本代复制（generation），测试时钟
/// 借助 generation 把放行句柄与具体的复制一一对应（worker 注册顺序不保证）。
type Waiter = Arc<dyn Fn(Duration, u64) + Send + Sync>;

impl ClipboardCleaner {
    /// 使用系统剪贴板的默认构造。
    pub fn system() -> Self {
        Self::with_ops(Arc::new(SystemClipboard))
    }

    /// 注入剪贴板实现（测试用，等待仍为真实睡眠）。
    pub fn with_ops(ops: Arc<dyn ClipboardOps>) -> Self {
        Self::with_ops_and_waiter(ops, Arc::new(|d: Duration, _gen: u64| thread::sleep(d)))
    }

    /// 同时注入剪贴板实现与延迟等待（测试用）。
    pub fn with_ops_and_waiter(ops: Arc<dyn ClipboardOps>, wait: Waiter) -> Self {
        Self {
            ops,
            generation: Arc::new(AtomicU64::new(0)),
            copied: Mutex::new(None),
            wait,
        }
    }

    /// 复制验证码并安排延迟清除。复制失败（无剪贴板/被占用）返回中文错误。
    pub fn copy_code(&self, code: &str, delay: Duration) -> Result<(), String> {
        self.ops.set_text(code)?;
        *self.copied.lock().map_err(|_| "内部状态异常".to_string())? = Some(code.to_string());
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let ops = Arc::clone(&self.ops);
        let flag = Arc::clone(&self.generation);
        let wait = Arc::clone(&self.wait);
        let code = code.to_string();
        // 后台线程延迟清除：代数一致且剪贴板内容仍是该验证码才清除
        thread::spawn(move || {
            wait(delay, generation);
            if flag.load(Ordering::SeqCst) != generation {
                return; // 已被新复制或锁定作废
            }
            if ops.get_text().is_ok_and(|t| t == code) {
                let _ = ops.set_text(""); // 清除失败属尽力而为
            }
        });
        Ok(())
    }

    /// 锁定时调用：作废全部未决计时，并立即清除仍残留的验证码。
    pub fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        let copied = self.copied.lock().map(|mut c| c.take()).unwrap_or_default();
        if let Some(code) = copied {
            if self.ops.get_text().is_ok_and(|t| t == code) {
                let _ = self.ops.set_text("");
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use std::sync::mpsc;

    /// 内存假剪贴板：记录当前文本（None 表示已清空）。
    struct FakeClipboard(StdMutex<Option<String>>);

    impl ClipboardOps for FakeClipboard {
        fn set_text(&self, text: &str) -> Result<(), String> {
            *self.0.lock().unwrap() = Some(text.to_string());
            Ok(())
        }

        fn get_text(&self) -> Result<String, String> {
            Ok(self.0.lock().unwrap().clone().unwrap_or_default())
        }
    }

    /// 测试门控句柄表：generation → 放行发送端。
    type Gates = Arc<StdMutex<Vec<(u64, mpsc::Sender<()>)>>>;

    fn text_of(clip: &FakeClipboard) -> String {
        clip.0.lock().unwrap().clone().unwrap_or_default()
    }

    /// 可控时钟：worker 在放行点完全阻塞，测试显式放行后推进。每次等待调用
    /// 按其 generation 注册放行句柄，使「到期前 / 到期后」的断言与线程启动
    /// 顺序、时钟抖动完全无关。
    fn gated_clock() -> (Arc<dyn Fn(Duration, u64) + Send + Sync>, Gates) {
        let gates: Gates = Arc::new(StdMutex::new(Vec::new()));
        let reg = Arc::clone(&gates);
        let clock = Arc::new(move |_delay: Duration, generation: u64| {
            let (tx, rx) = mpsc::channel::<()>();
            reg.lock().unwrap().push((generation, tx));
            let _ = rx.recv(); // 阻塞直到测试放行
        }) as Arc<dyn Fn(Duration, u64) + Send + Sync>;
        (clock, gates)
    }

    /// 构造注入可控时钟的清除器。
    fn gated() -> (ClipboardCleaner, Arc<FakeClipboard>, Gates) {
        let clip = Arc::new(FakeClipboard(StdMutex::new(None)));
        let (clock, gates) = gated_clock();
        let cleaner = ClipboardCleaner::with_ops_and_waiter(
            Arc::clone(&clip) as Arc<dyn ClipboardOps>,
            clock,
        );
        (cleaner, clip, gates)
    }

    /// 放行指定 generation 的未决计时（先轮询等 worker 完成注册，至多 2 秒：
    /// 只容忍「更晚」的注册，不存在「更早」的放行）。
    fn release(gates: &Gates, generation: u64) {
        for _ in 0..2000 {
            if gates.lock().unwrap().iter().any(|(g, _)| *g == generation) {
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        gates
            .lock()
            .unwrap()
            .iter()
            .find(|(g, _)| *g == generation)
            .expect("放行句柄应在 deadline 内注册")
            .1
            .send(())
            .unwrap();
    }

    /// 轮询直到剪贴板内容变为期望值（deadline 2 秒；worker 放行后清除只差
    /// 几条指令，此轮询只容忍「更晚」而不存在「更早」的失败方向）。
    fn wait_text(clip: &FakeClipboard, want: &str) -> bool {
        for _ in 0..2000 {
            if text_of(clip) == want {
                return true;
            }
            thread::sleep(Duration::from_millis(1));
        }
        text_of(clip) == want
    }

    /// 复制后延迟到期、内容未被替换：剪贴板被清空。
    #[test]
    fn 到期清除() {
        let (cleaner, clip, gates) = gated();
        cleaner.copy_code("123456", Duration::ZERO).unwrap();
        assert_eq!(text_of(&clip), "123456");
        // 未放行即未到期：验证码仍在（与时钟抖动无关）
        assert_eq!(text_of(&clip), "123456");

        release(&gates, 1);
        assert!(wait_text(&clip, ""), "放行（延迟到期）后应清空验证码");
    }

    /// 到期前用户复制了其他内容：不误清。
    #[test]
    fn 内容被替换后不误清() {
        let (cleaner, clip, gates) = gated();
        cleaner.copy_code("123456", Duration::ZERO).unwrap();
        clip.set_text("用户复制的新内容").unwrap();

        release(&gates, 1);
        assert!(
            wait_text(&clip, "用户复制的新内容"),
            "到期时内容已被替换，不得清除"
        );
    }

    /// 再次复制作废上一次计时：旧验证码到期后不得清除新验证码，
    /// 新验证码在其到期后被清除（按 generation 显式放行，无顺序竞态）。
    #[test]
    fn 二次复制作废旧计时() {
        let (cleaner, clip, gates) = gated();
        cleaner.copy_code("111111", Duration::ZERO).unwrap();
        cleaner.copy_code("222222", Duration::ZERO).unwrap();
        assert_eq!(text_of(&clip), "222222");

        release(&gates, 1); // 旧计时（generation 1）到期：代数已变
        assert!(wait_text(&clip, "222222"), "旧计时不应清除新验证码");

        release(&gates, 2); // 新计时（generation 2）到期：代数一致
        assert!(wait_text(&clip, ""), "新验证码应在其到期后被清除");
    }

    /// 锁定（invalidate）：立即清除残留验证码，且未决计时作废。
    #[test]
    fn 锁定立即清除并作废计时() {
        let (cleaner, clip, gates) = gated();
        cleaner.copy_code("123456", Duration::ZERO).unwrap();

        cleaner.invalidate();
        assert_eq!(text_of(&clip), "", "锁定应立即清除验证码");

        clip.set_text("锁定后复制的内容").unwrap();
        release(&gates, 1); // 已作废的计时到期
        assert!(
            wait_text(&clip, "锁定后复制的内容"),
            "作废的计时不得误清锁定后的新内容"
        );
    }
}
