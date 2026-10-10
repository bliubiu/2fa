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
}

impl ClipboardCleaner {
    /// 使用系统剪贴板的默认构造。
    pub fn system() -> Self {
        Self::with_ops(Arc::new(SystemClipboard))
    }

    /// 注入剪贴板实现（测试用）。
    pub fn with_ops(ops: Arc<dyn ClipboardOps>) -> Self {
        Self {
            ops,
            generation: Arc::new(AtomicU64::new(0)),
            copied: Mutex::new(None),
        }
    }

    /// 复制验证码并安排延迟清除。复制失败（无剪贴板/被占用）返回中文错误。
    pub fn copy_code(&self, code: &str, delay: Duration) -> Result<(), String> {
        self.ops.set_text(code)?;
        *self.copied.lock().map_err(|_| "内部状态异常".to_string())? = Some(code.to_string());
        let generation = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let ops = Arc::clone(&self.ops);
        let flag = Arc::clone(&self.generation);
        let code = code.to_string();
        // 后台线程延迟清除：代数一致且剪贴板内容仍是该验证码才清除
        thread::spawn(move || {
            thread::sleep(delay);
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

    fn fake() -> (ClipboardCleaner, Arc<FakeClipboard>) {
        let clip = Arc::new(FakeClipboard(StdMutex::new(None)));
        let cleaner = ClipboardCleaner::with_ops(Arc::clone(&clip) as Arc<dyn ClipboardOps>);
        (cleaner, clip)
    }

    fn text_of(clip: &FakeClipboard) -> String {
        clip.0.lock().unwrap().clone().unwrap_or_default()
    }

    /// 复制后延迟到期、内容未被替换：剪贴板被清空。
    #[test]
    fn 到期清除() {
        let (cleaner, clip) = fake();
        cleaner
            .copy_code("123456", Duration::from_millis(20))
            .unwrap();
        assert_eq!(text_of(&clip), "123456");

        thread::sleep(Duration::from_millis(60));
        assert_eq!(text_of(&clip), "", "到期后应清空验证码");
    }

    /// 到期前用户复制了其他内容：不误清。
    #[test]
    fn 内容被替换后不误清() {
        let (cleaner, clip) = fake();
        cleaner
            .copy_code("123456", Duration::from_millis(20))
            .unwrap();
        clip.set_text("用户复制的新内容").unwrap();

        thread::sleep(Duration::from_millis(60));
        assert_eq!(text_of(&clip), "用户复制的新内容");
    }

    /// 再次复制作废上一次计时：旧验证码到期后仍在（已被新验证码覆盖）。
    #[test]
    fn 二次复制作废旧计时() {
        let (cleaner, clip) = fake();
        cleaner
            .copy_code("111111", Duration::from_millis(20))
            .unwrap();
        thread::sleep(Duration::from_millis(5));
        cleaner
            .copy_code("222222", Duration::from_millis(80))
            .unwrap();

        thread::sleep(Duration::from_millis(40)); // 第一次计时已过期
        assert_eq!(text_of(&clip), "222222", "旧计时不应清除新验证码");

        thread::sleep(Duration::from_millis(60)); // 第二次计时到期
        assert_eq!(text_of(&clip), "", "新验证码应在其到期后被清除");
    }

    /// 锁定（invalidate）：立即清除残留验证码，且未决计时作废。
    #[test]
    fn 锁定立即清除并作废计时() {
        let (cleaner, clip) = fake();
        cleaner
            .copy_code("123456", Duration::from_millis(30))
            .unwrap();

        cleaner.invalidate();
        assert_eq!(text_of(&clip), "", "锁定应立即清除验证码");

        clip.set_text("锁定后复制的内容").unwrap();
        thread::sleep(Duration::from_millis(60));
        assert_eq!(
            text_of(&clip),
            "锁定后复制的内容",
            "作废的计时不得误清锁定后的新内容"
        );
    }
}
