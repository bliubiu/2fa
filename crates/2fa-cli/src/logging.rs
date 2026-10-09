//! 日志系统：默认仅写 stderr（不落盘），`--log-to-file` 显式开启后
//! 写入平台日志目录，按日轮转、保留 7 天。
//!
//! 格式（`docs/00-项目文档格式.md`）：
//! `[YYYY-MM-DD HH:MM:SS.SSS] [级别] [进程ID] [模块:行号] - 内容`
//!
//! 脱敏纪律（硬性规则）：OTP 密钥、主密码、恢复码、保险库正文、完整
//! `otpauth://` URI 一律禁止记录，任何级别都不例外——调用点只记录
//! 操作行为与实体名（服务商 / 账号），凭据从不进入日志参数。

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use chrono::{DateTime, Local, NaiveDate};
use log::{LevelFilter, Log, Metadata, Record};

/// 日志文件名前缀：`2fa-YYYYMMDD.log`。
const FILE_PREFIX: &str = "2fa-";
/// 日志文件名后缀。
const FILE_SUFFIX: &str = ".log";
/// 日志保留天数：超过即视为过期（`2fa logs purge` 与自动清理同口径）。
pub const RETAIN_DAYS: i64 = 7;

/// 解析日志级别文本（大小写不敏感，仅规范三级 DEBUG / INFO / ERROR）。
pub fn parse_level(text: &str) -> Option<LevelFilter> {
    match text.to_ascii_lowercase().as_str() {
        "debug" => Some(LevelFilter::Debug),
        "info" => Some(LevelFilter::Info),
        "error" => Some(LevelFilter::Error),
        _ => None,
    }
}

/// 平台日志目录（`docs/00-项目文档格式.md`）：
/// Windows `%LOCALAPPDATA%\2fa\logs`；Unix `$XDG_STATE_HOME/2fa/logs`，
/// 未设置时回退 `~/.local/state/2fa/logs`。
///
/// 所需环境变量全部缺失时返回 `None`（core 不读环境变量，采集归 CLI）。
pub fn platform_log_dir(
    localappdata: Option<&str>,
    xdg_state: Option<&str>,
    home: Option<&str>,
) -> Option<PathBuf> {
    #[cfg(windows)]
    {
        let _ = (xdg_state, home);
        localappdata.map(|root| Path::new(root).join("2fa").join("logs"))
    }
    #[cfg(not(windows))]
    {
        let _ = localappdata;
        if let Some(state) = xdg_state {
            return Some(Path::new(state).join("2fa").join("logs"));
        }
        home.map(|h| {
            Path::new(h)
                .join(".local")
                .join("state")
                .join("2fa")
                .join("logs")
        })
    }
}

/// 当天日期文本（`YYYYMMDD`，用于文件名）。
fn date_text(now: &DateTime<Local>) -> String {
    now.format("%Y%m%d").to_string()
}

/// 从日志文件名解析日期部分；不符合 `2fa-YYYYMMDD.log` 命名的返回 `None`。
fn parse_file_date(name: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(
        name.strip_prefix(FILE_PREFIX)?.strip_suffix(FILE_SUFFIX)?,
        "%Y%m%d",
    )
    .ok()
}

/// 文件输出目标：按写入时刻的日期懒打开当日文件，日期变化自动轮转。
struct FileTarget {
    /// 平台日志目录。
    dir: PathBuf,
    /// 当前打开的（日期, 文件句柄）。
    current: Mutex<Option<(String, File)>>,
}

impl FileTarget {
    /// 写入一行；文件打开失败时放弃文件输出（只保留 stderr），不中断主流程。
    fn write_line(&self, now: &DateTime<Local>, line: &str) {
        let mut guard = match self.current.lock() {
            Ok(guard) => guard,
            // 持锁线程曾 panic：接管内部状态继续写，日志不阻断主流程
            Err(poisoned) => poisoned.into_inner(),
        };
        let date = date_text(now);
        let needs_reopen = match guard.as_ref() {
            Some((open_date, _)) => *open_date != date,
            None => true,
        };
        if needs_reopen {
            // 目录在 init 时已创建；被外部删除则尽力重建，失败放弃本轮
            let _ = fs::create_dir_all(&self.dir);
            match OpenOptions::new()
                .create(true)
                .append(true)
                .open(self.dir.join(format!("{FILE_PREFIX}{date}{FILE_SUFFIX}")))
            {
                Ok(file) => *guard = Some((date, file)),
                Err(_) => {
                    *guard = None;
                    return;
                }
            }
        }
        if let Some((_, file)) = guard.as_mut() {
            let _ = writeln!(file, "{line}");
        }
    }
}

/// 应用日志器：stderr 为主通道，文件为可选辅助通道。
struct TwoFaLogger {
    /// 生效级别（init 时确定，不依赖全局 max_level，便于直接构造测试）。
    max_level: LevelFilter,
    /// 文件输出目标；`None` 表示不落盘。
    file: Option<FileTarget>,
}

impl Log for TwoFaLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.max_level
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let now = Local::now();
        let line = format!(
            "[{}] [{}] [{}] [{}:{}] - {}",
            now.format("%Y-%m-%d %H:%M:%S%.3f"),
            record.level(),
            std::process::id(),
            record.module_path().unwrap_or("未知模块"),
            record.line().unwrap_or(0),
            record.args()
        );
        let _ = writeln!(std::io::stderr(), "{line}");
        if let Some(target) = &self.file {
            target.write_line(&now, &line);
        }
    }

    fn flush(&self) {}
}

/// 初始化全局日志器。
///
/// `level` 为生效级别；`to_file` 为真时额外写入 `dir`（自动创建目录，
/// 目录无法创建时返回错误且不改变默认输出）。
pub fn init(level: LevelFilter, to_file: bool, dir: Option<PathBuf>) -> Result<(), String> {
    let file = if to_file {
        let dir = dir.ok_or_else(|| {
            "无法确定平台日志目录（缺少 LOCALAPPDATA / XDG_STATE_HOME / HOME 环境变量）".to_string()
        })?;
        fs::create_dir_all(&dir).map_err(|e| format!("创建日志目录失败：{e}"))?;
        Some(FileTarget {
            dir,
            current: Mutex::new(None),
        })
    } else {
        None
    };
    // 全局日志器只能设置一次；重复 init（仅测试可能）保留首个
    let _ = log::set_boxed_logger(Box::new(TwoFaLogger {
        max_level: level,
        file,
    }));
    log::set_max_level(level);
    Ok(())
}

/// 清理日志目录中超过保留期（[`RETAIN_DAYS`] 天）的日志文件，返回删除数量。
///
/// 只删除符合 `2fa-YYYYMMDD.log` 命名的文件，目录内其他文件一概不动。
pub fn purge_expired(dir: &Path, today: NaiveDate) -> std::io::Result<usize> {
    let mut removed = 0;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(date) = name.to_str().and_then(parse_file_date) else {
            continue;
        };
        if (today - date).num_days() > RETAIN_DAYS && fs::remove_file(entry.path()).is_ok() {
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use log::Level;

    fn temp_dir(tag: &str) -> PathBuf {
        let base = std::env::temp_dir().join(format!("2fa-log-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        base
    }

    /// 构造一条 INFO 级日志记录并写入 logger（Record 与 format_args! 临时值
    /// 必须同语句存活，因此封装为单次调用而非返回 Record）。
    fn log_info(logger: &TwoFaLogger, message: &str) {
        logger.log(
            &Record::builder()
                .args(format_args!("{message}"))
                .level(Level::Info)
                .module_path(Some("two_fa_cli::test"))
                .line(Some(42))
                .build(),
        );
    }

    /// 级别解析：大小写不敏感，仅规范三级，非法值拒绝。
    #[test]
    fn 级别解析() {
        assert_eq!(parse_level("DEBUG"), Some(LevelFilter::Debug));
        assert_eq!(parse_level("Info"), Some(LevelFilter::Info));
        assert_eq!(parse_level("error"), Some(LevelFilter::Error));
        assert_eq!(parse_level("warn"), None);
        assert_eq!(parse_level(""), None);
    }

    /// 平台目录解析（按当前平台取对应环境变量）。
    #[cfg(windows)]
    #[test]
    fn 平台目录解析() {
        let dir = platform_log_dir(Some(r"D:\state"), None, None).unwrap();
        assert_eq!(dir, Path::new(r"D:\state").join("2fa").join("logs"));
        assert!(platform_log_dir(None, Some("/x"), Some("/h")).is_none());
    }

    #[cfg(not(windows))]
    #[test]
    fn 平台目录解析() {
        assert_eq!(
            platform_log_dir(None, Some("/x/state"), None).unwrap(),
            Path::new("/x/state").join("2fa").join("logs")
        );
        assert_eq!(
            platform_log_dir(None, None, Some("/home/u")).unwrap(),
            Path::new("/home/u/.local/state/2fa/logs")
        );
        assert!(platform_log_dir(None, None, None).is_none());
    }

    /// 完整链路：`Log::log` 产出的行含级别、进程、模块与行号，并同步落盘。
    #[test]
    fn 文件输出格式合规() {
        let dir = temp_dir("format");
        let logger = TwoFaLogger {
            max_level: LevelFilter::Info,
            file: Some(FileTarget {
                dir: dir.clone(),
                current: Mutex::new(None),
            }),
        };
        log_info(&logger, "测试日志行");

        let now = Local::now();
        let today_file = dir.join(format!("{FILE_PREFIX}{}{FILE_SUFFIX}", date_text(&now)));
        let content = fs::read_to_string(&today_file).unwrap();
        assert!(content.contains("[INFO]"), "应含级别：{content}");
        assert!(
            content.contains("[two_fa_cli::test:42]"),
            "应含模块与行号：{content}"
        );
        assert!(content.contains("测试日志行"), "应含内容：{content}");
    }

    /// 文件目标按写入日期轮转：日期变化写新文件，旧文件不受影响。
    #[test]
    fn 文件按日轮转() {
        let dir = temp_dir("rotate");
        let target = FileTarget {
            dir: dir.clone(),
            current: Mutex::new(None),
        };
        let today = Local::now();
        let yesterday = today - chrono::Duration::days(1);
        target.write_line(&yesterday, "昨日行");
        target.write_line(&today, "今日行");

        let yesterday_file = dir.join(format!(
            "{FILE_PREFIX}{}{FILE_SUFFIX}",
            date_text(&yesterday)
        ));
        let today_file = dir.join(format!("{FILE_PREFIX}{}{FILE_SUFFIX}", date_text(&today)));
        assert_eq!(fs::read_to_string(&yesterday_file).unwrap(), "昨日行\n");
        assert_eq!(fs::read_to_string(&today_file).unwrap(), "今日行\n");
    }

    /// 清理：只删超过保留期且符合命名的文件，边界日（第 7 天）保留。
    #[test]
    fn 清理过期日志() {
        let dir = temp_dir("purge");
        let today = Local::now().date_naive();
        let expired = dir.join(format!(
            "{FILE_PREFIX}{}{FILE_SUFFIX}",
            (today - chrono::Duration::days(RETAIN_DAYS + 2)).format("%Y%m%d")
        ));
        let boundary = dir.join(format!(
            "{FILE_PREFIX}{}{FILE_SUFFIX}",
            (today - chrono::Duration::days(RETAIN_DAYS)).format("%Y%m%d")
        ));
        let today_file = dir.join(format!(
            "{FILE_PREFIX}{}{FILE_SUFFIX}",
            today.format("%Y%m%d")
        ));
        fs::write(&expired, "过期").unwrap();
        fs::write(&boundary, "边界保留").unwrap();
        fs::write(&today_file, "今天").unwrap();
        fs::write(dir.join("其他文件.txt"), "不动").unwrap();

        let removed = purge_expired(&dir, today).unwrap();

        assert_eq!(removed, 1);
        assert!(!expired.exists(), "过期文件应被删除");
        assert!(boundary.exists(), "第 7 天边界文件应保留");
        assert!(today_file.exists());
        assert!(
            dir.join("其他文件.txt").exists(),
            "非日志命名文件不应被删除"
        );
    }

    /// 超过保留期但发生在目录不存在的场景：返回空结果而非报错由调用方前置检查。
    #[test]
    fn 目录为空或不存在时清理返回零() {
        let dir = temp_dir("empty");
        // 目录存在但无日志文件
        assert_eq!(purge_expired(&dir, Local::now().date_naive()).unwrap(), 0);
        // 目录不存在：read_dir 报错交由调用方处理
        assert!(purge_expired(&dir.join("缺失"), Local::now().date_naive()).is_err());
    }
}
