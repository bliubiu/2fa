//! 保险库文件的原子写入与跨进程文件锁。
//!
//! 原子写入四步（少一步就有断电损坏窗口）：
//! 同目录临时文件 → fsync 文件 → rename 覆盖目标 → fsync 父目录。
//!
//! 文件锁（全程无 `unsafe`，不使用 LockFileEx/flock）：
//! - 以 `O_EXCL` 原子创建锁文件实现互斥，持锁信息（PID 等）写入锁文件供诊断
//! - Windows 使用 `FILE_FLAG_DELETE_ON_CLOSE`：持锁进程无论何种方式退出，
//!   锁文件自动消失，正常不会残留
//! - Unix 残留锁由 PID 存活判定接管（Linux 经 `/proc/<pid>` 精确校验）；
//!   无 `/proc` 的平台与 Windows 断电残留一样，按锁文件修改时间超过阈值判定接管
//! - 接管通过「rename 走旧锁文件」保证并发接管者只有一个成功

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use data_encoding::HEXLOWER;

/// 锁文件的修改时间超过该时长即视为残留（进程会话远短于此）。
const RESIDUAL_AFTER: Duration = Duration::from_secs(60 * 60);
/// Windows `FILE_FLAG_DELETE_ON_CLOSE`。
#[cfg(windows)]
const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
/// Windows 打开目录句柄所需的 `FILE_FLAG_BACKUP_SEMANTICS`。
#[cfg(windows)]
const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;

/// 文件锁错误。
#[derive(Debug, thiserror::Error)]
pub enum LockError {
    /// 另一个 2FA 进程正在编辑此保险库。
    #[error("另一个 2FA 进程（PID {pid}）正在编辑此保险库，请等待其完成后再试")]
    Busy { pid: u32 },
    /// 锁文件系统操作失败。
    #[error("文件锁操作失败：{0}")]
    Io(#[from] io::Error),
}

/// 生成本地唯一后缀（16 个小写十六进制字符，来源操作系统 CSPRNG）。
fn random_suffix() -> Result<String, io::Error> {
    let mut bytes = [0u8; 8];
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    Ok(HEXLOWER.encode(&bytes))
}

/// 原子写入：同目录临时文件 → fsync 文件 → rename → fsync 父目录。
///
/// 任何一步失败都不触碰目标文件，并清理临时文件。
pub fn atomic_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let dir = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        _ => PathBuf::from("."),
    };
    let tmp_path = dir.join(format!(".2fa-tmp-{}", random_suffix()?));

    // 写临时文件并 fsync
    {
        let mut file = File::create_new(&tmp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
    }
    // rename 覆盖目标；失败则清理临时文件，目标保持原样
    if let Err(err) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(err);
    }
    // fsync 父目录
    sync_dir(&dir)
}

/// fsync 父目录：目录条目落盘，rename 结果在断电后可复原。
fn sync_dir(dir: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(dir)?;
        file.sync_all()
    }
    #[cfg(unix)]
    {
        File::open(dir)?.sync_all()
    }
}

/// 跨进程排它锁：持有期间独占保险库的写访问。
#[derive(Debug)]
pub struct VaultLock {
    /// 锁文件句柄（Windows 上关闭即自动删除文件）。
    _file: File,
    /// 锁文件路径。
    path: PathBuf,
}

impl VaultLock {
    /// 对给定保险库文件获取排它锁（非阻塞，立即返回结果）。
    ///
    /// `O_EXCL` 创建锁文件实现互斥；锁文件已存在时先读出持锁信息判活，
    /// 持锁进程已死亡（或锁文件已残留超过阈值）则接管。
    pub fn acquire(vault_path: &Path) -> Result<Self, LockError> {
        let path = Self::lock_path(vault_path);
        loop {
            match Self::try_create(&path) {
                Ok(file) => {
                    return Ok(Self { _file: file, path });
                }
                Err(LockError::Io(err)) if err.kind() == io::ErrorKind::AlreadyExists => {
                    Self::handle_existing(&path)?;
                }
                Err(err) => return Err(err),
            }
        }
    }

    /// 原子创建锁文件并写入持锁信息（Windows 附加 DELETE_ON_CLOSE）。
    fn try_create(path: &Path) -> Result<File, LockError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt as _;
            options.custom_flags(FILE_FLAG_DELETE_ON_CLOSE);
        }
        let mut file = options.open(path)?;
        writeln!(file, "pid={}", std::process::id())?;
        file.flush()?;
        Ok(file)
    }

    /// 锁文件已存在：判活，死锁接管，活锁报 Busy。
    fn handle_existing(path: &Path) -> Result<(), LockError> {
        // 修改时间超过阈值：无条件视为残留（断电残留 / 无进程存活判定能力的平台兜底）
        if Self::is_residual_path(path) {
            return Self::reclaim(path);
        }
        // 读持锁信息判活
        let holder_pid = fs::read_to_string(path)
            .ok()
            .and_then(|text| parse_pid(&text));
        match holder_pid {
            Some(pid) if process_alive(pid) => Err(LockError::Busy { pid }),
            // 有 PID 但进程已死 → 接管；无 PID（内容异常或尚未写入）→ 视为活跃持有，报 Busy
            Some(_) => Self::reclaim(path),
            None => Err(LockError::Busy {
                pid: parse_pid_any(&fs::read_to_string(path).unwrap_or_default()).unwrap_or(0),
            }),
        }
    }

    /// 接管残留锁：把旧锁文件 rename 走（并发接管者只有一个成功），随后重建。
    fn reclaim(path: &Path) -> Result<(), LockError> {
        let abandoned = path.with_file_name(format!(
            "{}.stale-{}",
            path.file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default(),
            random_suffix().map_err(LockError::from)?
        ));
        match fs::rename(path, &abandoned) {
            Ok(()) => {
                let _ = fs::remove_file(&abandoned);
                Ok(())
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                // 别的接管者已抢先拿走，外层循环重建即可
                Ok(())
            }
            Err(err) => Err(err.into()),
        }
    }

    /// 锁文件路径：在保险库文件名后追加 `.lock`。
    fn lock_path(vault_path: &Path) -> PathBuf {
        let mut name = vault_path
            .file_name()
            .map(|n| n.to_os_string())
            .unwrap_or_default();
        name.push(".lock");
        vault_path.with_file_name(name)
    }

    /// 锁文件是否已变为残留（修改时间早于阈值）。
    fn is_residual_path(path: &Path) -> bool {
        fs::metadata(path)
            .and_then(|m| m.modified())
            .map(
                |modified| match SystemTime::now().duration_since(modified) {
                    Ok(age) => age >= RESIDUAL_AFTER,
                    Err(_) => false,
                },
            )
            .unwrap_or(false)
    }
}

/// 从锁文件内容解析持锁进程 PID。
fn parse_pid(content: &str) -> Option<u32> {
    parse_pid_any(content).filter(|&pid| pid != 0)
}

/// 宽容解析：内容中任意 `pid=数字` 行。
fn parse_pid_any(content: &str) -> Option<u32> {
    content
        .lines()
        .find_map(|line| line.strip_prefix("pid="))
        .and_then(|value| value.trim().parse().ok())
}

/// 持锁进程是否存活。
///
/// Linux 经 `/proc/<pid>` 精确判定；其余平台无法在不引入 `unsafe` 的情况下
/// 判定进程存活，一律按「存活」处理，残留交给 mtime 阈值兜底。
fn process_alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        Path::new("/proc").join(pid.to_string()).exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        true
    }
}

#[cfg(unix)]
impl Drop for VaultLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::env;

    /// 建立独立临时目录作为测试工作区。
    fn temp_dir(tag: &str) -> PathBuf {
        let base = env::temp_dir().join(format!("2fa-test-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(&base).unwrap();
        base
    }

    /// 原子写入后内容正确。
    #[test]
    fn 原子写入内容正确() {
        let dir = temp_dir("atomic-ok");
        let path = dir.join("vault.json");
        let content = "你好 2fa".as_bytes().to_vec();
        atomic_write(&path, &content).unwrap();
        assert_eq!(fs::read(&path).unwrap(), content);
    }

    /// 覆盖已存在文件时内容完整替换。
    #[test]
    fn 原子写入覆盖旧文件() {
        let dir = temp_dir("atomic-over");
        let path = dir.join("vault.json");
        let old = "旧内容旧内容旧内容".as_bytes().to_vec();
        let new = "新".as_bytes().to_vec();
        atomic_write(&path, &old).unwrap();
        atomic_write(&path, &new).unwrap();
        assert_eq!(fs::read(&path).unwrap(), new);
    }

    /// rename 失败时目标完好、临时文件被清理。
    #[test]
    fn 原子写入失败不伤目标() {
        let dir = temp_dir("atomic-fail");
        let target = dir.join("occupied"); // 一个目录：rename 文件到目录必失败
        fs::create_dir(&target).unwrap();
        let err = atomic_write(&target, b"xxx").unwrap_err();
        let _ = err;
        assert!(target.is_dir(), "目标目录应完好");
        // 临时文件应被清理，不留 .2fa-tmp- 残留
        let leftovers: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().starts_with(".2fa-tmp-"))
            .collect();
        assert!(leftovers.is_empty(), "临时文件应被清理");
    }

    /// 临时文件与目标同目录（保证 rename 同文件系统原子性）。
    #[test]
    fn 临时文件与目标同目录() {
        let dir = temp_dir("atomic-samedir");
        let path = dir.join("vault.json");
        // 中途无法直接观测；此处验证写入成功后同目录无残留即可
        atomic_write(&path, b"data").unwrap();
        let count = fs::read_dir(&dir).unwrap().count();
        assert_eq!(count, 1, "目录中应只剩目标文件");
    }

    /// 获取锁成功并写入持锁信息。
    #[test]
    fn 获取锁成功() {
        let dir = temp_dir("lock-ok");
        let vault = dir.join("vault.json");
        let lock = VaultLock::acquire(&vault).unwrap();
        assert!(VaultLock::lock_path(&vault).exists(), "锁文件应存在");
        let content = fs::read_to_string(VaultLock::lock_path(&vault)).unwrap();
        assert!(
            content.contains(&format!("pid={}", std::process::id())),
            "{content}"
        );
        drop(lock);
    }

    /// 已持锁时再次获取报 Busy，且提示持有者 PID。
    #[test]
    fn 重复获取报busy() {
        let dir = temp_dir("lock-busy");
        let vault = dir.join("vault.json");
        let _lock = VaultLock::acquire(&vault).unwrap();
        let err = VaultLock::acquire(&vault).unwrap_err();
        match err {
            LockError::Busy { pid } => assert_eq!(pid, std::process::id()),
            other => panic!("应为 Busy，实际 {other:?}"),
        }
    }

    /// 释放后可重新获取。
    #[test]
    fn 释放后可重新获取() {
        let dir = temp_dir("lock-relock");
        let vault = dir.join("vault.json");
        {
            let _lock = VaultLock::acquire(&vault).unwrap();
        }
        let _lock = VaultLock::acquire(&vault).unwrap();
    }

    /// 死进程的残留锁被接管：锁文件存在但修改时间超过阈值。
    #[test]
    fn 残留锁被接管() {
        let dir = temp_dir("lock-residual");
        let vault = dir.join("vault.json");
        let lock_path = VaultLock::lock_path(&vault);
        fs::write(&lock_path, format!("pid={}\n", std::process::id())).unwrap();
        // 把锁文件修改时间拨回阈值之前
        let old = SystemTime::now() - RESIDUAL_AFTER - Duration::from_secs(10);
        let f = OpenOptions::new().write(true).open(&lock_path).unwrap();
        f.set_modified(old).unwrap();
        drop(f);

        let _lock = VaultLock::acquire(&vault).unwrap();
        let content = fs::read_to_string(&lock_path).unwrap();
        assert!(content.contains(&format!("pid={}", std::process::id())));
    }
}
