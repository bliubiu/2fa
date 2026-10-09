//! 保险库路径解析：`--vault` > 当前目录 `.2fa/vault.json` > 平台惯例路径。
//!
//! 解析为纯函数：环境值（`%APPDATA%` / `$XDG_DATA_HOME` / `$HOME`）与当前目录
//! 由调用方采集注入，本模块不直接读取环境变量，保证可测试。
//!
//! 每条命令必须回显解析出的**绝对路径**与来源——这是防止用户在错误的
//! 保险库上操作的最后一道防线（`docs/adr/0004`）。

use std::path::{Path, PathBuf};

/// 项目内保险库目录名。
pub const PROJECT_DIR: &str = ".2fa";
/// 项目内保险库文件名。
pub const PROJECT_FILE: &str = "vault.json";

/// 保险库来源。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultSource {
    /// `--vault` 显式指定。
    Explicit,
    /// 当前工作目录下的 `.2fa/vault.json`。
    Project,
    /// 平台惯例路径。
    Platform,
}

impl VaultSource {
    /// 来源的中文说明（每条命令回显时使用）。
    pub fn label(self) -> &'static str {
        match self {
            VaultSource::Explicit => "--vault 指定",
            VaultSource::Project => "项目内",
            VaultSource::Platform => "平台惯例",
        }
    }
}

/// 解析结果：绝对路径 + 来源。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedVault {
    /// 保险库文件的绝对路径。
    pub path: PathBuf,
    /// 路径来源。
    pub source: VaultSource,
}

/// 路径解析错误。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    /// 平台惯例路径所需的环境变量未设置。
    MissingEnv(&'static str),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::MissingEnv(name) => {
                write!(f, "无法确定平台惯例路径：环境变量 {name} 未设置")
            }
        }
    }
}

impl std::error::Error for ResolveError {}

/// 路径解析所需的环境值（由调用方采集，字段随平台裁剪）。
#[derive(Debug, Clone, Default)]
pub struct Env {
    /// 当前工作目录（绝对路径）。
    pub cwd: PathBuf,
    /// Windows `%APPDATA%`。
    #[cfg(windows)]
    pub appdata: Option<PathBuf>,
    /// Unix `$XDG_DATA_HOME`。
    #[cfg(not(windows))]
    pub xdg_data_home: Option<PathBuf>,
    /// 用户主目录（Unix：`$HOME`；未设置时平台路径回退需要它）。
    #[cfg(not(windows))]
    pub home: Option<PathBuf>,
}

/// 按优先级解析保险库路径：`--vault` > CWD `.2fa/vault.json` > 平台惯例。
///
/// 显式路径若为相对路径，按当前目录补全为绝对路径。
pub fn resolve(vault_arg: Option<PathBuf>, env: &Env) -> Result<ResolvedVault, ResolveError> {
    if let Some(path) = vault_arg {
        let path = absolutize(&path, env);
        return Ok(ResolvedVault {
            path,
            source: VaultSource::Explicit,
        });
    }
    let project = env.cwd.join(PROJECT_DIR).join(PROJECT_FILE);
    if project.is_file() {
        return Ok(ResolvedVault {
            path: project,
            source: VaultSource::Project,
        });
    }
    Ok(ResolvedVault {
        path: platform_vault_path(env)?,
        source: VaultSource::Platform,
    })
}

/// `init` 的目标路径选择：`--vault` > `--project` > 平台惯例。
///
/// 与 [`resolve`] 的区别：默认 `init` 固定创建在平台惯例路径，
/// **不**因当前目录恰好存在项目保险库而改变目标（`docs/01` 第 4.6 节）。
pub fn init_target(
    vault_arg: Option<PathBuf>,
    project: bool,
    env: &Env,
) -> Result<PathBuf, ResolveError> {
    if let Some(path) = vault_arg {
        return Ok(absolutize(&path, env));
    }
    if project {
        return Ok(env.cwd.join(PROJECT_DIR).join(PROJECT_FILE));
    }
    platform_vault_path(env)
}

/// 平台惯例路径（不检查存在性）。
///
/// Windows：`%APPDATA%\2fa\vault.json`；
/// macOS / Linux：`$XDG_DATA_HOME/2fa/vault.json`，未设置时回退 `~/.local/share/2fa/vault.json`。
pub fn platform_vault_path(env: &Env) -> Result<PathBuf, ResolveError> {
    #[cfg(windows)]
    {
        env.appdata
            .as_ref()
            .map(|base| base.join("2fa").join(PROJECT_FILE))
            .ok_or(ResolveError::MissingEnv("APPDATA"))
    }
    #[cfg(not(windows))]
    {
        if let Some(base) = env.xdg_data_home.as_ref() {
            return Ok(base.join("2fa").join(PROJECT_FILE));
        }
        match env.home.as_ref() {
            Some(home) => Ok(home
                .join(".local")
                .join("share")
                .join("2fa")
                .join(PROJECT_FILE)),
            None => Err(ResolveError::MissingEnv("XDG_DATA_HOME 与 HOME")),
        }
    }
}

/// 相对路径按当前目录补全为绝对路径。
fn absolutize(path: &Path, env: &Env) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        env.cwd.join(path)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn env_with(cwd: &str) -> Env {
        Env {
            cwd: PathBuf::from(cwd),
            ..Default::default()
        }
    }

    /// `--vault` 最高优先级，相对路径按 CWD 补全为绝对路径。
    #[test]
    fn 显式路径优先且补全为绝对路径() {
        let env = env_with("D:/work");
        let resolved = resolve(Some(PathBuf::from("my/vault.json")), &env).unwrap();
        assert_eq!(resolved.source, VaultSource::Explicit);
        assert_eq!(resolved.path, PathBuf::from("D:/work/my/vault.json"));

        let resolved = resolve(Some(PathBuf::from("E:/abs/vault.json")), &env).unwrap();
        assert_eq!(resolved.path, PathBuf::from("E:/abs/vault.json"));
    }

    /// CWD 下存在 `.2fa/vault.json` 时优先于平台惯例。
    #[test]
    fn 项目内保险库优先于平台惯例() {
        let dir = std::env::temp_dir().join(format!("2fa-paths-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let project_dir = dir.join(PROJECT_DIR);
        std::fs::create_dir_all(&project_dir).unwrap();
        std::fs::write(project_dir.join(PROJECT_FILE), b"x").unwrap();

        let env = Env {
            cwd: dir.clone(),
            ..Default::default()
        };
        let resolved = resolve(None, &env).unwrap();
        assert_eq!(resolved.source, VaultSource::Project);
        assert_eq!(resolved.path, project_dir.join(PROJECT_FILE));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// CWD 下不存在项目保险库时落到平台惯例路径（Windows 分支）。
    #[cfg(windows)]
    #[test]
    fn 平台惯例路径_windows() {
        let env = Env {
            cwd: PathBuf::from("D:/work"),
            appdata: Some(PathBuf::from("C:/Users/u/AppData/Roaming")),
        };
        let resolved = resolve(None, &env).unwrap();
        assert_eq!(resolved.source, VaultSource::Platform);
        assert_eq!(
            resolved.path,
            PathBuf::from("C:/Users/u/AppData/Roaming/2fa/vault.json")
        );

        // APPDATA 未设置：明确报错
        let env = Env {
            cwd: PathBuf::from("D:/work"),
            ..Default::default()
        };
        let err = resolve(None, &env).unwrap_err();
        assert!(matches!(err, ResolveError::MissingEnv("APPDATA")));
    }

    /// Unix 平台惯例路径：`$XDG_DATA_HOME` 优先，未设置回退 `~/.local/share`（CI Linux 覆盖）。
    #[cfg(unix)]
    #[test]
    fn 平台惯例路径_unix() {
        let env = Env {
            cwd: PathBuf::from("/work"),
            xdg_data_home: Some(PathBuf::from("/data")),
            home: Some(PathBuf::from("/home/u")),
            ..Default::default()
        };
        let resolved = resolve(None, &env).unwrap();
        assert_eq!(resolved.path, PathBuf::from("/data/2fa/vault.json"));

        // XDG 未设置：回退 ~/.local/share
        let env = Env {
            cwd: PathBuf::from("/work"),
            home: Some(PathBuf::from("/home/u")),
            ..Default::default()
        };
        let resolved = resolve(None, &env).unwrap();
        assert_eq!(
            resolved.path,
            PathBuf::from("/home/u/.local/share/2fa/vault.json")
        );

        // 两者都未设置：明确报错
        let err = resolve(None, &env_with("/work")).unwrap_err();
        assert!(matches!(
            err,
            ResolveError::MissingEnv("XDG_DATA_HOME 与 HOME")
        ));
    }

    /// `init` 目标选择：`--vault` > `--project` > 平台惯例，
    /// 且不受「当前目录恰好已有项目保险库」影响。
    #[cfg(windows)]
    #[test]
    fn init目标选择() {
        let env = Env {
            cwd: PathBuf::from("D:/work"),
            appdata: Some(PathBuf::from("C:/Users/u/AppData/Roaming")),
        };
        assert_eq!(
            init_target(None, true, &env).unwrap(),
            PathBuf::from("D:/work/.2fa/vault.json")
        );
        assert_eq!(
            init_target(None, false, &env).unwrap(),
            PathBuf::from("C:/Users/u/AppData/Roaming/2fa/vault.json")
        );
        assert_eq!(
            init_target(Some(PathBuf::from("X:/v.json")), true, &env).unwrap(),
            PathBuf::from("X:/v.json")
        );
    }

    /// 来源标签文案。
    #[test]
    fn 来源标签() {
        assert_eq!(VaultSource::Explicit.label(), "--vault 指定");
        assert_eq!(VaultSource::Project.label(), "项目内");
        assert_eq!(VaultSource::Platform.label(), "平台惯例");
    }
}
