//! 保险库路径解析（GUI 侧）：当前目录 `.2fa/vault.json`（存在时）> 平台惯例路径。
//!
//! GUI 没有 `--vault` 参数，其余优先级与 CLI 同语义（`docs/adr/0004`）。
//! 解析为纯函数：环境值（`%APPDATA%` / `$XDG_DATA_HOME` / `$HOME`）与当前目录
//! 由壳层采集注入，本模块不直接读取环境变量，保证可测试。
//! 解析出的绝对路径与来源会通过 `status` 命令回显给前端——防止用户在错误的
//! 保险库上操作是最后一道防线。

use std::path::PathBuf;

/// 项目内保险库目录名。
pub const PROJECT_DIR: &str = ".2fa";
/// 项目内保险库文件名。
pub const PROJECT_FILE: &str = "vault.json";

/// 保险库来源（GUI 无 `--vault`，故无显式项）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VaultSource {
    /// 当前工作目录下的 `.2fa/vault.json`。
    Project,
    /// 平台惯例路径。
    Platform,
}

impl VaultSource {
    /// 来源的中文说明（status 回显用）。
    pub fn label(self) -> &'static str {
        match self {
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

/// 路径解析所需的环境值（由壳层采集，字段随平台裁剪）。
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
    /// 用户主目录（Unix 回退用）。
    #[cfg(not(windows))]
    pub home: Option<PathBuf>,
}

/// 按优先级解析保险库路径：CWD `.2fa/vault.json`（存在时）> 平台惯例。
pub fn resolve(env: &Env) -> Result<ResolvedVault, ResolveError> {
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// CWD 下存在 `.2fa/vault.json` 时优先于平台惯例。
    #[test]
    fn 项目内保险库优先于平台惯例() {
        let dir = std::env::temp_dir().join(format!("2fa-app-paths-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let project_dir = dir.join(PROJECT_DIR);
        std::fs::create_dir_all(&project_dir).unwrap();
        std::fs::write(project_dir.join(PROJECT_FILE), b"x").unwrap();

        let env = Env {
            cwd: dir.clone(),
            ..Default::default()
        };
        let resolved = resolve(&env).unwrap();
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
        let resolved = resolve(&env).unwrap();
        assert_eq!(resolved.source, VaultSource::Platform);
        assert_eq!(
            resolved.path,
            PathBuf::from("C:/Users/u/AppData/Roaming/2fa/vault.json")
        );

        // APPDATA 未设置：明确报错而非静默回退
        let env = Env {
            cwd: PathBuf::from("D:/work"),
            ..Default::default()
        };
        let err = resolve(&env).unwrap_err();
        assert_eq!(err, ResolveError::MissingEnv("APPDATA"));
    }

    /// Unix 平台惯例路径：`$XDG_DATA_HOME` 优先，未设置回退 `~/.local/share`（CI Linux 覆盖）。
    #[cfg(unix)]
    #[test]
    fn 平台惯例路径_unix() {
        let env = Env {
            cwd: PathBuf::from("/work"),
            xdg_data_home: Some(PathBuf::from("/data")),
            home: Some(PathBuf::from("/home/u")),
        };
        assert_eq!(
            resolve(&env).unwrap().path,
            PathBuf::from("/data/2fa/vault.json")
        );

        // XDG 未设置：回退 ~/.local/share
        let env = Env {
            cwd: PathBuf::from("/work"),
            xdg_data_home: None,
            home: Some(PathBuf::from("/home/u")),
        };
        assert_eq!(
            resolve(&env).unwrap().path,
            PathBuf::from("/home/u/.local/share/2fa/vault.json")
        );

        // 两者都未设置：明确报错
        let err = resolve(&Env {
            cwd: PathBuf::from("/work"),
            xdg_data_home: None,
            home: None,
        })
        .unwrap_err();
        assert_eq!(err, ResolveError::MissingEnv("XDG_DATA_HOME 与 HOME"));
    }

    /// 来源标签文案。
    #[test]
    fn 来源标签() {
        assert_eq!(VaultSource::Project.label(), "项目内");
        assert_eq!(VaultSource::Platform.label(), "平台惯例");
    }
}
