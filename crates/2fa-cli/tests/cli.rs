//! CLI 集成测试：真实二进制 + 管道输入，验证单次命令模式的退出码与 stdout 纪律。
//!
//! 覆盖实施计划 M3-3 验收：
//! - `2fa --stdin-password status` 输出可被管道解析（stdout 只有命令输出）
//! - 退出码正确：成功 0、认证失败 2、一般错误 1

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use two_fa_core::usecase;
use two_fa_core::vault::atomic_write;

/// 构造测试专用保险库，返回目录与保险库路径。
fn make_vault(password: &str, recovery: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "2fa-cli-test-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let vault = dir.join("vault.json");
    let bytes = usecase::init::create_vault(
        password,
        &usecase::recovery::normalize(recovery),
        1_700_000_000,
    )
    .unwrap();
    atomic_write(&vault, &bytes).unwrap();
    (dir, vault)
}

/// 运行 2fa 二进制，stdin 写入给定行，返回 (退出码, stdout, stderr)。
fn run_2fa(vault: &PathBuf, stdin_text: &str, args: &[&str]) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_2fa"))
        .arg("--vault")
        .arg(vault)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin_text.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

/// `--stdin-password status`：成功路径，stdout 只有命令输出且含关键字段。
#[test]
fn status_管道输出与退出码() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let (code, stdout, stderr) = run_2fa(&vault, "测试密码123\n", &["--stdin-password", "status"]);

    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("保险库："), "stdout 应含路径回显：{stdout}");
    assert!(stdout.contains("来源："), "stdout 应含来源：{stdout}");
    assert!(
        stdout.contains("条目数量：0"),
        "stdout 应含条目数量：{stdout}"
    );
    assert!(stdout.contains("v1"), "stdout 应含 KDF 版本：{stdout}");
    assert!(
        !stdout.contains("错误"),
        "stdout 不应包含错误信息（走 stderr）：{stdout}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// 错误密码：退出码 2，stdout 干净。
#[test]
fn 错误密码退出码2() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let (code, stdout, stderr) = run_2fa(&vault, "错误密码\n", &["--stdin-password", "status"]);

    assert_eq!(code, 2, "stderr: {stderr}");
    assert!(stdout.is_empty(), "失败时 stdout 应为空：{stdout}");
    assert!(
        stderr.contains("认证失败"),
        "stderr 应说明认证失败：{stderr}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// 保险库不存在：退出码 1，stderr 给出可操作的提示。
#[test]
fn 保险库不存在退出码1() {
    let dir = std::env::temp_dir().join(format!("2fa-cli-missing-{}", std::process::id()));
    let vault = dir.join("不存在.json");
    let (code, stdout, stderr) = run_2fa(&vault, "任意\n", &["--stdin-password", "status"]);

    assert_eq!(code, 1);
    assert!(stdout.is_empty());
    assert!(stderr.contains("保险库文件不存在"), "stderr: {stderr}");
}

/// 未传 `--stdin-password` 且 stdin 有管道数据时，status 需要交互输入——
/// 集成测试无法模拟 tty，此处仅验证空 stdin 报一般错误而非挂死。
#[test]
fn 无密码来源时退出码1() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    // rpassword 在无 tty 的 stdin 上读取失败或得到空输入，应报错退出而非挂死
    let (code, _stdout, _stderr) = run_2fa(&vault, "", &["status"]);
    assert_ne!(code, 0, "无凭据来源不应成功");
    assert_ne!(code, 2, "无凭据来源不是认证失败");
    std::fs::remove_dir_all(&dir).unwrap();
}
