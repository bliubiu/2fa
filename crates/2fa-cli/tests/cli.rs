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

/// 从 add 的输出中提取新条目的 ID 前缀（8 位）。
fn extract_id8(stdout: &str) -> String {
    let marker = "ID 前缀 ";
    let start = stdout.find(marker).unwrap() + marker.len();
    stdout[start..start + 8].to_string()
}

/// 条目增删改查全流程：add → list → find → show → edit → del → list。
#[test]
fn 条目增删改查全流程() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let password = "测试密码123\n";
    let secret = "JBSWY3DPEHPK3PXP";

    // 添加
    let (code, stdout, stderr) = run_2fa(
        &vault,
        password,
        &[
            "--stdin-password",
            "add",
            "GitHub",
            "alice",
            secret,
            "--tags",
            "工作,代码",
        ],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("已添加条目"), "stdout: {stdout}");
    assert!(
        stdout.contains("保险库："),
        "每条命令必须回显路径：{stdout}"
    );
    let id8 = extract_id8(&stdout);

    // 列表：含服务商、账号与表头
    let (code, stdout, stderr) = run_2fa(&vault, password, &["--stdin-password", "list"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("GitHub"), "stdout: {stdout}");
    assert!(stdout.contains("alice"), "stdout: {stdout}");
    assert!(stdout.contains("验证码"), "stdout 应含表头：{stdout}");

    // 搜索（不区分大小写子串）
    let (code, stdout, stderr) = run_2fa(&vault, password, &["--stdin-password", "find", "git"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("GitHub"), "stdout: {stdout}");

    // 详情（--yes 旁路确认）：含明文密钥
    let (code, stdout, stderr) = run_2fa(
        &vault,
        password,
        &["--stdin-password", "show", &id8, "--yes"],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("密钥（明文）"), "stdout: {stdout}");
    assert!(stdout.contains(secret), "stdout 应含明文密钥：{stdout}");
    assert!(stdout.contains("SHA1"), "stdout 应含算法：{stdout}");

    // 更新：改服务商与算法
    let (code, stdout, stderr) = run_2fa(
        &vault,
        password,
        &[
            "--stdin-password",
            "edit",
            &id8,
            "--issuer",
            "GitLab",
            "--algorithm",
            "SHA256",
            "--digits",
            "8",
        ],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("已更新条目"), "stdout: {stdout}");

    // 更新后列表反映新服务商；show 反映新算法
    let (code, stdout, _stderr) = run_2fa(&vault, password, &["--stdin-password", "list"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("GitLab"), "stdout: {stdout}");
    assert!(!stdout.contains("GitHub"), "旧服务商不应存在：{stdout}");
    let (code, stdout, stderr) = run_2fa(
        &vault,
        password,
        &["--stdin-password", "show", &id8, "--yes"],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("SHA256"), "stdout: {stdout}");

    // 删除（--yes 旁路确认）后列表为空
    let (code, stdout, stderr) = run_2fa(
        &vault,
        password,
        &["--stdin-password", "del", &id8, "--yes"],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("已删除条目"), "stdout: {stdout}");
    let (code, stdout, _stderr) = run_2fa(&vault, password, &["--stdin-password", "list"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("保险库为空"), "stdout: {stdout}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// 重名条目：非交互必须显式选择 --overwrite / --keep-both。
#[test]
fn 重名条目需显式选择() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let password = "测试密码123\n";

    // 首次添加成功
    let (code, _stdout, stderr) = run_2fa(
        &vault,
        password,
        &[
            "--stdin-password",
            "add",
            "GitHub",
            "alice",
            "JBSWY3DPEHPK3PXP",
        ],
    );
    assert_eq!(code, 0, "stderr: {stderr}");

    // 同标识再次添加且无选择：报错并提示两个选项
    let (code, stdout, stderr) = run_2fa(
        &vault,
        password,
        &["--stdin-password", "add", "GitHub", "alice", "MZXW6YTBOI"],
    );
    assert_eq!(code, 1, "同标识冲突应报一般错误");
    assert!(stdout.is_empty());
    assert!(
        stderr.contains("--overwrite") && stderr.contains("--keep-both"),
        "stderr 应提示两个选项：{stderr}"
    );

    // --overwrite 覆盖：仍只有 1 条
    let (code, stdout, stderr) = run_2fa(
        &vault,
        password,
        &[
            "--stdin-password",
            "add",
            "GitHub",
            "alice",
            "MZXW6YTBOI",
            "--overwrite",
        ],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("已覆盖"), "stdout: {stdout}");
    let (code, stdout, _stderr) = run_2fa(&vault, password, &["--stdin-password", "status"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("条目数量：1"), "stdout: {stdout}");

    // --keep-both 并存：共 2 条
    let (code, _stdout, stderr) = run_2fa(
        &vault,
        password,
        &[
            "--stdin-password",
            "add",
            "GitHub",
            "alice",
            "MZXW6YQ",
            "--keep-both",
        ],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    let (code, stdout, _stderr) = run_2fa(&vault, password, &["--stdin-password", "status"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("条目数量：2"), "stdout: {stdout}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// 危险操作确认：del 与 show 在非交互且无 --yes 时拒绝执行。
#[test]
fn 删除与明文显示需确认() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let password = "测试密码123\n";
    let (code, stdout, stderr) = run_2fa(
        &vault,
        password,
        &[
            "--stdin-password",
            "add",
            "GitHub",
            "alice",
            "JBSWY3DPEHPK3PXP",
        ],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    let id8 = extract_id8(&stdout);

    // del 无 --yes：拒绝
    let (code, stdout, stderr) = run_2fa(&vault, password, &["--stdin-password", "del", &id8]);
    assert_eq!(code, 1);
    assert!(stdout.is_empty());
    assert!(stderr.contains("--yes"), "stderr: {stderr}");

    // show 无 --yes：拒绝（明文密钥保护）
    let (code, stdout, stderr) = run_2fa(&vault, password, &["--stdin-password", "show", &id8]);
    assert_eq!(code, 1);
    assert!(stdout.is_empty());
    assert!(stderr.contains("--yes"), "stderr: {stderr}");

    // 拒绝后条目仍在
    let (code, stdout, _stderr) = run_2fa(&vault, password, &["--stdin-password", "status"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("条目数量：1"), "stdout: {stdout}");
    std::fs::remove_dir_all(&dir).unwrap();
}
