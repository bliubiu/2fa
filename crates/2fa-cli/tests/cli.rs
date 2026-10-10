//! CLI 集成测试：真实二进制 + 管道输入，验证单次命令模式的退出码与 stdout 纪律。
//!
//! 覆盖实施计划 M3-3 验收：
//! - `2fa --stdin-password status` 输出可被管道解析（stdout 只有命令输出）
//! - 退出码正确：成功 0、认证失败 2、一般错误 1

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
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

// ---------------------------------------------------------------------------
// 日志与辅助命令（M3-7）
// ---------------------------------------------------------------------------

/// 测试专用日志根目录（进程内唯一，作为 LOCALAPPDATA / XDG_STATE_HOME 注入）。
fn log_root(tag: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!(
        "2fa-cli-log-{tag}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    root
}

/// 运行 2fa 并注入日志环境变量：Windows 取 LOCALAPPDATA、Unix 取
/// XDG_STATE_HOME，两者同时注入互不干扰；显式 `--vault` 不受影响。
fn run_2fa_with_log_root(
    root: &Path,
    vault: &PathBuf,
    stdin_text: &str,
    args: &[&str],
) -> (i32, String, String) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_2fa"))
        .env("LOCALAPPDATA", root)
        .env("XDG_STATE_HOME", root)
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

/// 默认运行无任何文件落盘：不创建日志目录。
#[test]
fn 默认运行无日志文件落盘() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let root = log_root("default");

    let (code, _stdout, stderr) = run_2fa_with_log_root(
        &root,
        &vault,
        "测试密码123\n",
        &["--stdin-password", "list"],
    );

    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        !root.join("2fa").exists(),
        "未开启 --log-to-file 时不应创建日志目录"
    );
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&root).ok();
}

/// `--log-to-file`：日志文件生成、格式合规，且经检索确认无密钥、无密码、无 otpauth。
#[test]
fn 日志落盘且无敏感内容() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let root = log_root("tofile");

    let (code, _stdout, stderr) = run_2fa_with_log_root(
        &root,
        &vault,
        "测试密码123\n",
        &[
            "--stdin-password",
            "--log-to-file",
            "add",
            "GitHub",
            "alice",
            "JBSWY3DPEHPK3PXP",
        ],
    );
    assert_eq!(code, 0, "stderr: {stderr}");

    let logs = root.join("2fa").join("logs");
    let mut log_files: Vec<PathBuf> = std::fs::read_dir(&logs)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .collect();
    assert_eq!(log_files.len(), 1, "应只有一个日志文件：{log_files:?}");
    let content = std::fs::read_to_string(log_files.remove(0)).unwrap();
    assert!(content.contains("[INFO]"), "应含 INFO 级别：{content}");
    assert!(content.contains("已添加条目"), "应记录操作行为：{content}");
    // 脱敏红线：密钥、密码、otpauth URI 一律不落盘
    assert!(
        !content.contains("JBSWY3DPEHPK3PXP"),
        "密钥不得进入日志：{content}"
    );
    assert!(
        !content.contains("测试密码123"),
        "密码不得进入日志：{content}"
    );
    assert!(
        !content.contains("otpauth://"),
        "otpauth 载荷不得进入日志：{content}"
    );
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&root).ok();
}

/// `logs purge`：清理超过保留期的日志文件，当天文件保留。
#[test]
fn logs_purge清理过期日志() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let root = log_root("purge");
    let logs = root.join("2fa").join("logs");
    std::fs::create_dir_all(&logs).unwrap();
    let today = chrono::Local::now().date_naive();
    let expired = logs.join(format!(
        "2fa-{}.log",
        (today - chrono::Duration::days(9)).format("%Y%m%d")
    ));
    let keep = logs.join(format!("2fa-{}.log", today.format("%Y%m%d")));
    std::fs::write(&expired, "过期日志").unwrap();
    std::fs::write(&keep, "当天日志").unwrap();

    let (code, stdout, stderr) = run_2fa_with_log_root(&root, &vault, "", &["logs", "purge"]);

    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("已清理 1 个"),
        "stdout 应报告清理数量：{stdout}"
    );
    assert!(!expired.exists(), "过期日志应被删除");
    assert!(keep.exists(), "当天日志应保留");
    std::fs::remove_dir_all(&dir).ok();
    std::fs::remove_dir_all(&root).ok();
}

/// `bench`：输出可读，含 KDF 与 TOTP 计时及单位。
#[test]
fn bench输出可读且数值合理() {
    // bench 不访问保险库，--vault 传假路径即可
    let (code, stdout, stderr) = run_2fa(&PathBuf::from("不存在的保险库.json"), "", &["bench"]);

    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("Argon2id"), "应报告 KDF 类型：{stdout}");
    assert!(stdout.contains("TOTP"), "应报告 TOTP 计时：{stdout}");
    assert!(stdout.contains("ms"), "KDF 耗时单位：{stdout}");
    assert!(stdout.contains("µs"), "TOTP 耗时单位：{stdout}");
}

// ---------------------------------------------------------------------------
// otpauth 文本导入（M4-1）
// ---------------------------------------------------------------------------

/// 写入测试导入文件。
fn make_import_file(tag: &str, content: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "2fa-cli-import-{tag}-{}-{}.txt",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&path, content).unwrap();
    path
}

/// 混合批次：注释行忽略、损坏行不中断整批、逐行报告。
#[test]
fn otpauth文本导入_混合批次() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let file = make_import_file(
        "mixed",
        "# 导出注释\n\
         \n\
         otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP\n\
         损坏行\n\
         otpauth://totp/Example:bob?secret=MZXW6YTBOI\n",
    );

    let (code, stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &["--stdin-password", "import", file.to_str().unwrap()],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("新增 2"), "stdout: {stdout}");
    assert!(stdout.contains("失败 1"), "stdout: {stdout}");
    assert!(stderr.contains("第 4 行"), "stderr 应报行号：{stderr}");

    // 条目确实入库
    let (code, stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &["--stdin-password", "find", "GitHub"],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("GitHub") && stdout.contains("alice"),
        "stdout: {stdout}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_file(&file).unwrap();
}

/// 重复条目（归一化同标识且密钥相同）跳过并提示。
#[test]
fn otpauth文本导入_重复跳过() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let file = make_import_file(
        "dup",
        "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP\n",
    );
    let args = ["--stdin-password", "import", file.to_str().unwrap()];

    let (code, stdout, stderr) = run_2fa(&vault, "测试密码123\n", &args);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("新增 1"), "首次导入：{stdout}");

    let (code, stdout, stderr) = run_2fa(&vault, "测试密码123\n", &args);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("新增 0"), "再次导入：{stdout}");
    assert!(stdout.contains("跳过重复 1"), "再次导入：{stdout}");
    assert!(stderr.contains("重复"), "stderr 应提示重复：{stderr}");
    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_file(&file).unwrap();
}

/// 同标识不同密钥：非交互默认跳过；--overwrite 覆盖；--keep-both 并存；互斥参数报错。
#[test]
fn otpauth文本导入_冲突处理() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let first = make_import_file(
        "c1",
        "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP\n",
    );
    let second = make_import_file("c2", "otpauth://totp/GitHub:alice?secret=MZXW6YTBOI\n");
    let password = "测试密码123\n";

    // 先导入第一条
    let (code, _o, stderr) = run_2fa(
        &vault,
        password,
        &["--stdin-password", "import", first.to_str().unwrap()],
    );
    assert_eq!(code, 0, "stderr: {stderr}");

    // 非交互无参数：默认跳过并提示
    let (code, stdout, stderr) = run_2fa(
        &vault,
        password,
        &["--stdin-password", "import", second.to_str().unwrap()],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("跳过冲突 1"), "stdout: {stdout}");
    assert!(
        stderr.contains("--overwrite"),
        "stderr 应给出选择提示：{stderr}"
    );

    // --overwrite：覆盖后仍是 1 条
    let (code, stdout, stderr) = run_2fa(
        &vault,
        password,
        &[
            "--stdin-password",
            "import",
            "--overwrite",
            file_to_str(&second),
        ],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("覆盖 1"), "stdout: {stdout}");
    let (_code, stdout, _stderr) = run_2fa(&vault, password, &["--stdin-password", "status"]);
    assert!(stdout.contains("条目数量：1"), "覆盖后仍一条：{stdout}");

    // --keep-both：并存后 2 条
    let (code, stdout, stderr) = run_2fa(
        &vault,
        password,
        &[
            "--stdin-password",
            "import",
            "--keep-both",
            file_to_str(&first),
        ],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("并存 1"), "stdout: {stdout}");
    let (_code, stdout, _stderr) = run_2fa(&vault, password, &["--stdin-password", "status"]);
    assert!(stdout.contains("条目数量：2"), "并存后两条：{stdout}");

    // 互斥参数：报错不执行
    let (code, _o, stderr) = run_2fa(
        &vault,
        password,
        &[
            "--stdin-password",
            "import",
            "--overwrite",
            "--keep-both",
            file_to_str(&first),
        ],
    );
    assert_eq!(code, 1, "互斥参数应报错");
    assert!(stderr.contains("互斥"), "stderr: {stderr}");

    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_file(&first).unwrap();
    std::fs::remove_file(&second).unwrap();
}

/// 路径 → 字符串（测试内统一转换）。
fn file_to_str(path: &Path) -> &str {
    path.to_str().unwrap()
}

/// 真实 GA 迁移样本（来源：dfarnham/totp-qr 项目 README，其解码依赖
/// alexbakker.me 的逆向 schema）：3 个 TOTP 条目 Test1~3。
#[test]
fn 迁移uri导入_真实样本() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let uri = "otpauth-migration://offline?data=Ci0KCkhlbGxvId6tvu8SEnRlc3QxQGV4YW1wbGUxLmNvbRoFVGVzdDEgASgBMAIKLQoKSGVsbG8h3q2%2B8BISdGVzdDJAZXhhbXBsZTIuY29tGgVUZXN0MiABKAEwAgotCgpIZWxsbyHerb7xEhJ0ZXN0M0BleGFtcGxlMy5jb20aBVRlc3QzIAEoATACEAIYASAA";
    let file = make_import_file("gauth-real", &format!("{uri}\n"));
    let (code, stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &["--stdin-password", "import", file_to_str(&file)],
    );

    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("新增 3"), "stdout: {stdout}");
    assert!(
        stdout.contains("安全提醒"),
        "迁移导入后必须提示删除原始二维码：{stdout}"
    );
    let (code, stdout, _e) = run_2fa(&vault, "测试密码123\n", &["--stdin-password", "status"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("条目数量：3"), "stdout: {stdout}");
    let (code, stdout, _e) = run_2fa(&vault, "测试密码123\n", &["--stdin-password", "list"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Test1"), "列表应含 Test1：{stdout}");
    assert!(stdout.contains("test1@example1.com"), "stdout: {stdout}");

    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_file(&file).unwrap();
}

/// 迁移批次含 HOTP 条目：TOTP 正常导入、HOTP 拒绝并说明原因。
/// payload 为手工构造（secret "1234"/"5678"，类型分别 TOTP/HOTP）。
#[test]
fn 迁移uri导入_hotp条目拒绝() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    // 0A 16 <TOTP: secret=1234 name=GH:alice> 0A 14 <HOTP: secret=5678 name=GL:bob>
    let uri = "otpauth-migration://offline?data=ChYKBDEyMzQSCEdIOmFsaWNlIAEoATACChQKBDU2NzgSBkdMOmJvYiABKAEwAQ==";
    let file = make_import_file("gauth-hotp", &format!("{uri}\n"));
    let (code, stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &["--stdin-password", "import", file_to_str(&file)],
    );

    assert_eq!(code, 0, "单条失败不中断整批：stderr {stderr}");
    assert!(stdout.contains("新增 1"), "stdout: {stdout}");
    assert!(stdout.contains("失败 1"), "stdout: {stdout}");
    assert!(stderr.contains("HOTP"), "拒绝原因应说明 HOTP：{stderr}");
    let (code, stdout, _e) = run_2fa(&vault, "测试密码123\n", &["--stdin-password", "status"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("条目数量：1"), "只有 TOTP 入库：{stdout}");

    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_file(&file).unwrap();
}

/// 多批次迁移（batch_size=3, batch_index=2, batch_id=7）：进度提示 +
/// 安全提醒 + issuer 字段与 name 前缀一致不告警。
#[test]
fn 迁移uri导入_多批次进度提示() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    // <TOTP: secret=1234 name=Test:one issuer=Test> batch_size=3 batch_index=2 batch_id=7
    let uri = "otpauth-migration://offline?data=ChwKBDEyMzQSCFRlc3Q6b25lGgRUZXN0IAEoATACGAMgAigH";
    let file = make_import_file("gauth-batch", &format!("{uri}\n"));
    let (code, stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &["--stdin-password", "import", file_to_str(&file)],
    );

    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stderr.contains("迁移批次 3/3"), "stderr 应含进度：{stderr}");
    assert!(stderr.contains("batch_id 7"), "stderr: {stderr}");
    assert!(stdout.contains("新增 1"), "stdout: {stdout}");
    assert!(stdout.contains("安全提醒"), "stdout: {stdout}");
    assert!(
        !stderr.contains("issuer 冲突"),
        "issuer 一致不应告警：{stderr}"
    );

    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_file(&file).unwrap();
}

// ---------------------------------------------------------------------------
// 加密备份导出 / 导入（M4-3）
// ---------------------------------------------------------------------------

/// 导出加密备份再导入：条目级往返一致，导入后主密码为备份文件的主密码。
#[test]
fn 备份导出导入往返一致() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let backup = dir.join("backup.bin");

    // 添加条目 A 后导出（export backup 无需解锁，stdin 可为空）
    let (code, _stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &[
            "--stdin-password",
            "add",
            "GitHub",
            "alice",
            "JBSWY3DPEHPK3PXP",
        ],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    let (code, stdout, stderr) =
        run_2fa(&vault, "", &["export", "backup", backup.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("加密备份已导出"), "stdout: {stdout}");
    let exported = std::fs::read(&backup).unwrap();
    assert!(
        exported.starts_with(&two_fa_core::vault::MAGIC),
        "导出文件应是保险库字节级拷贝"
    );

    // 导出后再添加条目 B：当前保险库与备份产生差异
    let (code, _stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &["--stdin-password", "add", "GitLab", "bob", "MZXW6YTBOI"],
    );
    assert_eq!(code, 0, "stderr: {stderr}");

    // 导入备份：整体覆盖回导出时状态
    let (code, stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &[
            "--stdin-password",
            "import",
            backup.to_str().unwrap(),
            "--yes",
        ],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("加密备份导入完成：1 个条目"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("主密码与恢复码已替换"), "stdout: {stdout}");
    // 回滚保障：覆盖前的保险库已存入 .bak
    assert!(
        vault.with_file_name("vault.json.bak").exists(),
        "应产生 .bak"
    );

    // 条目级往返一致：只剩条目 A（用备份的主密码解锁验证）
    let (code, stdout, stderr) = run_2fa(&vault, "测试密码123\n", &["--stdin-password", "list"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("GitHub"), "stdout: {stdout}");
    assert!(stdout.contains("alice"), "stdout: {stdout}");
    assert!(
        !stdout.contains("GitLab"),
        "导入后条目 B 不应存在：{stdout}"
    );

    std::fs::remove_dir_all(&dir).unwrap();
}

/// 非交互导入加密备份无 --yes：报错要求显式确认，不改动保险库。
#[test]
fn 备份导入非交互需yes() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let backup = dir.join("backup.bin");
    let (code, _stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &[
            "--stdin-password",
            "add",
            "GitHub",
            "alice",
            "JBSWY3DPEHPK3PXP",
        ],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    let (code, _stdout, stderr) =
        run_2fa(&vault, "", &["export", "backup", backup.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");

    let before = std::fs::read(&vault).unwrap();
    let (code, _stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &["--stdin-password", "import", backup.to_str().unwrap()],
    );

    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stderr.contains("--yes"), "stderr 应要求 --yes：{stderr}");
    assert_eq!(
        std::fs::read(&vault).unwrap(),
        before,
        "未确认前保险库不应被改动"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// 备份主密码错误：退出码 2（认证失败），保险库不变。
#[test]
fn 备份导入密码错误退出码2() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let backup = dir.join("backup.bin");
    let (code, _stdout, stderr) =
        run_2fa(&vault, "", &["export", "backup", backup.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");

    let before = std::fs::read(&vault).unwrap();
    let (code, stdout, stderr) = run_2fa(
        &vault,
        "错误密码\n",
        &[
            "--stdin-password",
            "import",
            backup.to_str().unwrap(),
            "--yes",
        ],
    );

    assert_eq!(code, 2, "stderr: {stderr}");
    assert!(stdout.is_empty(), "失败时 stdout 应为空：{stdout}");
    assert!(stderr.contains("认证失败"), "stderr: {stderr}");
    assert_eq!(std::fs::read(&vault).unwrap(), before, "保险库不应被改动");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// 导出路径指向保险库本体：报错拒绝，避免覆盖保险库。
#[test]
fn 导出路径与保险库相同报错() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let (code, _stdout, stderr) =
        run_2fa(&vault, "", &["export", "backup", vault.to_str().unwrap()]);

    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stderr.contains("导出路径与保险库相同"), "stderr: {stderr}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// 当前保险库损坏时仍可从备份恢复：备份导入无需解锁当前保险库。
#[test]
fn 损坏保险库可从备份恢复() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let backup = dir.join("backup.bin");
    let (code, _stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &[
            "--stdin-password",
            "add",
            "GitHub",
            "alice",
            "JBSWY3DPEHPK3PXP",
        ],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    let (code, _stdout, stderr) =
        run_2fa(&vault, "", &["export", "backup", backup.to_str().unwrap()]);
    assert_eq!(code, 0, "stderr: {stderr}");

    // 模拟保险库损坏：覆盖为垃圾字节
    std::fs::write(&vault, b"corrupted").unwrap();

    let (code, stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &[
            "--stdin-password",
            "import",
            backup.to_str().unwrap(),
            "--yes",
        ],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("加密备份导入完成"), "stdout: {stdout}");

    // 恢复后条目可正常解锁与列出
    let (code, stdout, stderr) = run_2fa(&vault, "测试密码123\n", &["--stdin-password", "list"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("GitHub"), "stdout: {stdout}");
    assert!(stdout.contains("alice"), "stdout: {stdout}");

    std::fs::remove_dir_all(&dir).unwrap();
}

// ---------------------------------------------------------------------------
// 明文导出（危险出口，M4-4）
// ---------------------------------------------------------------------------

/// 明文导出：非交互无 --yes 拒绝执行，文件不落盘。
#[test]
fn 明文导出非交互需确认() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let (code, _stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &[
            "--stdin-password",
            "add",
            "GitHub",
            "alice",
            "JBSWY3DPEHPK3PXP",
        ],
    );
    assert_eq!(code, 0, "stderr: {stderr}");

    let plain = dir.join("plain.txt");
    let (code, _stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &[
            "--stdin-password",
            "export",
            "plain",
            plain.to_str().unwrap(),
        ],
    );

    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stderr.contains("--yes"), "stderr 应要求 --yes：{stderr}");
    assert!(!plain.exists(), "未通过确认时文件不应落盘");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// 明文导出 --yes：文件首行为警告注释、条目行数正确、完成提示含删除提醒；
/// 导出文本可被自家 import 无损往返（警告注释被忽略）。
#[test]
fn 明文导出确认与往返() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    for (issuer, account) in [("GitHub", "alice"), ("GitLab", "bob")] {
        let (code, _stdout, stderr) = run_2fa(
            &vault,
            "测试密码123\n",
            &[
                "--stdin-password",
                "add",
                issuer,
                account,
                "JBSWY3DPEHPK3PXP",
            ],
        );
        assert_eq!(code, 0, "stderr: {stderr}");
    }

    let plain = dir.join("plain.txt");
    let (code, stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &[
            "--stdin-password",
            "export",
            "plain",
            plain.to_str().unwrap(),
            "--yes",
        ],
    );

    // 门槛 4：完成即提示删除并说明未加密
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(
        stdout.contains("明文导出完成：2 个条目"),
        "stdout: {stdout}"
    );
    assert!(stdout.contains("未受任何加密保护"), "stdout: {stdout}");
    assert!(stdout.contains("删除"), "stdout 应含删除提醒：{stdout}");

    // 门槛 3：文件首行警告注释；随后每条目一行 URI
    let text = std::fs::read_to_string(&plain).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert!(
        lines[0].starts_with("# 警告："),
        "首行应为警告注释：{}",
        lines[0]
    );
    assert_eq!(lines.len(), 3, "警告行 + 2 个条目行");
    assert!(
        lines[1].starts_with("otpauth://totp/GitHub:alice?"),
        "{}",
        lines[1]
    );

    // 往返：新保险库导入明文文件（otpauth 文本通道），条目一致
    let (_dir2, vault2) = make_vault("另一密码456", "RECOVERYCODE4567");
    let (code, stdout, stderr) = run_2fa(
        &vault2,
        "另一密码456\n",
        &["--stdin-password", "import", plain.to_str().unwrap()],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("新增 2"), "stdout: {stdout}");
    let (code, stdout, stderr) = run_2fa(&vault2, "另一密码456\n", &["--stdin-password", "list"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("GitHub"), "stdout: {stdout}");
    assert!(stdout.contains("alice"), "stdout: {stdout}");
    assert!(stdout.contains("GitLab"), "stdout: {stdout}");
    assert!(stdout.contains("bob"), "stdout: {stdout}");

    std::fs::remove_dir_all(&dir).unwrap();
    std::fs::remove_dir_all(&_dir2).unwrap();
}

/// 空保险库明文导出：报错且不落盘。
#[test]
fn 明文导出空库报错() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let plain = dir.join("plain.txt");
    let (code, _stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &[
            "--stdin-password",
            "export",
            "plain",
            plain.to_str().unwrap(),
            "--yes",
        ],
    );

    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stderr.contains("保险库为空"), "stderr: {stderr}");
    assert!(!plain.exists(), "空库导出不应落盘");
    std::fs::remove_dir_all(&dir).unwrap();
}

// ---------------------------------------------------------------------------
// 二维码图片导入（M5-2）
// ---------------------------------------------------------------------------

/// 把内容编码为二维码 PNG（4 模块静区，8 倍放大）。
fn make_qr_png(dir: &Path, tag: &str, content: &str) -> PathBuf {
    use image::{GrayImage, Luma};
    let code = qrcode::QrCode::new(content.as_bytes()).unwrap();
    let width = code.width() as u32;
    let quiet = 4u32;
    let scale = 8u32;
    let size = (width + quiet * 2) * scale;
    let mut img = GrayImage::new(size, size);
    for y in 0..size {
        for x in 0..size {
            img.put_pixel(x, y, Luma([255]));
        }
    }
    for (i, c) in code.to_colors().iter().enumerate() {
        let mx = (i % width as usize) as u32 + quiet;
        let my = (i / width as usize) as u32 + quiet;
        let value = if *c == qrcode::types::Color::Dark {
            0
        } else {
            255
        };
        for dy in 0..scale {
            for dx in 0..scale {
                img.put_pixel(mx * scale + dx, my * scale + dy, Luma([value]));
            }
        }
    }
    let file = dir.join(format!("{tag}.png"));
    img.save(&file).unwrap();
    file
}

/// 二维码图片（otpauth 载荷）导入：条目入库可验证。
#[test]
fn 二维码图片导入otpauth() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let png = make_qr_png(
        &dir,
        "qr-otpauth",
        "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
    );

    let (code, stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &["--stdin-password", "import", file_to_str(&png)],
    );

    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("新增 1"), "stdout: {stdout}");
    let (code, stdout, _e) = run_2fa(&vault, "测试密码123\n", &["--stdin-password", "list"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("GitHub"), "stdout: {stdout}");
    assert!(stdout.contains("alice"), "stdout: {stdout}");

    std::fs::remove_dir_all(&dir).unwrap();
}

/// 二维码图片（GA 迁移载荷）导入：3 条目入库并提示删除原始二维码。
#[test]
fn 二维码图片导入迁移载荷() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let png = make_qr_png(
        &dir,
        "qr-migration",
        "otpauth-migration://offline?data=Ci0KCkhlbGxvId6tvu8SEnRlc3QxQGV4YW1wbGUxLmNvbRoFVGVzdDEgASgBMAIKLQoKSGVsbG8h3q2%2B8BISdGVzdDJAZXhhbXBsZTIuY29tGgVUZXN0MiABKAEwAgotCgpIZWxsbyHerb7xEhJ0ZXN0M0BleGFtcGxlMy5jb20aBVRlc3QzIAEoATACEAIYASAA",
    );

    let (code, stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &["--stdin-password", "import", file_to_str(&png)],
    );

    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("新增 3"), "stdout: {stdout}");
    assert!(
        stdout.contains("安全提醒"),
        "应提示删除原始迁移二维码：{stdout}"
    );
    let (code, stdout, _e) = run_2fa(&vault, "测试密码123\n", &["--stdin-password", "status"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("条目数量：3"), "stdout: {stdout}");

    std::fs::remove_dir_all(&dir).unwrap();
}

/// 图片中没有二维码：明确报错不 panic。
#[test]
fn 无二维码图片报错() {
    use image::{GrayImage, Luma};
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let blank = dir.join("blank.png");
    GrayImage::from_pixel(200, 200, Luma([255]))
        .save(&blank)
        .unwrap();

    let (code, _stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &["--stdin-password", "import", file_to_str(&blank)],
    );

    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stderr.contains("未找到二维码"), "stderr: {stderr}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// 导入文件不存在：明确提示路径。
#[test]
fn 导入文件不存在报错() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let missing = dir.join("no-such-file.txt");

    let (code, _stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &["--stdin-password", "import", file_to_str(&missing)],
    );

    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stderr.contains("导入文件不存在"), "stderr: {stderr}");
    std::fs::remove_dir_all(&dir).unwrap();
}

// ---------------------------------------------------------------------------
// REPL 非交互防护（e2e 发现：rpassword 直读控制台，管道重定向无效，
// unlock/import 备份在非交互管道下无限挂死）
// ---------------------------------------------------------------------------

/// REPL 在非交互管道下读密码不得挂死：应明确报错需要交互终端并退出。
#[test]
fn repl非交互读密码不挂死() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");

    // unlock 触发读密码：非交互下应报错退出（而非等待永不到来的控制台输入）
    let (code, stdout, stderr) = run_2fa(&vault, "unlock\nexit\n", &[]);
    assert_eq!(code, 1, "非交互读密码应报错退出：stdout: {stdout}");
    assert!(
        stderr.contains("交互终端"),
        "stderr 应说明需要交互终端：{stderr}"
    );
    // 报错经 stderr 输出，stdout 只有 REPL 启动横幅
    assert!(!stdout.contains("交互终端"), "错误不应走 stdout：{stdout}");

    std::fs::remove_dir_all(&dir).unwrap();
}

// ---------------------------------------------------------------------------
// ID 前缀自适应（e2e 发现：同毫秒批量导入的 v7 id 前 32 bit 全是时间戳，
// 固定 8 位前缀全同，show/del 无法定位）
// ---------------------------------------------------------------------------

/// 解析 list/find 输出各行的 ID 列（首个空白分隔字段）。
fn parse_id_column(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter(|l| {
            !l.trim().is_empty()
                && !l.contains("保险库：")
                && !l.contains("来源：")
                && !l.starts_with("ID")
        })
        .filter_map(|l| l.split_whitespace().next().map(str::to_string))
        .collect()
}

/// 批量导入同毫秒条目后：list 的 ID 列互异，且用列表前缀可唯一定位条目。
#[test]
fn 批量导入后id前缀自适应可定位() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    // GA 三批次真实样本：3 条目同一次导入、同毫秒创建
    let sample = dir.join("ga-3batch.txt");
    std::fs::write(
        &sample,
        "otpauth-migration://offline?data=Ci0KCkhlbGxvId6tvu8SEnRlc3QxQGV4YW1wbGUxLmNvbRoFVGVzdDEgASgBMAIKLQoKSGVsbG8h3q2%2B8BISdGVzdDJAZXhhbXBsZTIuY29tGgVUZXN0MiABKAEwAgotCgpIZWxsbyHerb7xEhJ0ZXN0M0BleGFtcGxlMy5jb20aBVRlc3QzIAEoATACEAIYASAA",
    )
    .unwrap();

    let (code, stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &["--stdin-password", "import", file_to_str(&sample), "--yes"],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("新增 3"), "stdout: {stdout}");

    // list 的 ID 列长度 > 8（8 位全是毫秒时间戳）且互异
    let (code, stdout, stderr) = run_2fa(&vault, "测试密码123\n", &["--stdin-password", "list"]);
    assert_eq!(code, 0, "stderr: {stderr}");
    let ids = parse_id_column(&stdout);
    assert_eq!(ids.len(), 3, "stdout: {stdout}");
    assert!(
        ids.iter().all(|id| id.len() > 8),
        "同毫秒导入后前缀应自动延长：{ids:?}"
    );
    let unique: std::collections::HashSet<&String> = ids.iter().collect();
    assert_eq!(unique.len(), 3, "前缀应互异：{ids:?}");

    // 用列表展示的前缀 show 唯一定位；del 亦然
    let pfx = ids[0].clone();
    let (code, stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &["--stdin-password", "show", &pfx, "--yes"],
    );
    assert_eq!(code, 0, "前缀 {pfx} 应可唯一定位，stderr: {stderr}");
    assert!(stdout.contains("条目 "), "stdout: {stdout}");
    let (code, stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &["--stdin-password", "del", &pfx, "--yes"],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    assert!(stdout.contains("已删除条目"), "stdout: {stdout}");

    // 歧义错误列出完整 UUID：短前缀 hit 多条时提示可操作
    let (code, _stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &["--stdin-password", "show", "0", "--yes"],
    );
    assert_eq!(code, 1, "空前缀应报歧义");
    let hex36 = stderr.matches('-').count();
    assert!(hex36 >= 4, "歧义提示应含完整 UUID（带连字符）：{stderr}");

    std::fs::remove_dir_all(&dir).unwrap();
}

// ---------------------------------------------------------------------------
// `code` 子命令（M7-1）：单条验证码脚本输出
// ---------------------------------------------------------------------------

/// `code <前缀>`：stdout 唯一行「验证码 剩余秒」（均为数字、空格分隔，
/// 供脚本直接取列）；保险库路径回显走 stderr，不污染 stdout。
#[test]
fn code子命令脚本输出() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let (_, add_out, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &[
            "--stdin-password",
            "add",
            "GitHub",
            "alice",
            "JBSWY3DPEHPK3PXP",
        ],
    );
    assert!(add_out.contains("已添加"), "stderr: {stderr}");
    let prefix = extract_id8(&add_out);

    let (code, stdout, stderr) = run_2fa(
        &vault,
        "测试密码123\n",
        &["--stdin-password", "code", &prefix],
    );
    assert_eq!(code, 0, "stderr: {stderr}");
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "stdout 应只有一行：{stdout}");
    let mut parts = lines[0].split(' ');
    let otp = parts.next().unwrap();
    assert!(
        otp.len() == 6 && otp.bytes().all(|b| b.is_ascii_digit()),
        "验证码应为 6 位数字：{stdout}"
    );
    let remain: u64 = parts.next().unwrap().parse().unwrap_or(0);
    assert!((1..=30).contains(&remain), "剩余秒数应在 1..=30：{stdout}");
    assert!(parts.next().is_none(), "行内不应有第三个字段：{stdout}");
    assert!(stderr.contains("保险库："), "路径回显应走 stderr：{stderr}");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `code`：前缀无匹配 → 退出码 1；空前缀命中多条 → 退出码 1 并列出候选。
#[test]
fn code子命令找不到与歧义() {
    let (dir, vault) = make_vault("测试密码123", "RECOVERYCODE1234");
    let password = "测试密码123\n";
    let (_, out1, _) = run_2fa(
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
    let (_, out2, _) = run_2fa(
        &vault,
        password,
        &[
            "--stdin-password",
            "add",
            "GitLab",
            "bob",
            "JBSWY3DPEHPK3PXP",
        ],
    );
    assert!(out1.contains("已添加") && out2.contains("已添加"));

    // 无匹配：退出码 1，stdout 干净
    let (code, stdout, stderr) =
        run_2fa(&vault, password, &["--stdin-password", "code", "ffffffff"]);
    assert_eq!(code, 1, "stderr: {stderr}");
    assert!(stdout.is_empty(), "失败时 stdout 应为空：{stdout}");
    assert!(stderr.contains("未找到条目"), "stderr: {stderr}");

    // 空前缀命中全部条目：报歧义并列出候选
    let (code, _stdout, stderr) = run_2fa(&vault, password, &["--stdin-password", "code", ""]);
    assert_eq!(code, 1, "空前缀应报歧义");
    assert!(stderr.contains("多个条目"), "stderr 应报歧义：{stderr}");

    std::fs::remove_dir_all(&dir).unwrap();
}
