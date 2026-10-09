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
