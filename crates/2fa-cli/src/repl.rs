//! 交互式 REPL（`2fa` 不带子命令时进入）。
//!
//! - `rustyline` 驱动，提示符 `2fa> `
//! - 启动时处于锁定状态，`unlock` 输入主密码后持有主密钥
//! - `lock` 立即锁定（密钥 `drop` 清零）；空闲超时自动锁定
//! - Ctrl-C / Ctrl-D / `exit` 退出进程，`Drop` 无条件归零
//!
//! 每条命令输出都回显保险库路径（`docs/adr/0004`）。

use std::path::Path;
use std::time::Duration;

use rustyline::DefaultEditor;
use rustyline::error::ReadlineError;
use two_fa_core::vault::{
    Entry, UnlockError, UpgradeOutcome, VaultBody, VaultKey, load_and_migrate, unlock,
};

use crate::commands::{self, AddArgs, EditArgs};
use crate::paths::ResolvedVault;
use crate::session::Session;

/// 单条命令的处理结果。
enum Flow {
    /// 继续下一轮。
    Continue,
    /// 退出 REPL。
    Exit,
}

/// 运行 REPL，正常退出返回 `Ok(())`。
pub fn run(vault: &ResolvedVault, idle_timeout: Duration) -> Result<(), String> {
    let mut rl = DefaultEditor::new().map_err(|e| format!("初始化交互输入失败：{e}"))?;
    let mut session = Session::new(idle_timeout);

    println!("2FA 两步验证器（完全离线）");
    println!("保险库：{}", vault.path.display());
    println!("来源：{}", vault.source.label());
    println!("输入 help 查看可用命令。");

    loop {
        if session.check_idle() {
            println!("已因空闲超时自动锁定。");
        }
        match rl.readline("2fa> ") {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(line);
                match dispatch(&mut session, line, vault)? {
                    Flow::Continue => {}
                    Flow::Exit => break,
                }
            }
            Err(ReadlineError::Interrupted) => {
                // Ctrl-C：退出，密钥随进程结束经 Drop 归零
                println!();
                break;
            }
            Err(ReadlineError::Eof) => {
                println!();
                break;
            }
            Err(err) => return Err(format!("读取输入失败：{err}")),
        }
    }
    println!("再见。");
    Ok(())
}

/// 解析并执行一条 REPL 命令。
fn dispatch(session: &mut Session, line: &str, vault: &ResolvedVault) -> Result<Flow, String> {
    let mut parts = line.split_whitespace();
    let cmd = parts.next().unwrap_or("");
    match cmd {
        "help" | "?" => {
            print_help();
        }
        "lock" => {
            if session.lock() {
                println!("已锁定，密钥已从内存清零。");
                log::info!("会话已手动锁定");
            } else {
                println!("当前已是锁定状态。");
            }
        }
        "unlock" => {
            cmd_unlock(session, vault)?;
        }
        "list" => {
            require_unlocked(session, vault)?;
            let key = session_key(session)?;
            let body = load_body(vault, key)?;
            commands::op_list(vault, &body).map_err(|e| e.to_string())?;
        }
        "find" => {
            let query = parts.next().unwrap_or("");
            if query.is_empty() {
                return Err("用法：find <关键词>".to_string());
            }
            require_unlocked(session, vault)?;
            let key = session_key(session)?;
            let body = load_body(vault, key)?;
            commands::op_find(vault, &body, query).map_err(|e| e.to_string())?;
        }
        "add" => {
            // 用法：add <服务商> <账号> <Base32密钥>（高级字段用 edit 调整）
            let mut values = parts;
            let (issuer, account, secret) = match (values.next(), values.next(), values.next()) {
                (Some(i), Some(a), Some(s)) => (i, a, s),
                _ => return Err("用法：add <服务商> <账号> <Base32密钥>".to_string()),
            };
            if values.next().is_some() {
                return Err("add 只接受三个参数，算法/位数/周期/标签请用 edit 修改".to_string());
            }
            require_unlocked(session, vault)?;
            let key = session_key(session)?;
            let mut body = load_body(vault, key)?;
            let mut args = AddArgs {
                issuer: issuer.to_string(),
                account: account.to_string(),
                secret: secret.to_string(),
                ..AddArgs::default()
            };
            // REPL 内是交互环境：同标识冲突时提示选择
            commands::op_add(vault, key, &mut body, &mut args, true).map_err(|e| e.to_string())?;
        }
        "edit" => {
            let mut values = parts;
            let prefix = values.next().unwrap_or("");
            if prefix.is_empty() {
                return Err("用法：edit <id前缀> [字段=值 ...]（字段：issuer/account/secret/algorithm/digits/period/tags）".to_string());
            }
            let args = parse_kv_pairs(values)?;
            require_unlocked(session, vault)?;
            let key = session_key(session)?;
            let mut body = load_body(vault, key)?;
            commands::op_edit(vault, key, &mut body, prefix, &args).map_err(|e| e.to_string())?;
        }
        "del" | "rm" => {
            let prefix = parts.next().unwrap_or("");
            if prefix.is_empty() {
                return Err("用法：del <id前缀>".to_string());
            }
            require_unlocked(session, vault)?;
            let key = session_key(session)?;
            let mut body = load_body(vault, key)?;
            // REPL 内是交互环境：删除需确认
            commands::op_del(vault, key, &mut body, prefix, false, true)
                .map_err(|e| e.to_string())?;
        }
        "show" => {
            let prefix = parts.next().unwrap_or("");
            if prefix.is_empty() {
                return Err("用法：show <id前缀>".to_string());
            }
            require_unlocked(session, vault)?;
            let key = session_key(session)?;
            let body = load_body(vault, key)?;
            // REPL 内是交互环境：显示明文密钥需确认
            commands::op_show(vault, &body, prefix, false, true).map_err(|e| e.to_string())?;
        }
        "watch" => {
            // 用法：watch [id前缀]（唯一条目时可省略）
            let prefix = parts.next().unwrap_or("");
            require_unlocked(session, vault)?;
            let key = session_key(session)?;
            let body = load_body(vault, key)?;
            let entry = select_watch_entry(&body, prefix)?;
            commands::op_watch(entry).map_err(|e| e.to_string())?;
        }
        "recover" => {
            // 忘主密码场景：不要求已解锁，恢复码本身就是身份凭证
            commands::cmd_recover(vault).map_err(|e| e.to_string())?;
        }
        "import" => {
            // 用法：import <文件>（自动识别 otpauth 文本 / GA 迁移 URI /
            // 二维码图片 / 加密备份）
            let file = parts.next().unwrap_or("");
            if file.is_empty() {
                return Err("用法：import <文件>".to_string());
            }
            if parts.next().is_some() {
                return Err("import 只接受一个参数：文件路径".to_string());
            }
            let payload =
                commands::classify_import_file(Path::new(file)).map_err(|e| e.to_string())?;
            match payload {
                commands::ImportPayload::Backup(raw) => {
                    // 加密备份：无需解锁当前保险库（备份导入的典型场景正是
                    // 当前保险库损坏或忘记主密码）；保险库被整体替换，旧会话密钥失效
                    let password = rpassword::prompt_password("备份文件的主密码：")
                        .map_err(|e| format!("读取密码失败：{e}"))?;
                    commands::import_backup_bytes(vault, &raw, &password, false, true)
                        .map_err(|e| e.to_string())?;
                    session.lock();
                    println!("保险库已被备份整体替换，当前会话已失效，请重新 unlock。");
                }
                commands::ImportPayload::Image(text) => {
                    println!("已从图片中解码出 otpauth 载荷，按文本批次导入。");
                    require_unlocked(session, vault)?;
                    let key = session_key(session)?;
                    let mut body = load_body(vault, key)?;
                    // REPL 内为交互环境：同标识不同密钥时逐条询问
                    commands::op_import(vault, key, &mut body, &text, false, false, true)
                        .map_err(|e| e.to_string())?;
                }
                commands::ImportPayload::Text(text) => {
                    require_unlocked(session, vault)?;
                    let key = session_key(session)?;
                    let mut body = load_body(vault, key)?;
                    // REPL 内为交互环境：同标识不同密钥时逐条询问
                    commands::op_import(vault, key, &mut body, &text, false, false, true)
                        .map_err(|e| e.to_string())?;
                }
            }
        }
        "export" => {
            // 用法：export backup <文件>（字节级拷贝，无需解锁）
            //       export plain <文件>（明文导出，需解锁 + 输入条目数确认）
            let file = match (parts.next(), parts.next(), parts.next()) {
                (Some(sub), Some(f), None) => (sub, f),
                _ => return Err("用法：export backup <文件> 或 export plain <文件>".to_string()),
            };
            let path = Path::new(file.1);
            match file.0 {
                "backup" => commands::cmd_export_backup(vault, path).map_err(|e| e.to_string())?,
                "plain" => {
                    require_unlocked(session, vault)?;
                    let key = session_key(session)?;
                    let body = load_body(vault, key)?;
                    // REPL 内为交互环境：输入条目数确认
                    commands::op_export_plain(vault, &body, path, false, true)
                        .map_err(|e| e.to_string())?;
                }
                other => {
                    return Err(format!("未知导出类型：{other}（可选 backup / plain）"));
                }
            }
        }
        "status" => {
            echo_vault(vault);
            println!(
                "状态：{}",
                if session.is_unlocked() {
                    "已解锁"
                } else {
                    "已锁定"
                }
            );
        }
        "exit" | "quit" | "q" => return Ok(Flow::Exit),
        _ => {
            echo_vault(vault);
            println!("未知命令：{cmd}。输入 help 查看可用命令。");
        }
    }
    Ok(Flow::Continue)
}

/// `unlock`：输入主密码解锁保险库。
fn cmd_unlock(session: &mut Session, vault: &ResolvedVault) -> Result<(), String> {
    if session.is_unlocked() {
        echo_vault(vault);
        println!("当前已是解锁状态。");
        return Ok(());
    }
    let password =
        rpassword::prompt_password("主密码：").map_err(|e| format!("读取密码失败：{e}"))?;
    match unlock(&vault.path, &password) {
        Ok((key, outcome)) => {
            session.unlock(key);
            echo_vault(vault);
            println!("已解锁。");
            log::info!("保险库已解锁（交互会话）");
            match outcome {
                UpgradeOutcome::NotNeeded => {}
                UpgradeOutcome::Upgraded => {
                    println!("封套 KDF 已自动升级到当前版本。");
                    log::info!("封套 KDF 已自动升级到当前版本");
                }
                UpgradeOutcome::Failed(err) => {
                    eprintln!("警告：KDF 自动升级失败（不影响本次使用）：{err}");
                    log::error!("KDF 自动升级失败（不影响本次使用）：{err}");
                }
            }
            Ok(())
        }
        Err(UnlockError::AuthFailed) => {
            eprintln!("认证失败：密码或恢复码错误。");
            Ok(())
        }
        Err(err) => Err(err.to_string()),
    }
}

/// 回显保险库路径（每条命令都必须）。
fn echo_vault(vault: &ResolvedVault) {
    println!("保险库：{}", vault.path.display());
}

/// 条目命令前置：未解锁时引导解锁，解锁被取消/失败则中断命令。
fn require_unlocked(session: &mut Session, vault: &ResolvedVault) -> Result<(), String> {
    if !session.is_unlocked() {
        cmd_unlock(session, vault)?;
    }
    if !session.is_unlocked() {
        return Err("命令需要先解锁保险库（unlock）".to_string());
    }
    Ok(())
}

/// 取用会话密钥（`require_unlocked` 之后调用，必然存在）。
fn session_key(session: &mut Session) -> Result<&VaultKey, String> {
    session
        .key()
        .ok_or_else(|| "命令需要先解锁保险库（unlock）".to_string())
}

/// 用会话密钥加载保险库正文（含 schema 迁移）。
fn load_body(vault: &ResolvedVault, key: &VaultKey) -> Result<VaultBody, String> {
    load_and_migrate(&vault.path, key)
        .map(|(body, _)| body)
        .map_err(|e| format!("加载保险库失败：{e}"))
}

/// 选出 watch 的目标条目：无前缀时仅唯一条目可省略指定。
fn select_watch_entry<'a>(body: &'a VaultBody, prefix: &str) -> Result<&'a Entry, String> {
    if prefix.is_empty() {
        return match body.entries.len() {
            0 => Err("保险库为空，无条目可 watch".to_string()),
            1 => Ok(&body.entries[0]),
            n => Err(format!(
                "保险库有 {n} 个条目，请指定 id 前缀（先 list 查看）"
            )),
        };
    }
    let idx = two_fa_core::usecase::entries::find_index_by_prefix(body, prefix)
        .map_err(|e| e.to_string())?;
    Ok(&body.entries[idx])
}

/// 解析 `字段=值` 参数对（edit 命令）。
fn parse_kv_pairs<'a>(pairs: impl Iterator<Item = &'a str>) -> Result<EditArgs, String> {
    let mut args = EditArgs::default();
    for pair in pairs {
        let Some((field, value)) = pair.split_once('=') else {
            return Err(format!("参数格式错误：{pair}（应为 字段=值）"));
        };
        if value.is_empty() {
            return Err(format!("字段 {field} 的值不能为空"));
        }
        match field {
            "issuer" => args.issuer = Some(value.to_string()),
            "account" => args.account = Some(value.to_string()),
            "secret" => args.secret = Some(value.to_string()),
            "algorithm" => args.algorithm = Some(value.to_string()),
            "digits" => {
                args.digits = Some(value.parse().map_err(|_| format!("位数无效：{value}"))?);
            }
            "period" => {
                args.period = Some(value.parse().map_err(|_| format!("周期无效：{value}"))?);
            }
            "tags" => args.tags = Some(value.to_string()),
            _ => {
                return Err(format!(
                    "未知字段：{field}（可选 issuer/account/secret/algorithm/digits/period/tags）"
                ));
            }
        }
    }
    if args.issuer.is_none()
        && args.account.is_none()
        && args.secret.is_none()
        && args.algorithm.is_none()
        && args.digits.is_none()
        && args.period.is_none()
        && args.tags.is_none()
    {
        return Err("edit 至少需要一个 字段=值 参数".to_string());
    }
    Ok(args)
}

/// 帮助信息。
fn print_help() {
    println!("可用命令：");
    println!("  unlock                  解锁保险库（输入主密码或恢复码）");
    println!("  lock                    立即锁定并清零内存中的密钥");
    println!("  status                  显示保险库路径与锁定状态");
    println!("  list                    列出全部条目与当前验证码");
    println!("  find <关键词>           按服务商 / 账号 / 标签搜索");
    println!("  add <服务商> <账号> <密钥>");
    println!("                          添加条目（高级字段用 edit 调整）");
    println!("  edit <id前缀> [字段=值] 更新条目字段");
    println!("  del <id前缀>            删除条目（需确认）");
    println!("  show <id前缀>           显示详情与明文密钥（需确认）");
    println!("  watch [id前缀]          倒计时循环刷新验证码（Ctrl-C 退出）");
    println!("  recover                 忘记主密码：输入恢复码并轮换新码");
    println!("  import <文件>           导入条目 / 恢复备份 / 扫码导入（自动识别）");
    println!("  export backup <文件>    导出加密备份（保险库字节级拷贝，无需解锁）");
    println!("  export plain <文件>     明文导出 otpauth 文本（危险出口，需确认）");
    println!("  exit                    退出（或 Ctrl-D / Ctrl-C）");
}
