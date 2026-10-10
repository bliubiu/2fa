# 2FA 两步验证器

完全离线、本地加密的 TOTP 两步验证命令行工具。所有账号密钥存放在单个 AES-256-GCM 加密的 JSON 保险库文件中，全程不联网——代码中不存在任何网络调用路径。

## 特性

- **完全离线**：不上传任何数据，无云同步、无账号体系、无找回密码
- **强加密**：AES-256-GCM 认证加密，Argon2id 密钥派生（19 MiB / t=2 / p=1），全量内存零化，`unsafe_code = "forbid"`
- **双封套**：主密码 + 80 位随机恢复码各持一个独立封套，忘记主密码可凭恢复码恢复（恢复后旧码即刻作废并强制轮换）
- **多算法**：TOTP SHA1 / SHA256 / SHA512（RFC 4226 / RFC 6238 官方测试向量全通过）、6 位与 8 位、Steam Guard 自定义字母表
- **导入**：otpauth 文本、Google Authenticator 迁移二维码（protobuf 手写解析）、二维码图片（PNG/JPEG/GIF/WebP）、本工具自身的加密备份
- **导出**：加密备份（字节级拷贝）；明文 otpauth（四道门槛确认的危险出口）
- **fuzz 加固**：项目唯一处理不可信外部输入的两个解析器（otpauth URI、迁移 protobuf）纳入模糊测试

## 安装

需要 Rust 1.85+（MSRV）：

```bash
cargo build --release
# 二进制位于 target/release/2fa.exe（Windows）或 target/release/2fa（Unix）
```

## 快速开始

```bash
# 1. 初始化保险库（交互式：设置主密码 → 抄录恢复码 → 自动生成首份加密备份）
2fa init

# 2. 添加条目
2fa add GitHub alice JBSWY3DPEHPK3PXP --tags 工作,代码

# 3. 查看验证码
2fa list

# 4. 持续显示某个条目的倒计时（REPL 内）
2fa
2fa> watch

# 5. 搜索 / 详情 / 编辑 / 删除
2fa find git
2fa show <id前缀>          # 显示明文密钥需确认
2fa edit <id前缀> --issuer GitLab
2fa del <id前缀>
```

### 保险库路径

按以下优先级解析（每条命令都会回显当前使用的路径，防止在错误的保险库上操作）：

1. `--vault <路径>` 显式指定
2. 当前目录下的 `.2fa/vault.json`（项目级保险库）
3. 平台惯例路径（Windows `%APPDATA%\2fa\vault.json`，Unix 遵循 XDG）

## 恢复码（重要）

- `init` 时生成 80 位 CSPRNG 恢复码，以 4×4 展示并**强制确认已保存**
- 恢复码是**丢失主密码时的唯一恢复手段**，请抄写到纸上并妥善保管
- 忘记主密码时：

```bash
2fa recover     # 交互输入恢复码（不回显、不进 shell 历史）
```

- 恢复成功后旧恢复码**立即作废**，必须保存展示的新恢复码
- 随时可重新轮换：`2fa recover`（用当前有效的恢复码或主密码进入）

## 脚本与管道

```bash
# --stdin-password 从 stdin 第一行读主密码（供脚本使用，仅去行尾换行）
echo "主密码" | 2fa --stdin-password status
```

退出码约定：`0` 成功、`1` 一般错误、`2` 认证失败。stdout 只放命令输出，警告与日志走 stderr。

## 导入与导出

```bash
# 导入（自动识别格式：加密备份 / 二维码图片 / otpauth 文本 / GA 迁移 URI）
2fa import 某备份.json
2fa import 二维码截图.png
2fa import otpauth.txt

# 导出加密备份（字节级拷贝，无需解锁）
2fa export backup 备份.json

# 明文导出（危险：四道门槛确认，导出后请立即删除）
2fa export plain 明文导出.txt
```

- 加密备份导入后，当前保险库的主密码与恢复码即为**备份文件中的凭据**
- GA 迁移导入完成后，请立即删除原始迁移二维码截图（载荷中的密钥为明文形式）

## 开发

```bash
cargo test                    # 全部测试（core 181 单测 + CLI 单测/集成）
cargo clippy --all-targets    # 静态检查（unwrap/expect 禁用）
cargo fmt --check             # 格式
cargo audit                   # 漏洞审计
cargo deny check              # 供应链准入（license/来源/yanked）
```

fuzz 位于独立 workspace `fuzz/`（Linux 下 `cargo fuzz run <target>`；Windows 用 `smoke_run` 确定性长跑替代），CI 每周定时执行。详细格式规格见 [`docs/04-保险库格式.md`](./docs/04-保险库格式.md)，架构决策见 [`docs/adr/`](./docs/adr/)。

## 许可

MIT OR Apache-2.0
