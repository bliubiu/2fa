# 更新日志

本文件记录 2FA 两步验证器的全部变更。版本号采用双轨制：标题左侧为 CalVer 主口径（`YYYY.MM.DD.MICRO`，用于 Git Tag），右侧为 SemVer 包管理器口径（对应 `Cargo.toml` 的 `version`，保持 `0.x`）。

## [2026.10.08.0] - 0.0.1

### ✨ New Features 新增功能
- 【工程骨架】建立 Cargo workspace：`two-fa-core`（库，模块 domain/vault/usecase）+ `two-fa-cli`（二进制 `2fa`）
- 【工程骨架】启用 workspace lints：`unsafe_code = "forbid"`、`clippy::unwrap_used`、`clippy::expect_used`
- 【工程骨架】锁定核心依赖（aes-gcm、argon2、hmac、sha1、sha2、data-encoding、zeroize、rand_core、getrandom、uuid、serde、serde_json、thiserror）与 CLI 依赖（clap、rpassword、rustyline），平台层按目标引入 libc / windows-sys
- 【工程骨架】建立 CI：`cargo fmt --check` / `cargo clippy` / `cargo test` / `cargo audit`，跑在 Windows 与 Linux
- 【算法内核】Base32 编解码与宽容解析（M1-1）：去除空白与多余填充、接受小写、拒绝非法字符与非法长度
- 【算法内核】TOTP 计算内核（M1-2）：RFC 4226 Appendix D 全部向量与 RFC 6238 Appendix B 三算法全时间点通过，动态截断按 RFC 4226 §5.3，非法位数立即报错
- 【算法内核】时间步计数器换算（M1-3）：整数除法 `floor(unix/period)` 防浮点精度丢失，`period = 0` 报错防除零
- 【算法内核】Steam Guard（M1-4）：5 位自定义字母表，独立 Python 参考实现交叉验证（FreeOTP 不支持 Steam 字母表，不能作验证对象）
- 【算法内核】otpauth URI 解析与序列化（M1-5）：issuer 冲突以 query 为准并警告、百分号解码、未知参数忽略、无 issuer 时用空前缀「:账号」保证往返
- 【保险库】密钥类型与随机源（M2-1）：`VaultKey`（32 字节零化包装）、`SecretKey`（Base32 文本零化包装），均禁 `Clone`/`Copy`、`Debug` 固定输出 `«已隐藏»`；随机数来自操作系统 CSPRNG
- 【保险库】KDF 版本查表（M2-2）：v1 = Argon2id / 19 MiB / 2 次 / 1 线程，静态查表不可运行时自定义，未知版本报错不降级；派生输出经 Python argon2-cffi（独立参考实现）交叉验证
- 【保险库】封套读写（M2-3）：78 字节布局（盐 16 + kdf_version 2 + nonce 12 + 密文 48），封套 AAD 只覆盖自身盐与 kdf_version，重写任一封套不影响另一封套；失败区分「认证失败」与「数据损坏」；aes-gcm 启用 zeroize feature 使 cipher 内部密钥材料用后零化
- 【保险库】文件格式与 AAD 组装（M2-4）：明文头部（magic「2FAVLT\0」+ schema_version + 封套列表 + nonce）整体作为正文 GCM 的 AAD；篡改头部任一字节必被拒；错误魔数报「这不是 2FA 保险库文件」；经变异验证确认 AAD 覆盖范围被测试锁定
- 【保险库】正文与条目模型（M2-5）：JSON 正文（schema_version/created_at/entries）；条目 id 用 UUID v7（时间有序）；`secret` 序列化直接引用零化缓冲、反序列化中间副本立即清零；`(issuer, account)` 归一化（大小写与空白不敏感）且允许同标识并存、提供显式查找；digits/period 解析与构造双端校验；Algorithm 增加规范名（SHA1/SHA256/SHA512）映射
- 【保险库】原子写入与文件锁（M2-6）：原子写入完整四步（临时文件 → fsync → rename → fsync 父目录），失败不伤目标并清理临时文件；文件锁采用 `O_EXCL` 锁文件 + PID 判活 + mtime 阈值接管（Windows 附加 DELETE_ON_CLOSE 崩溃自清），全程无 `unsafe`——实施计划原定的 LockFileEx/flock 与 `unsafe_code = "forbid"` 硬规则冲突，经确认改用此方案
- 【保险库】内存保护收口（M2-7）：密钥类型全部零化、禁 Clone、Debug 类型层面隐藏（已完成项审查确认）；内存锁按 ADR-0005 尽力而为语义实现为「不支持」薄层接入点，上层启动输出中文警告后继续，未来平台层可无感替换
- 【保险库】schema 迁移链（M2-8）：`schema_version` 单调递增，逐级纯函数迁移且每级入参必须是恰好该级版本（防跳级）；迁移前原始字节备份到 `.bak`、回写走原子写入，中断可回滚；低版本程序读高版本文件明确报错提示升级，绝不部分加载；无迁移路径的版本报错不静默
- 【保险库】解锁入口与 KDF 自动升级（M2-9）：逐封套尝试解封、首个成功者胜出；被使用封套 `kdf_version` 低于当前版本时用同一凭据按当前版本重新封存，并按新头部重算正文密文（主密钥与条目明文不变）；升级前备份 `.bak`、回写走原子写入；重写失败不阻断解锁、以 `UpgradeOutcome::Failed` 返回由上层警告；封套或正文版本比程序新时报错提示升级且不触碰文件，未知 KDF 版本绝不降级尝试
- 【CLI】参数解析与路径解析（M3-1）：`--vault` > 当前目录 `.2fa/vault.json` > 平台惯例路径三级解析，每条命令回显绝对路径与来源；`2fa init [--project]` 创建新保险库并执行首次设置（主密码确认 → 80 位 CSPRNG 恢复码 4×4 展示 → 首份加密备份字节拷贝 → 强制确认已保存），重复初始化明确拒绝，首次在 CWD 创建 `.2fa/` 显式提示；`$XDG_DATA_HOME` 未设置回退 `~/.local/share`；启动时按 ADR-0005 输出内存锁警告；`2fa status` 显示路径与来源
- 【CLI】REPL 交互框架（M3-2）：`rustyline` 驱动、提示符 `2fa> `；启动为锁定态，`unlock` 持有主密钥、`lock` 立即锁定清零；`--idle-timeout`（默认 5 分钟）空闲自动锁定；Ctrl-C / Ctrl-D / `exit` 退出时密钥经 `Drop` 无条件归零；每条命令回显保险库路径
- 【CLI】单次命令模式（M3-3）：`--stdin-password` 从 stdin 第一行读主密码（供脚本与管道，仅去行尾换行保留密码空格）；退出码约定 0 成功 / 1 一般错误 / 2 认证失败；stdout 只放命令输出、警告与日志走 stderr；`status` 升级为完整形态（路径、来源、条目数量、封套 KDF 版本，需解锁）；非交互且未给 `--stdin-password` 时立即报错不挂起；新增集成测试用真实二进制验证管道输出与退出码
- 【CLI】条目增删改查与展示（M3-4）：`list` 列出服务商、账号、当前验证码与剩余秒数；`find` 按服务商 / 账号 / 标签不区分大小写模糊搜索；`add` 支持算法 / 位数 / 周期 / 标签参数，同标识冲突时交互选择覆盖 / 并存 / 取消、非交互必须显式 `--overwrite` 或 `--keep-both`（二者互斥）；`edit` 仅更新给出的字段并做修改后整体校验；`del` 与 `show`（显示明文密钥）均需确认或 `--yes`；变更操作持跨进程文件锁、回写走原子写入且封套不变；列表禁止展示密钥；REPL 补齐同套条目命令（复用会话密钥不再重复输密码）并支持 `字段=值` 形式的 edit；新增增删改查全流程、重名冲突、危险操作确认三组集成测试
- 【CLI】watch 倒计时（M3-5）：REPL `watch [id前缀]` 循环刷新验证码与剩余秒数（唯一条目可省略前缀），回车原位重写单行不滚动、不打印重复日志；刷新点由 core 新增的 `Ticker` 调度器以固定增量推进（单调时钟对齐周期边界，唤醒误差被吸收不累积，经模拟 3 周期对齐测试验证）；睡眠按至多 100ms 分段以便及时响应 Ctrl-C 退出（引入 `ctrlc` 安全封装捕获控制台事件——相关 Win32/信号 API 均为 unsafe FFI，与 `unsafe_code = "forbid"` 冲突，且与 rustyline 的按键级捕获互不干扰）；重定向 stdout 时明确报错拒绝运行

### 📚 Docs 文档更新
- 初始化项目文档：PRD、实施计划、领域语言、五份 ADR、踩坑分析（含两轮文档审查修订）
