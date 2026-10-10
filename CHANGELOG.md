# 更新日志

本文件记录 2FA 两步验证器的全部变更。版本号采用双轨制：标题左侧为 CalVer 主口径（`YYYY.MM.DD.MICRO`，用于 Git Tag），右侧为 SemVer 包管理器口径（对应 `Cargo.toml` 的 `version`，保持 `0.x`）。

## [2026.10.10.0] - 0.0.1

### 🔒 Hardening 加固发布（M6）

- 【加固】供应链准入与每周 fuzz 进 CI（M6-1）：新增 `deny.toml`（cargo-deny 0.20）——漏洞通告发现即失败、yanked 阻断、license 白名单（仅宽松协议准入）、来源白名单（仅 crates.io，杜绝不明 git 依赖）；CI 新增 `cargo deny check` 步骤（与既有 cargo-audit 并行双闸，RUSTSEC 高危阻断合并）；唯一豁免 lru unsound 通告（RUSTSEC-2026-0253，rqrr 传递依赖锁定 0.16 无升级路径；触发条件为 unwind panic + `catch_unwind`，本项目 `unsafe_code = forbid` 且无 `catch_unwind`，待 rqrr 升级后移除）；新增每周定时 fuzz workflow（周一 03:30 UTC，Linux runner 跑 otpauth_parse 与 gauth_parse 各 5 分钟，崩溃样本上传工件），落实 M5-3「主分支不跑 fuzz、CI 每周定时」约定；workspace 与两个 crate 补 `license = "MIT OR Apache-2.0"` 字段（cargo-deny 要求 manifest 声明协议）；本地 `cargo deny check` 四项（advisories/bans/licenses/sources）全过
- 【加固】全量脱敏审查（M6-2，人工 review + 检索）：19 处日志调用参数全部为服务商/账号/计数/耗时（无密钥、密码、otpauth URI）；生产代码零 `panic!`/`assert!`（仅测试与 fuzz 工具自身）；错误消息仅含解码位置与非法参数片段（algorithm/digits/period 等，不含 secret 参数）；`VaultKey`/`SecretKey` 的 `Debug` 在类型层固定输出 `«已隐藏»`（单测锁定）；明文密钥的 stdout 暴露仅两处设计允许点——`show`（需确认或 `--yes`）与明文导出（四道门槛）；日志文件脱敏已由 M3-7 集成测试持续保障（检索无密钥/密码/otpauth）
- 【加固】首次设置后全链路演练（M6-6，Windows 实机）：模拟 init 产物后逐步走通 status（路径回显/来源/条目数/KDF 版本）→ add（ID 前缀告知）→ list（表格含验证码与剩余秒数）→ find 模糊搜索 → show --yes（完整详情含明文密钥）→ export backup（字节级拷贝提示）→ 错误密码（退出码 2、明确「认证失败」不误导）→ del --yes → 空态 status → 从加密备份 import --yes 一键恢复（条目原样回归）——全程无阻断、每步回显当前保险库路径、错误提示可操作；REPL 收到 exit 干净退出；init 与 recover 的交互段（主密码确认、恢复码强制确认）需真实终端，核心逻辑已由集成测试覆盖，未在本环境重复验证
- 【加固】性能实测对照 PRD §5.2 全部指标（M6-4，Windows 实机 release 构建）：冷启动到提示符 53–67 ms（目标 <100 ms）、主密码解锁含 Argon2id 80–90 ms（目标 <500 ms）、1000 条目 `list` 渲染（差分法剥离解锁与进程启动开销）约 18 ms（目标 <50 ms）、单条 TOTP 计算 0.30 µs（目标 <10 µs，`2fa bench` 1000 次均值）、5000 条目保险库（实测 930 KB）字节级备份 65–76 ms（目标 <200 ms）——五项全部达标；注意 bench 与实测必须用 release 构建（dev profile 下 KDF 与 TOTP 数值失真约 20–40 倍，不能作为性能结论依据）
- 【加固】修正 `DynamicImage` 未使用导入泄漏到普通构建（仅测试使用，移入 tests 模块）

### 📚 Docs 文档更新
- 初始化项目文档：PRD、实施计划、领域语言、五份 ADR、踩坑分析（含两轮文档审查修订）

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
- 【CLI】恢复码恢复与轮换（M3-6）：`2fa recover` 与 REPL `recover` 交互式提示输入恢复码（rpassword 不回显，不经行内参数，避免凭据进入 shell 历史与终端回滚），验证通过后强制轮换——生成新 80 位恢复码、重写命中的恢复码封套并按新头部重算正文密文（条目明文不变）、打印新码并强制确认已保存，旧码即刻作废；core 新增 `vault::rotate_recovery`：轮换前原始字节备份 `.bak`、回写走原子写入，中断（进程被杀 / 写入失败）时原文件完好、旧码仍可用；测试覆盖轮换后旧码对所有封套解封必失败、新码解出同一主密钥、主密码封套字节不变、错误旧码认证失败文件不变
- 【CLI】日志与辅助命令（M3-7）：新增 `log` facade（0.4.28 起 default feature 被移除，显式启用 std）与自实现日志器（stderr 主通道，格式 `[YYYY-MM-DD HH:MM:SS.SSS] [级别] [进程ID] [模块:行号] - 内容`），默认仅 stderr 不落盘；`--log-level`（DEBUG/INFO/ERROR，默认 INFO）与 `RUST_LOG`（合法值优先）控制级别；`--log-to-file` 显式开启平台日志目录（Windows `%LOCALAPPDATA%\2fa\logs`，Unix `$XDG_STATE_HOME/2fa/logs` 回退 `~/.local/state`）按日轮转、保留 7 天（引入 `chrono` 纯 Rust 时间库处理本地时区换算与日期运算——手写时区换算必然出错）；关键操作接入日志（解锁、KDF 升级、条目增删改、恢复码轮换），凭据类数据一律不进日志参数；`2fa logs purge` 手动清理过期日志；`2fa bench` 报告 Argon2id KDF 派生（3 次均值）与单次 TOTP 计算（1000 次均值）耗时，供性能指标复核；集成测试验证默认运行零落盘、日志文件检索无密钥/密码/otpauth、purge 只删过期文件、bench 输出可读
- 【导入导出】otpauth 文本导入（M4-1）：core 新增 `importexport::otpauth_text` 批次解析——逐行解析 otpauth URI 并构造条目，空行与 `#` 注释行忽略，单行失败不影响其余行（返回逐行成败报告），行数上限 10000 防畸形输入拖垮解析，issuer 冲突警告随行透传；CLI 新增 `2fa import <文件>`（自动识别 otpauth 文本，GA 迁移与加密备份随 M4-2/M4-3 接入）与 REPL `import <文件>`；归并语义与 `add` 一致——归一化同标识且密钥相同跳过提示、密钥不同交互选择覆盖/并存/跳过，非交互必须显式 `--overwrite` 或 `--keep-both`（互斥校验），默认安全跳过；统计「新增/覆盖/并存/跳过重复/跳过冲突/失败」并在有变更时持锁原子回写；集成测试覆盖混合批次（成功与失败逐行报告）、重复导入幂等跳过、冲突三态处理与互斥参数校验
- 【导入导出】Google 迁移二维码解析（M4-2）：core 新增 `importexport::gauth`——解析 `otpauth-migration://offline?data=<base64(protobuf)>`（社区逆向 unofficial schema，来源 alexbakker.me 逆向文章与 qistoph/otp_export 的 proto 定义），按项目约束不引 protobuf 生成库、varint 手写解码；宽容输入处理（data 参数原文 Base64 优先、失败再百分号解码重试，兼容 GA 原生与第三方工具导出；尾部 `=` 填充可省略）；畸形输入全部返回错误而非 panic（截断 varint、错误 wire 类型、非法 UTF-8、超长输入 8KB/载荷 64KB 上限），未知字段按 wire 类型跳过（前向兼容 GA 新增字段），已知字段类型错误明确报错；HOTP 条目逐条拒绝（中文说明原因，不影响同批 TOTP），MD5 算法拒绝，period 一律 30；issuer 取独立字段（与 GA 行为一致），name 无冒号时整体作账号，name 前缀与字段冲突时告警；迁移载荷中的密钥原始字节进入 `SecretKey::from_bytes` 零化管辖；多批次（batch_size>1）逐张导入并提示「迁移批次 i/n」进度，导入完成提示用户立即删除原始迁移二维码（载荷密钥为明文）；`import` 命令升级为统一分派器（`importexport::parse_any_batch`）自动识别行格式，otpauth 文本与迁移 URI 可混装；测试固件含 3 组公开技术文章/项目中的真实 GA 导出样本（totp-qr README、jimmy0w0.me、raphael.badia.cc，来源已写入测试注释）逐字段断言，另覆盖 HOTP 拒绝、未知字段、截断、非法 Base64、多批次进度等 22 项单元测试与 3 项集成测试
- 【导入导出】加密备份导出与导入（M4-3）：core 新增 `unlock_readonly` 只读解锁——验证凭据并解出正文但不写任何文件、不触发 KDF 升级（加密备份必须保持字节级原样，KDF 升级回写只应发生在保险库本体上），配套 `.bak` 路径函数 `backup_path` 改为公开；CLI 新增 `export backup <文件>`——保险库文件**字节级拷贝**（无转换层，PRD §4.5），无需解锁（拷贝的是密文），持锁防止拷贝到并发写坏的中间态，导出路径指向保险库本体时拒绝；`import` 升级为三格式分派（文件以保险库魔数 `2FAVLT\0` 开头即走备份通道）——备份导入**无需解锁当前保险库**（典型场景正是当前保险库损坏或忘记主密码），流程：只读验证备份凭据 → 显式确认覆盖（非交互必须 `--yes`）→ 当前保险库字节级存入 `.bak`（回滚保障）→ 原子写入备份字节 → 老 schema 自动走迁移链 → 条目数与备份时一致否则警告（防御性校验），导入后当前保险库的主密码与恢复码即备份文件中的凭据；REPL 接入 `export backup` 与备份导入通道（备份导入成功后会话密钥立即失效并提示重新 unlock，otpauth 文本通道不变）；集成测试覆盖字节级导出导入往返一致（含 .bak 产生与主密码切换验证）、非交互无 `--yes` 拒绝且文件不动、备份密码错误退出码 2、导出路径与保险库相同报错、损坏保险库从备份恢复
- 【导入导出】明文 otpauth 导出（M4-4 危险出口）：core 新增 `importexport::plain` 序列化——每条目一行 otpauth URI（复用 `domain::otpauth::to_uri`，空 issuer/账号按缺失处理生成空前缀「:账号」），文件首行写入中文警告注释（`#` 开头，与自家导入器兼容可无损往返；标签不含在 otpauth URI 中属格式固有限制）；CLI 新增 `export plain <文件>`，四道门槛缺一不可：①二次确认（交互输入当前条目数，`--yes` 为显式确认词通道，非交互且无确认词直接拒绝）②输出路径必须显式指定（clap 必选参数，无默认路径）③文件首行警告注释④导出完成后立即提示「未受任何加密保护，请尽快删除」；空保险库拒绝导出；REPL 接入 `export plain`（复用会话密钥不再重复输密码）；集成测试覆盖非交互无确认拒绝且文件不落盘、`--yes` 导出文件首行警告与条目行数、完成提示含删除提醒、明文文件经新保险库 import 往返条目一致、空库导出报错
- 【二维码】图片解码与载荷分派（M5-1 / M5-2）：core 新增 `qrcode` 模块（`rqrr` + `image` 纯 Rust 栈，仅启用 PNG/JPEG/GIF/WebP 后端，不引入 C/C++ 依赖）——`decode_first` 接收调用方读入的图片字节解码出二维码载荷（不碰文件 IO）；不可信输入校验门槛齐备：字节上限 16 MiB、像素总数上限约 4000×4000、格式白名单（魔数识别，白名单外格式与「根本不是图片」分别给出中文错误），图片损坏/无二维码/纠错耗尽均有可操作提示，任何畸形输入返回错误而非 panic；`looks_like_image` 供调用方做输入分派，`validate_payload` 校验载荷必须是 `otpauth://` 或 `otpauth-migration://`（其他载荷拒绝并截断展示前 32 字符）；`import` 命令升级为四通道自动识别（加密备份 → 二维码图片 → otpauth 文本，按魔数分派）：图片解码成功后按既有文本批次流程导入（otpauth 单条目与 GA 迁移多批次自动区分，迁移导入保留「立即删除原始二维码」提醒）；REPL `import` 同步接入；测试固件用 `qrcode` crate（dev-dependency，不进运行时）现场编码二维码图片，覆盖 PNG/JPEG/GIF/WebP 四格式解码、超大文件拒绝、超大像素拒绝、损坏文件不 panic、无二维码明确报错、魔数判断与载荷校验，集成测试覆盖 otpauth 图片导入、迁移图片导入（3 条目 + 安全提醒）、无二维码图片报错、文件不存在报错
- 【健壮性】fuzz 模糊测试工程（M5-3）：新增独立 workspace `fuzz/`（libfuzzer-sys，构建产物与崩溃样本不入库），覆盖项目**唯一处理不可信外部输入**的两个解析器——`otpauth_parse`（otpauth URI 解析）与 `gauth_parse`（Google 迁移 protobuf 手写解码）两个 fuzz target，语料库含 12 个英文命名种子（RFC 风格 URI、三算法向量、真实 GA 迁移样本、截断/非法 Base64/空数据等畸形输入）；本机 Windows 验收改跑 `smoke_run`（cargo-fuzz 的 libFuzzer 依赖 MSVC 不支持的 sancov section 边界符号、ASan 动态运行时 DLL 缺失，均无法运行）——确定性 xorshift64* PRNG 对语料做变异（改字节/加一/插入/删除各 1~8 处）60 秒长跑喂两个解析器，49 497 800 轮无 panic 无崩溃；fuzz targets 保留待 CI（Linux）每周定时执行

### 📚 Docs 文档更新
- 初始化项目文档：PRD、实施计划、领域语言、五份 ADR、踩坑分析（含两轮文档审查修订）
