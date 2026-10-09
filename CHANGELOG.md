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

### 📚 Docs 文档更新
- 初始化项目文档：PRD、实施计划、领域语言、五份 ADR、踩坑分析（含两轮文档审查修订）
