//! 纯逻辑域：TOTP 与 Steam Guard 计算、Base32 编解码、条目模型、otpauth URI 解析。
//!
//! 本模块完全不碰 IO，不感知系统时间与环境变量；
//! 时间以计数器形式由调用方传入，一切输入均为显式参数。

pub mod base32;
pub mod counter;
pub mod totp;
