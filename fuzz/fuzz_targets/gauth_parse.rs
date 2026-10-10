//! fuzz 目标：`importexport::gauth::parse`（GA 迁移 URI 解析）。
//!
//! 项目唯一处理不可信外部输入的环节之一。验收标准：任何输入都不 panic，
//! 手写 varint 与 protobuf 跳过逻辑对截断、超长、非法输入必须全部返回错误。
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let input = std::str::from_utf8(data).unwrap_or("");
    let _ = two_fa_core::importexport::gauth::parse_uri(input);
});
