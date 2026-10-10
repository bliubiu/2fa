//! fuzz 目标：`domain::otpauth::parse`。
//!
//! 项目唯一处理不可信外部输入的环节之一。验收标准：任何输入都不 panic，
//! 解析成功与否只通过返回值表达。
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 二维码载荷本质是文本：非 UTF-8 输入等价于乱码 URI，按空串处理即可
    let input = std::str::from_utf8(data).unwrap_or("");
    let _ = two_fa_core::domain::otpauth::parse(input);
});
