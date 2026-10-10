//! 本地 60 秒冒烟长跑：Windows 无法运行 cargo-fuzz（MSVC 链接器不支持
//! sancov section 边界符号，ASan 动态运行时亦缺失），本工具用确定性 PRNG
//! 对语料种子做随机变异后喂两个解析器，作为「连续 60 秒无崩溃」的本地
//! 验收替代。CI（Linux）上仍以 cargo fuzz 为准。

use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use two_fa_core::domain::otpauth;
use two_fa_core::importexport::gauth;

/// xorshift64*：确定性、可复现，只用于测试变异，不用于任何安全场景。
struct Prng(u64);

impl Prng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

/// 每轮随机变异 1~8 处：改字节 / 字节加一 / 插入 / 删除。
fn mutate(prng: &mut Prng, seed: &mut Vec<u8>) {
    for _ in 0..(prng.below(8) + 1) {
        if seed.is_empty() {
            return;
        }
        let i = prng.below(seed.len());
        match prng.below(4) {
            0 => seed[i] = (prng.next() & 0xff) as u8,
            1 => seed[i] = seed[i].wrapping_add(1),
            2 => seed.insert(i, (prng.next() & 0xff) as u8),
            _ => {
                seed.remove(i);
            }
        }
    }
}

fn main() {
    let corpus = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus");
    let mut seeds: Vec<Vec<u8>> = Vec::new();
    for target in ["otpauth_parse", "gauth_parse"] {
        let dir = corpus.join(target);
        for entry in fs::read_dir(&dir).unwrap_or_else(|e| panic!("读取语料目录失败：{e}")) {
            let path = entry.unwrap_or_else(|e| panic!("遍历语料失败：{e}")).path();
            if path.is_file() {
                seeds.push(fs::read(&path).unwrap_or_else(|e| panic!("读取种子失败：{e}")));
            }
        }
    }
    assert!(!seeds.is_empty(), "语料目录为空");

    let mut prng = Prng(0x2FA_2026_1010_0001);
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut rounds = 0u64;
    while Instant::now() < deadline {
        let mut input = seeds[prng.below(seeds.len())].clone();
        mutate(&mut prng, &mut input);
        // 解析器对任何输入只允许返回 Err，不允许 panic
        let text = String::from_utf8_lossy(&input);
        let _ = otpauth::parse(&text);
        let _ = gauth::parse_uri(&text);
        rounds += 1;
    }
    println!("冒烟长跑完成：60 秒内 {rounds} 轮，无 panic、无崩溃。");
}
