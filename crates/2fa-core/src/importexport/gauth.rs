//! Google Authenticator 迁移 URI 解析（M4-2）。
//!
//! GA「导出账号」生成 `otpauth-migration://offline?data=<base64(protobuf)>`，
//! 其中 protobuf 结构是社区逆向的 unofficial schema（见 alexbakker.me
//! 《Parsing the Google Authenticator backup QR code》与
//! qistoph/otp_export 的 `OtpMigration.proto`）：
//!
//! ```proto
//! message MigrationPayload {
//!   repeated OtpParameters otp_parameters = 1;
//!   optional int32 version = 2;
//!   optional int32 batch_size = 3;
//!   optional int32 batch_index = 4;
//!   optional int32 batch_id = 5;
//! }
//! message OtpParameters {
//!   optional bytes secret = 1;
//!   optional string name = 2;
//!   optional string issuer = 3;
//!   optional Algorithm algorithm = 4;   // 1=SHA1 2=SHA256 3=SHA512 4=MD5
//!   optional DigitCount digits = 5;     // 1=SIX 2=EIGHT
//!   optional OtpType type = 6;          // 1=HOTP 2=TOTP
//!   optional int64 counter = 7;
//! }
//! ```
//!
//! 按项目约束不引入 protobuf 生成库（不引 C/C++ 依赖链），varint 解码
//! 手写实现。安全边界：本模块是处理不可信外部输入的环节（M5 将纳入
//! fuzz），一切畸形输入必须返回错误而非 panic。

use zeroize::Zeroizing;

use crate::domain::counter::DEFAULT_PERIOD;
use crate::domain::totp::Algorithm;
use crate::vault::{Entry, SecretKey};

use super::otpauth_text::BatchItem;

/// 单条迁移 URI 输入上限（字节）。GA 每批最多 10 个条目，真实 URI
/// 约 1–2 KB，8 KB 上限既能容纳全部合法输入又能拦住畸形超长输入。
const MAX_URI_LEN: usize = 8192;

/// protobuf 载荷上限（字节），拦在 base64 解码之后、解析之前。
const MAX_PAYLOAD_LEN: usize = 64 * 1024;

/// 迁移 URI 解析错误。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GauthError {
    /// 输入超过长度上限。
    #[error("输入过长（上限 {MAX_URI_LEN} 字节）")]
    TooLong,
    /// scheme 不是 `otpauth-migration://`。
    #[error("这不是 otpauth-migration:// 迁移 URI")]
    NotMigration,
    /// URI 中没有 `data` 参数。
    #[error("迁移 URI 中缺少 data 参数")]
    MissingData,
    /// data 参数 Base64 解码失败。
    #[error("data 参数 Base64 解码失败：{0}")]
    InvalidBase64(String),
    /// protobuf 载荷超过大小上限。
    #[error("迁移载荷超过 {MAX_PAYLOAD_LEN} 字节上限")]
    PayloadTooLarge,
    /// protobuf 数据在字段中途截断。
    #[error("迁移载荷数据截断")]
    Truncated,
    /// varint 超过 64 位范围。
    #[error("迁移载荷 varint 超长")]
    VarintTooLong,
    /// 不支持的 wire 类型（含已废弃的 group）。
    #[error("迁移载荷含不支持的 wire 类型 {0}")]
    UnsupportedWire(u8),
    /// 已知字段携带了错误的 wire 类型。
    #[error("迁移载荷字段 {0} 的类型错误")]
    WrongWireType(u32),
    /// 字符串字段不是合法 UTF-8。
    #[error("迁移载荷字符串字段不是合法 UTF-8")]
    InvalidUtf8,
}

/// 解出的单个条目参数（枚举保留原始数值，语义转换在行级完成）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtpParameters {
    /// 密钥原始字节（零化管辖）。
    pub secret: Zeroizing<Vec<u8>>,
    /// 条目名（通常是「服务商:账号」或纯账号）。
    pub name: String,
    /// 服务商字段（可能为空）。
    pub issuer: String,
    /// 算法枚举原始值。
    pub algorithm: u32,
    /// 位数枚举原始值。
    pub digits: u32,
    /// 类型枚举原始值（1=HOTP 2=TOTP）。
    pub otp_type: u32,
    /// 计数器（仅 HOTP 有效，TOTP 忽略）。
    pub counter: i64,
}

/// 解出的迁移载荷。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationPayload {
    /// 全部条目参数。
    pub otp_parameters: Vec<OtpParameters>,
    /// schema 版本（真实样本为 1 或 2，本项目不据此分支）。
    pub version: i32,
    /// 总批次数。
    pub batch_size: i32,
    /// 当前批次下标（0 起始）。
    pub batch_index: i32,
    /// 批次标识（同一次导出的多张二维码共享）。
    pub batch_id: i32,
}

/// 解析单个迁移 URI，返回原始 protobuf 载荷。
pub fn parse_uri(uri: &str) -> Result<MigrationPayload, GauthError> {
    if uri.len() > MAX_URI_LEN {
        return Err(GauthError::TooLong);
    }
    let (scheme, rest) = uri.split_once("://").ok_or(GauthError::NotMigration)?;
    if !scheme.eq_ignore_ascii_case("otpauth-migration") {
        return Err(GauthError::NotMigration);
    }
    // data 参数提取：query 中第一个 `data=` 键。base64 字母表含 `+ / =`，
    // 真实 GA 导出不做 URL 编码直接放行；部分工具会做百分号编码，先按
    // 原文解码、失败再按百分号解码重试（两种来源都兼容）。
    let query = rest
        .split_once('?')
        .map(|(_, q)| q)
        .ok_or(GauthError::MissingData)?;
    let mut data: Option<String> = None;
    for pair in query.split('&') {
        if let Some(value) = pair.strip_prefix("data=") {
            data = Some(value.to_string());
            break;
        }
    }
    let data = data.ok_or(GauthError::MissingData)?;

    let raw = decode_data(&data)?;
    decode_payload(&raw)
}

/// data 参数两段式解码：原文 Base64 优先，失败再尝试百分号解码。
fn decode_data(data: &str) -> Result<Vec<u8>, GauthError> {
    if let Ok(raw) = base64_decode_lenient(data) {
        return Ok(raw);
    }
    let decoded = percent_decode(data).map_err(GauthError::InvalidBase64)?;
    base64_decode_lenient(&decoded).map_err(GauthError::InvalidBase64)
}

/// 宽容 Base64 解码：省略尾部填充合法（`BASE64_NOPAD` 对 2/3 字节余数
/// 与标准填充语义一致），中间出现 `=` 视为非法。
fn base64_decode_lenient(text: &str) -> Result<Vec<u8>, String> {
    let stripped = text.trim_end_matches('=');
    data_encoding::BASE64_NOPAD
        .decode(stripped.as_bytes())
        .map_err(|e| e.to_string())
}

/// 手写百分号解码（`%XX` 十六进制；非法序列报错）。
fn percent_decode(text: &str) -> Result<String, String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'%' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        let hex = bytes
            .get(i + 1..i + 3)
            .and_then(|h| std::str::from_utf8(h).ok())
            .and_then(|h| u8::from_str_radix(h, 16).ok())
            .ok_or_else(|| "非法百分号编码".to_string())?;
        out.push(hex);
        i += 3;
    }
    String::from_utf8(out).map_err(|_| "百分号解码结果不是合法 UTF-8".to_string())
}

// ---------------------------------------------------------------------------
// 手写 protobuf 解码（varint + length-delimited）
// ---------------------------------------------------------------------------

/// 字节游标读取器：全部读取越界返回 [`GauthError::Truncated`]，绝不 panic。
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    /// 读 varint（每字节低 7 位，最高位续位；最多 10 字节覆盖 u64）。
    fn read_varint(&mut self) -> Result<u64, GauthError> {
        let mut result: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            let Some(&byte) = self.data.get(self.pos) else {
                return Err(GauthError::Truncated);
            };
            self.pos += 1;
            let value = u64::from(byte & 0x7F);
            if shift < 64 {
                result |= value << shift;
            } else if value != 0 {
                return Err(GauthError::VarintTooLong);
            }
            if byte & 0x80 == 0 {
                return Ok(result);
            }
            shift = shift.checked_add(7).ok_or(GauthError::VarintTooLong)?;
        }
    }

    /// 读下一个字段标签（字段号 + wire 类型），数据耗尽返回 `None`。
    fn read_tag(&mut self) -> Result<Option<(u32, u8)>, GauthError> {
        if self.pos >= self.data.len() {
            return Ok(None);
        }
        let tag = self.read_varint()?;
        let field = u32::try_from(tag >> 3).map_err(|_| GauthError::VarintTooLong)?;
        if field == 0 {
            return Err(GauthError::UnsupportedWire(0));
        }
        Ok(Some((field, (tag & 0x7) as u8)))
    }

    /// 读 length-delimited 原始字节。
    fn read_bytes(&mut self) -> Result<&'a [u8], GauthError> {
        let len = self.read_varint()?;
        let end = self
            .pos
            .checked_add(len as usize)
            .ok_or(GauthError::Truncated)?;
        let slice = self.data.get(self.pos..end).ok_or(GauthError::Truncated)?;
        self.pos = end;
        Ok(slice)
    }

    /// 按 wire 类型跳过未知字段。
    fn skip(&mut self, wire: u8) -> Result<(), GauthError> {
        match wire {
            0 => {
                self.read_varint()?;
            }
            1 => {
                if self.data.len() - self.pos < 8 {
                    return Err(GauthError::Truncated);
                }
                self.pos += 8;
            }
            2 => {
                self.read_bytes()?;
            }
            5 => {
                if self.data.len() - self.pos < 4 {
                    return Err(GauthError::Truncated);
                }
                self.pos += 4;
            }
            other => return Err(GauthError::UnsupportedWire(other)),
        }
        Ok(())
    }
}

/// 解码 MigrationPayload 顶层消息。
pub fn decode_payload(bytes: &[u8]) -> Result<MigrationPayload, GauthError> {
    if bytes.len() > MAX_PAYLOAD_LEN {
        return Err(GauthError::PayloadTooLarge);
    }
    let mut reader = Reader::new(bytes);
    let mut payload = MigrationPayload {
        otp_parameters: Vec::new(),
        version: 0,
        batch_size: 0,
        batch_index: 0,
        batch_id: 0,
    };
    while let Some((field, wire)) = reader.read_tag()? {
        match (field, wire) {
            (1, 2) => {
                let sub = reader.read_bytes()?;
                payload.otp_parameters.push(decode_otp_parameters(sub)?);
            }
            (2, 0) => payload.version = reader.read_varint()? as i32,
            (3, 0) => payload.batch_size = reader.read_varint()? as i32,
            (4, 0) => payload.batch_index = reader.read_varint()? as i32,
            (5, 0) => payload.batch_id = reader.read_varint()? as i32,
            // 已知字段携带错误 wire 类型：数据已损坏，明确报错
            (1..=5, _) => return Err(GauthError::WrongWireType(field)),
            // 未知字段按 wire 类型跳过（前向兼容 GA 新增字段）
            (_, _) => reader.skip(wire)?,
        }
    }
    Ok(payload)
}

/// 解码 OtpParameters 子消息。
fn decode_otp_parameters(bytes: &[u8]) -> Result<OtpParameters, GauthError> {
    let mut reader = Reader::new(bytes);
    let mut params = OtpParameters {
        secret: Zeroizing::new(Vec::new()),
        name: String::new(),
        issuer: String::new(),
        algorithm: 0,
        digits: 0,
        otp_type: 0,
        counter: 0,
    };
    while let Some((field, wire)) = reader.read_tag()? {
        match (field, wire) {
            (1, 2) => {
                let raw = reader.read_bytes()?;
                params.secret = Zeroizing::new(raw.to_vec());
            }
            (2, 2) => params.name = read_string(&mut reader)?,
            (3, 2) => params.issuer = read_string(&mut reader)?,
            (4, 0) => params.algorithm = reader.read_varint()? as u32,
            (5, 0) => params.digits = reader.read_varint()? as u32,
            (6, 0) => params.otp_type = reader.read_varint()? as u32,
            (7, 0) => params.counter = reader.read_varint()? as i64,
            (1..=7, _) => return Err(GauthError::WrongWireType(field)),
            (_, _) => reader.skip(wire)?,
        }
    }
    Ok(params)
}

/// 读字符串字段并校验 UTF-8。
fn read_string(reader: &mut Reader<'_>) -> Result<String, GauthError> {
    let raw = reader.read_bytes()?;
    std::str::from_utf8(raw)
        .map(str::to_string)
        .map_err(|_| GauthError::InvalidUtf8)
}

// ---------------------------------------------------------------------------
// 行级解析：迁移 URI → 逐条目 BatchItem
// ---------------------------------------------------------------------------

/// 单行迁移解析的行级输出：条目结果 + 多批次进度说明。
#[derive(Debug)]
pub struct LineOut {
    /// 本行产出的条目结果（一个 URI 可含多个条目）。
    pub items: Vec<BatchItem>,
    /// 多批次进度说明（batch_size > 1 时给出，供调用方提示进度）。
    pub note: Option<String>,
}

/// 解析一行迁移 URI（供统一分派器逐行调用）。
///
/// 每个条目独立产出成功或失败：HOTP 条目被拒绝（项目刻意不支持，
/// 恢复后计数器必然落后于服务端），同批 TOTP 条目不受影响。
pub fn parse_uri_line(line: usize, uri: &str) -> LineOut {
    let mut items = Vec::new();
    let payload = match parse_uri(uri) {
        Ok(payload) => payload,
        Err(err) => {
            items.push(BatchItem::Failed {
                line,
                error: err.to_string(),
            });
            return LineOut { items, note: None };
        }
    };
    let note = (payload.batch_size > 1).then(|| {
        format!(
            "迁移批次 {}/{}（batch_id {}）",
            payload.batch_index + 1,
            payload.batch_size,
            payload.batch_id
        )
    });
    if payload.otp_parameters.is_empty() {
        items.push(BatchItem::Failed {
            line,
            error: "迁移载荷中没有条目".to_string(),
        });
        return LineOut { items, note };
    }
    for params in payload.otp_parameters {
        match convert_otp_parameters(&params) {
            Ok((entry, warnings)) => items.push(BatchItem::Ok {
                line,
                entry,
                warnings,
            }),
            Err(error) => items.push(BatchItem::Failed { line, error }),
        }
    }
    LineOut { items, note }
}

/// 从 name 与 issuer 字段推导 (issuer, account) 与警告。
///
/// 迁移 payload 的 issuer 是独立字段（对应 otpauth URI 中 query issuer
/// 优先的 GA 行为）：
/// - issuer 字段非空：account 取 name 去掉「前缀:」部分（无冒号时 name
///   整体是账号），name 前缀与字段值不一致时告警
/// - issuer 字段为空：name 按 otpauth label 规则拆分（无冒号整体作
///   issuer、账号为空）
fn entry_label(name: &str, issuer_field: &str) -> (String, String, Vec<String>) {
    let name = name.trim();
    if issuer_field.is_empty() {
        return match name.split_once(':') {
            Some((i, a)) => (i.trim().to_string(), a.trim().to_string(), Vec::new()),
            None => (name.to_string(), String::new(), Vec::new()),
        };
    }
    let mut warnings = Vec::new();
    let account = match name.split_once(':') {
        Some((path_issuer, account)) => {
            let path_issuer = path_issuer.trim();
            if !path_issuer.is_empty() && path_issuer != issuer_field {
                warnings.push(format!(
                    "issuer 冲突：条目名前缀「{path_issuer}」与 issuer 字段「{issuer_field}」不一致，以 issuer 字段为准"
                ));
            }
            account.trim().to_string()
        }
        None => name.to_string(),
    };
    (issuer_field.to_string(), account, warnings)
}

/// 枚举与类型校验后构造条目（period 一律 30，TOTP 无状态）。
/// 返回条目与解析警告（issuer 冲突）。
fn convert_otp_parameters(params: &OtpParameters) -> Result<(Entry, Vec<String>), String> {
    let (issuer, account, warnings) = entry_label(&params.name, &params.issuer);
    match params.otp_type {
        2 => {}
        1 => {
            return Err(format!(
                "HOTP 条目「{issuer}」不支持导入（本项目仅支持 TOTP）"
            ));
        }
        other => return Err(format!("条目「{issuer}」类型未知（{other}）")),
    }
    let algorithm = match params.algorithm {
        0 | 1 => Algorithm::Sha1,
        2 => Algorithm::Sha256,
        3 => Algorithm::Sha512,
        4 => return Err(format!("条目「{issuer}」使用 MD5 算法，不支持导入")),
        other => return Err(format!("条目「{issuer}」算法未知（{other}）")),
    };
    let digits = match params.digits {
        0 | 1 => 6,
        2 => 8,
        other => return Err(format!("条目「{issuer}」位数未知（{other}）")),
    };
    let secret = SecretKey::from_bytes(&params.secret)
        .map_err(|e| format!("条目「{issuer}」密钥非法：{e}"))?;
    let entry = Entry::new(
        issuer,
        account,
        secret,
        algorithm,
        digits,
        DEFAULT_PERIOD,
        Vec::new(),
    )
    .map_err(|e| format!("条目字段校验失败：{e}"))?;
    Ok((entry, warnings))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use data_encoding::BASE64;

    /// 把 protobuf 载荷编码为迁移 URI（测试构造输入用）。
    fn to_uri(payload: &[u8]) -> String {
        format!(
            "otpauth-migration://offline?data={}",
            BASE64.encode(payload)
        )
    }

    /// 构造一个最小 OtpParameters 子消息（枚举值显式传入）。
    fn otp_sub(secret: &[u8], name: &str, issuer: &str, otp_type: u32) -> Vec<u8> {
        otp_sub_full(secret, name, issuer, otp_type, 1, 1)
    }

    /// 同 [`Self::otp_sub`]，但算法与位数枚举可控。
    fn otp_sub_full(
        secret: &[u8],
        name: &str,
        issuer: &str,
        otp_type: u32,
        algorithm: u32,
        digits: u32,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        // field1 secret (wire 2)
        out.push(0x0A);
        out.push(secret.len() as u8);
        out.extend_from_slice(secret);
        // field2 name (wire 2)
        out.push(0x12);
        out.push(name.len() as u8);
        out.extend_from_slice(name.as_bytes());
        if !issuer.is_empty() {
            // field3 issuer (wire 2)
            out.push(0x1A);
            out.push(issuer.len() as u8);
            out.extend_from_slice(issuer.as_bytes());
        }
        // field4 algorithm、field5 digits、field6 type（全部 varint）
        out.extend_from_slice(&[
            0x20,
            algorithm as u8,
            0x28,
            digits as u8,
            0x30,
            otp_type as u8,
        ]);
        out
    }

    /// 包一层 MigrationPayload field1（wire 2）。
    fn wrap(sub: &[u8]) -> Vec<u8> {
        let mut out = vec![0x0A, sub.len() as u8];
        out.extend_from_slice(sub);
        out
    }

    /// 真实样本（来源：dfarnham/totp-qr 项目 README，其解码依赖
    /// alexbakker.me 的逆向 schema）：3 个 TOTP 条目，逐字段断言。
    #[test]
    fn 真实样本_三条件() {
        let uri = "otpauth-migration://offline?data=Ci0KCkhlbGxvId6tvu8SEnRlc3QxQGV4YW1wbGUxLmNvbRoFVGVzdDEgASgBMAIKLQoKSGVsbG8h3q2%2B8BISdGVzdDJAZXhhbXBsZTIuY29tGgVUZXN0MiABKAEwAgotCgpIZWxsbyHerb7xEhJ0ZXN0M0BleGFtcGxlMy5jb20aBVRlc3QzIAEoATACEAIYASAA";
        let payload = parse_uri(uri).unwrap();

        assert_eq!(payload.otp_parameters.len(), 3);
        assert_eq!(payload.version, 2);
        assert_eq!(payload.batch_size, 1);
        assert_eq!(payload.batch_index, 0);

        let first = &payload.otp_parameters[0];
        assert_eq!(
            first.secret.as_slice(),
            b"Hello!\xDE\xAD\xBE\xEF",
            "secret 为「Hello!」+ DEADBEEF 哨兵字节"
        );
        assert_eq!(first.name, "test1@example1.com");
        assert_eq!(first.issuer, "Test1");
        assert_eq!(first.otp_type, 2);
        let line = parse_uri_line(1, uri);
        assert_eq!(line.items.len(), 3);
        let BatchItem::Ok { entry, .. } = &line.items[0] else {
            panic!("应为成功项");
        };
        assert_eq!(entry.issuer, "Test1");
        assert_eq!(entry.account, "test1@example1.com");
        assert_eq!(entry.algorithm, Algorithm::Sha1);
        assert_eq!(entry.digits, 6);
        assert_eq!(entry.period, 30);
    }

    /// 真实样本（来源：jimmy0w0.me《处理 Google Authenticator 导出的
    /// QR Code》，2025-02 真实导出）：URL 编码（%2F %3D）、version=1、
    /// 10 字节负数 batch_id varint、条目外直接跟顶层字段。
    #[test]
    fn 真实样本_url编码与负数batch_id() {
        let uri = "otpauth-migration://offline?data=Ci8KCke7Wn1dzBf7B4QSG3RvdHBAYXV0aGVudGljYXRpb250ZXN0LmNvbSABKAEwAgoqChTjrWUfiCuBHIAj%2Br0YbS8oSrOLqBIMdGVzdC1hY2NvdW50IAEoATACEAEYASAAKNyAq4%2F4%2F%2F%2F%2F%2FwE%3D";
        let payload = parse_uri(uri).unwrap();

        assert_eq!(payload.otp_parameters.len(), 2);
        assert_eq!(payload.version, 1);
        assert_eq!(payload.batch_size, 1);
        assert_eq!(payload.batch_index, 0);
        // 负数 int32 编码为 10 字节 varint，按补码截断解释（-2115321764）
        assert_eq!(payload.batch_id, -2_115_321_764);
        let line = parse_uri_line(1, uri);
        assert_eq!(line.items.len(), 2);
        assert!(line.items.iter().all(|i| matches!(i, BatchItem::Ok { .. })));
    }

    /// 真实样本（来源：raphael.badia.cc《Extracting secrets from Google
    /// Authenticator export QR codes》真实导出）：单条目，issuer 字段
    /// 「CoinList」与无冒号 name 并存。
    #[test]
    fn 真实样本_单条目issuer字段() {
        let uri = "otpauth-migration://offline?data=CjMKD6NIo47vL9P5plq8l5KEhRIQcmFwaGFlbEBiYWRpYS5jYxoIQ29pbkxpc3QgASgBMAIQAhgBIAA%3D";
        let line = parse_uri_line(1, uri);
        let BatchItem::Ok {
            entry, warnings, ..
        } = &line.items[0]
        else {
            panic!("应为成功项");
        };
        assert_eq!(entry.issuer, "CoinList");
        assert_eq!(entry.account, "raphael@badia.cc");
        assert!(warnings.is_empty(), "issuer 字段与 name 无前缀时不告警");
    }

    /// issuer 字段优先于 name 前缀，冲突时告警。
    #[test]
    fn issuer字段优先与冲突告警() {
        let sub = otp_sub(b"1234", "GitHub:alice", "GitLab", 2);
        let line = parse_uri_line(1, &to_uri(&wrap(&sub)));
        let BatchItem::Ok {
            entry, warnings, ..
        } = &line.items[0]
        else {
            panic!("应为成功项");
        };
        assert_eq!(entry.issuer, "GitLab");
        assert_eq!(entry.account, "alice");
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("冲突"));
    }

    /// name 无冒号且无 issuer 字段：整个 name 作为 issuer，账号为空。
    #[test]
    fn name无冒号整体作issuer() {
        let sub = otp_sub(b"1234", "OnlyIssuer", "", 2);
        let line = parse_uri_line(1, &to_uri(&wrap(&sub)));
        let BatchItem::Ok { entry, .. } = &line.items[0] else {
            panic!("应为成功项");
        };
        assert_eq!(entry.issuer, "OnlyIssuer");
        assert_eq!(entry.account, "");
    }

    /// HOTP 条目（type=1）拒绝，错误信息说明原因。
    #[test]
    fn hotp条目拒绝() {
        let sub = otp_sub(b"1234", "GitHub:alice", "GitHub", 1);
        let line = parse_uri_line(1, &to_uri(&wrap(&sub)));
        let BatchItem::Failed { error, .. } = &line.items[0] else {
            panic!("应为失败项");
        };
        assert!(error.contains("HOTP"), "错误应说明 HOTP：{error}");
    }

    /// 未知类型（type=0）拒绝。
    #[test]
    fn 未知类型拒绝() {
        let sub = otp_sub(b"1234", "GitHub:alice", "", 0);
        let line = parse_uri_line(1, &to_uri(&wrap(&sub)));
        assert!(matches!(&line.items[0], BatchItem::Failed { .. }));
    }

    /// MD5 算法（枚举 4）拒绝。
    #[test]
    fn md5算法拒绝() {
        let sub = otp_sub_full(b"1234", "GitHub:alice", "", 2, 4, 1);
        let line = parse_uri_line(1, &to_uri(&wrap(&sub)));
        let BatchItem::Failed { error, .. } = &line.items[0] else {
            panic!("应为失败项");
        };
        assert!(error.contains("MD5"));
    }

    /// SHA256 与 8 位映射正确。
    #[test]
    fn 算法与位数枚举映射() {
        let sub = otp_sub_full(b"1234", "GitHub:alice", "", 2, 2, 2);
        let line = parse_uri_line(1, &to_uri(&wrap(&sub)));
        let BatchItem::Ok { entry, .. } = &line.items[0] else {
            panic!("应为成功项");
        };
        assert_eq!(entry.algorithm, Algorithm::Sha256);
        assert_eq!(entry.digits, 8);
    }

    /// 空 secret 拒绝；counter 字段（field7）被忽略。
    #[test]
    fn 空secret拒绝且counter被忽略() {
        let mut sub = otp_sub(b"", "GitHub:alice", "", 2);
        sub.extend_from_slice(&[0x38, 0x2A]); // field7 counter=42
        let line = parse_uri_line(1, &to_uri(&wrap(&sub)));
        assert!(matches!(&line.items[0], BatchItem::Failed { .. }));
    }

    /// 子消息内未知字段（varint 与 length-delimited）按 wire 类型跳过；
    /// GA 未来新增字段不阻塞导入。
    #[test]
    fn 子消息未知字段跳过() {
        let mut sub = otp_sub(b"1234", "GitHub:alice", "", 2);
        // field 99 wire 0 varint 42：tag = (99 << 3) | 0 = 0x318 → varint 0x98 0x06
        sub.extend_from_slice(&[0x98, 0x06, 0x2A]);
        // field 99 wire 2 "hi"：tag = (99 << 3) | 2 = 0x31A → varint 0x9A 0x06
        sub.extend_from_slice(&[0x9A, 0x06, 0x02, 0x68, 0x69]);
        let line = parse_uri_line(1, &to_uri(&wrap(&sub)));
        assert!(
            matches!(&line.items[0], BatchItem::Ok { .. }),
            "未知字段应被跳过"
        );
    }

    /// 顶层未知字段跳过（与已知字段交错出现）。
    #[test]
    fn 顶层未知字段跳过() {
        let sub = otp_sub(b"1234", "GitHub:alice", "", 2);
        let mut payload = wrap(&sub);
        payload.extend_from_slice(&[0xA8, 0x06, 0x01]); // field 101 wire 0 varint 1
        payload.extend_from_slice(&[0xB2, 0x06, 0x02, 0x68, 0x69]); // field 102 wire 2 "hi"
        let line = parse_uri_line(1, &to_uri(&payload));
        assert!(matches!(&line.items[0], BatchItem::Ok { .. }));
    }

    /// 已知字段携带错误 wire 类型必须报错，不能静默跳过。
    #[test]
    fn 已知字段类型错误报错() {
        let mut payload = vec![0x08, 0x2A]; // field1 wire 0（应为 wire 2）
        payload.extend_from_slice(&[0x12, 0x01, 0x61]);
        assert!(matches!(
            decode_payload(&payload),
            Err(GauthError::WrongWireType(1))
        ));
    }

    /// 截断 varint 报错；截断 length-delimited 报错。
    #[test]
    fn 截断数据报错() {
        assert_eq!(decode_payload(&[0x0A]), Err(GauthError::Truncated));
        // 声明长度 5 实际只有 2
        assert_eq!(
            decode_payload(&[0x0A, 0x05, 0x0A, 0x00]),
            Err(GauthError::Truncated)
        );
        // varint 永不终结
        assert_eq!(decode_payload(&[0xFF]), Err(GauthError::Truncated));
    }

    /// 非法 Base64 与缺失 data 参数报错。
    #[test]
    fn 非法base64与缺data报错() {
        assert!(matches!(
            parse_uri("otpauth-migration://offline?data=!!!"),
            Err(GauthError::InvalidBase64(_))
        ));
        assert!(matches!(
            parse_uri("otpauth-migration://offline"),
            Err(GauthError::MissingData)
        ));
        assert!(matches!(
            parse_uri("otpauth://totp/GitHub:alice?secret=MZXW6YTBOI"),
            Err(GauthError::NotMigration)
        ));
    }

    /// 空 otp_parameters 报「载荷中没有条目」。
    #[test]
    fn 空载荷报错() {
        let line = parse_uri_line(1, &to_uri(&[]));
        let BatchItem::Failed { error, .. } = &line.items[0] else {
            panic!("应为失败项");
        };
        assert!(error.contains("没有条目"));
    }

    /// 多批次信息（batch_size>1）生成进度说明。
    #[test]
    fn 多批次进度说明() {
        let sub = otp_sub(b"1234", "GitHub:alice", "", 2);
        let mut payload = wrap(&sub);
        payload.extend_from_slice(&[0x18, 0x03, 0x20, 0x02, 0x28, 0x07]); // batch_size=3 batch_index=2 batch_id=7
        let line = parse_uri_line(1, &to_uri(&payload));
        assert_eq!(line.note.as_deref(), Some("迁移批次 3/3（batch_id 7）"));
    }

    /// 单批次（batch_size<=1）不生成进度说明。
    #[test]
    fn 单批次无进度说明() {
        let sub = otp_sub(b"1234", "GitHub:alice", "", 2);
        let line = parse_uri_line(1, &to_uri(&wrap(&sub)));
        assert!(line.note.is_none());
    }

    /// 超长 URI 直接拒绝（不进 base64 解码）。
    #[test]
    fn 超长uri拒绝() {
        let uri = format!(
            "otpauth-migration://offline?data={}",
            "A".repeat(MAX_URI_LEN)
        );
        assert!(matches!(parse_uri(&uri), Err(GauthError::TooLong)));
    }

    /// 混合批次：TOTP 正常导入，HOTP 逐条拒绝不中断。
    #[test]
    fn 混合批次逐条报告() {
        let totp = otp_sub(b"1234", "GitHub:alice", "", 2);
        let hotp = otp_sub(b"5678", "GitLab:bob", "", 1);
        let mut payload = wrap(&totp);
        let mut hotp_wrap = wrap(&hotp);
        payload.append(&mut hotp_wrap);
        let line = parse_uri_line(1, &to_uri(&payload));
        assert_eq!(line.items.len(), 2);
        assert!(matches!(&line.items[0], BatchItem::Ok { .. }));
        assert!(matches!(&line.items[1], BatchItem::Failed { .. }));
    }

    /// 百分号解码：合法序列正确解码，非法序列报错。
    #[test]
    fn 百分号解码() {
        assert_eq!(percent_decode("%2F%3D").unwrap(), "/=");
        assert_eq!(percent_decode("abc").unwrap(), "abc");
        assert!(percent_decode("%2").is_err());
        assert!(percent_decode("%GG").is_err());
    }

    /// varint 超过 64 位报错（10 字节后仍带有效位）。
    #[test]
    fn varint超长报错() {
        // 11 字节全带续位且末字节有效位非零
        let payload = vec![
            0x10, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F,
        ];
        assert!(matches!(
            decode_payload(&payload),
            Err(GauthError::VarintTooLong)
        ));
    }
}
