//! 保险库正文与条目模型。
//!
//! 正文 JSON：`{ schema_version, created_at, entries: [...] }`。
//! 条目：`{ id, issuer, account, secret, algorithm, digits, period, tags }`。
//!
//! - `id` 使用 UUID v7（时间有序，便于人工排序与调试；禁用随机 v4 与自增整数）
//! - `secret` 的序列化直接引用零化缓冲；反序列化产生的明文副本立即清零
//! - `(issuer, account)` 归一化（大小写与空白不敏感）：同标识多条目**允许并存**
//!   （同站换绑密钥是合法场景），归并决策交由上层交互，本层只提供查找能力

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::key::SecretKey;
use crate::domain::totp::Algorithm;
use crate::vault::format::SCHEMA_VERSION;

/// 条目模型错误。
#[derive(Debug, thiserror::Error)]
pub enum ModelError {
    /// 位数为 6 / 8 之外的值。
    #[error("位数为 6 / 8 之外的值：{0}")]
    InvalidDigits(u8),
    /// 刷新周期小于 1 秒。
    #[error("刷新周期必须至少为 1 秒，当前为 {0}")]
    InvalidPeriod(u32),
    /// JSON 编解码失败。
    #[error("保险库正文编解码失败：{0}")]
    Json(#[from] serde_json::Error),
    /// 条目字段校验失败（反序列化后统一校验时使用）。
    #[error("条目 {0} 校验失败：{1}")]
    InvalidEntry(Uuid, &'static str),
    /// 正文 schema_version 与当前不符（低版本文件应走迁移链，高版本应提示升级）。
    #[error("正文 schema_version 为 {0}，当前支持 {1}")]
    SchemaMismatch(u16, u16),
}

/// 保险库正文。
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct VaultBody {
    /// 正文 schema 版本。
    pub schema_version: u16,
    /// 保险库创建时间（Unix 秒，由调用方传入，本层不读时钟）。
    pub created_at: u64,
    /// 全部条目。
    pub entries: Vec<Entry>,
}

/// 条目归一化：大小写与全部空白不敏感（「Git Hub」与「github」视为同标识）。
pub fn normalize_id(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect()
}

/// 单个 2FA 条目。
///
/// **禁止 `Clone`**：内部持有 [`SecretKey`]，派生副本会产生零化覆盖不到的残留。
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct Entry {
    /// UUID v7 标识。
    pub id: Uuid,
    /// 服务商名（展示用原文）。
    pub issuer: String,
    /// 账号名（展示用原文）。
    pub account: String,
    /// OTP 密钥。
    pub secret: SecretKey,
    /// 哈希算法（JSON 中存大写规范名，如 `SHA1`）。
    #[serde(with = "algorithm_serde")]
    pub algorithm: Algorithm,
    /// 验证码位数，6 或 8。
    pub digits: u8,
    /// 时间步长（秒）。
    pub period: u32,
    /// 标签。
    pub tags: Vec<String>,
}

/// `Algorithm` 的 serde 映射：存大写规范名。
mod algorithm_serde {
    use super::Algorithm;
    use serde::{Deserializer, Serializer};

    pub(super) fn serialize<S: Serializer>(
        algorithm: &Algorithm,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(algorithm.label())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Algorithm, D::Error> {
        use serde::Deserialize as _;
        let text = String::deserialize(deserializer)?;
        Algorithm::parse_label(&text)
            .ok_or_else(|| serde::de::Error::custom(format!("未知算法：{text}")))
    }
}

impl Entry {
    /// 构造并校验条目（`digits` 必须 6/8，`period` 必须 ≥ 1）。
    pub fn new(
        issuer: String,
        account: String,
        secret: SecretKey,
        algorithm: Algorithm,
        digits: u8,
        period: u32,
        tags: Vec<String>,
    ) -> Result<Self, ModelError> {
        let entry = Self {
            id: Uuid::now_v7(),
            issuer,
            account,
            secret,
            algorithm,
            digits,
            period,
            tags,
        };
        entry.validate()?;
        Ok(entry)
    }

    /// 字段合法性校验。
    pub fn validate(&self) -> Result<(), ModelError> {
        if self.digits != 6 && self.digits != 8 {
            return Err(ModelError::InvalidDigits(self.digits));
        }
        if self.period == 0 {
            return Err(ModelError::InvalidPeriod(self.period));
        }
        Ok(())
    }

    /// 归一化 `(issuer, account)` 标识键。
    pub fn identity_key(&self) -> (String, String) {
        (normalize_id(&self.issuer), normalize_id(&self.account))
    }
}

impl VaultBody {
    /// 创建空正文（当前 schema 版本）。
    pub fn empty(created_at: u64) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            created_at,
            entries: Vec::new(),
        }
    }

    /// 查找与给定 `(issuer, account)` 归一化同标识的全部条目。
    ///
    /// 同标识多条目允许并存；add/edit/import 的归并决策由上层交互完成。
    pub fn find_same_identity(&self, issuer: &str, account: &str) -> Vec<&Entry> {
        let key = (normalize_id(issuer), normalize_id(account));
        self.entries
            .iter()
            .filter(|e| e.identity_key() == key)
            .collect()
    }

    /// 序列化为 JSON 字符串，主缓冲零化管辖。
    pub fn to_json(&self) -> Result<Zeroizing<String>, ModelError> {
        Ok(Zeroizing::new(serde_json::to_string(self)?))
    }

    /// 从 JSON 解析正文并全量校验（含 schema 版本与每个条目的字段合法性）。
    pub fn from_json(json: &str) -> Result<Self, ModelError> {
        Self::from_json_version(json, SCHEMA_VERSION)
    }

    /// 从 JSON 解析正文，要求 schema 版本等于 `expected`，并全量校验条目字段。
    ///
    /// 供迁移链逐级使用：迁移过程中的正文处于历史版本，
    /// 不能按当前版本校验，但条目字段合法性必须逐级保证。
    pub fn from_json_version(json: &str, expected: u16) -> Result<Self, ModelError> {
        let body: Self = serde_json::from_str(json)?;
        if body.schema_version != expected {
            return Err(ModelError::SchemaMismatch(body.schema_version, expected));
        }
        for entry in &body.entries {
            entry.validate().map_err(|e| {
                ModelError::InvalidEntry(
                    entry.id,
                    match e {
                        ModelError::InvalidDigits(d) => {
                            static DIGITS: &str = "位数为 6 / 8 之外的值";
                            let _ = d;
                            DIGITS
                        }
                        ModelError::InvalidPeriod(_) => "刷新周期必须至少为 1 秒",
                        _ => "字段校验失败",
                    },
                )
            })?;
        }
        Ok(body)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn sample_entry(issuer: &str, account: &str, secret_text: &str) -> Entry {
        Entry::new(
            issuer.to_string(),
            account.to_string(),
            SecretKey::from_base32(secret_text).unwrap(),
            Algorithm::Sha1,
            6,
            30,
            Vec::new(),
        )
        .unwrap()
    }

    /// JSON 往返字段级一致。
    #[test]
    fn 往返字段级一致() {
        let mut body = VaultBody::empty(1_700_000_000);
        body.entries.push(
            Entry::new(
                "GitHub".to_string(),
                "alice@example.com".to_string(),
                SecretKey::from_base32("MZXW6YTBOI").unwrap(),
                Algorithm::Sha256,
                8,
                60,
                vec!["工作".to_string()],
            )
            .unwrap(),
        );

        let json = body.to_json().unwrap();
        let parsed = VaultBody::from_json(&json).unwrap();

        assert_eq!(parsed, body);
        let e = &parsed.entries[0];
        assert_eq!(e.issuer, "GitHub");
        assert_eq!(e.account, "alice@example.com");
        assert_eq!(e.secret.as_text(), "MZXW6YTBOI");
        assert_eq!(e.algorithm, Algorithm::Sha256);
        assert_eq!(e.digits, 8);
        assert_eq!(e.period, 60);
        assert_eq!(e.tags, vec!["工作".to_string()]);
    }

    /// id 必须是 UUID v7。
    #[test]
    fn 条目id为uuid_v7() {
        let entry = sample_entry("GitHub", "alice", "MZXW6YTBOI");
        assert_eq!(entry.id.get_version_num(), 7);
    }

    /// 连续创建的条目 id 按时间有序（v7 语义）。
    #[test]
    fn 条目id时间有序() {
        let a = sample_entry("A", "a", "MZXW6YTBOI");
        let b = sample_entry("B", "b", "MZXW6YTBOI");
        assert!(a.id < b.id, "UUID v7 应随时间单调递增");
    }

    /// secret 在 JSON 中序列化为规范 Base32 文本。
    #[test]
    fn secret序列化为base32文本() {
        let entry = sample_entry("GitHub", "alice", "mzxw6ytboi=====");
        let json = entry_to_json(&entry);
        assert!(json.contains("MZXW6YTBOI"), "JSON 应含规范密钥文本：{json}");
        assert!(!json.contains("mzxw6ytboi"), "不应保留非规范形式");
    }

    /// to_json 的返回值被零化管辖（类型层面）；此处验证序列化内容本身正确。
    #[test]
    fn 序列化主缓冲可用() {
        let mut body = VaultBody::empty(42);
        body.entries.push(sample_entry("A", "a", "MZXW6YTBOI"));
        let json = body.to_json().unwrap();
        assert!(json.contains("MZXW6YTBOI"));
    }

    /// 归一化：大小写、首尾空白、内部空白均不敏感。
    #[test]
    fn 归一化规则() {
        assert_eq!(normalize_id("GitHub"), "github");
        assert_eq!(normalize_id("  GIT  Hub  "), "github");
        assert_eq!(normalize_id("Git Hub"), "github");
        assert_eq!(normalize_id("国内服务商·中文"), "国内服务商·中文");
        assert_ne!(normalize_id("GitHub"), "GitHub2");
    }

    /// 同标识多条目允许并存，查找返回全部；不同标识不混入。
    #[test]
    fn 同标识查找含并存条目() {
        let mut body = VaultBody::empty(0);
        let e1 = sample_entry("GitHub", "alice", "MZXW6YTBOI");
        let e2 = sample_entry("  git hub ", "ALICE", "MZXW6YTB");
        let other = sample_entry("GitHub", "bob", "MZXW6YQ");
        body.entries.push(e1);
        body.entries.push(e2);
        body.entries.push(other);

        let found = body.find_same_identity("GitHub", "Alice");
        assert_eq!(found.len(), 2, "大小写与空白差异应视为同标识");
        let found = body.find_same_identity("github", "bob");
        assert_eq!(found.len(), 1);
        let found = body.find_same_identity("Gitee", "alice");
        assert!(found.is_empty());
    }

    /// digits 非 6/8 构造报错。
    #[test]
    fn 非法位数报错() {
        for digits in [0u8, 5, 7, 9, 255] {
            let err = Entry::new(
                "A".into(),
                "a".into(),
                SecretKey::from_base32("MZXW6YTBOI").unwrap(),
                Algorithm::Sha1,
                digits,
                30,
                Vec::new(),
            )
            .unwrap_err();
            assert!(matches!(err, ModelError::InvalidDigits(_)), "位数 {digits}");
        }
    }

    /// period 为 0 构造报错。
    #[test]
    fn 零周期报错() {
        let err = Entry::new(
            "A".into(),
            "a".into(),
            SecretKey::from_base32("MZXW6YTBOI").unwrap(),
            Algorithm::Sha1,
            6,
            0,
            Vec::new(),
        )
        .unwrap_err();
        assert!(matches!(err, ModelError::InvalidPeriod(0)));
    }

    /// 解析 JSON 时同样执行字段校验：手写非法 JSON 必须被拒。
    #[test]
    fn 解析时校验字段() {
        let json = r#"{"schema_version":1,"created_at":0,"entries":[{"id":"018f0000-0000-7000-8000-000000000000","issuer":"A","account":"a","secret":"MZXW6YTBOI","algorithm":"SHA1","digits":9,"period":30,"tags":[]}]}"#;
        let err = VaultBody::from_json(json).unwrap_err();
        assert!(matches!(
            err,
            ModelError::InvalidEntry(_, "位数为 6 / 8 之外的值")
        ));
    }

    /// schema 版本不符被拒（迁移链负责升级，本层不做静默兼容）。
    #[test]
    fn schema版本不符被拒() {
        let json = r#"{"schema_version":99,"created_at":0,"entries":[]}"#;
        let err = VaultBody::from_json(json).unwrap_err();
        assert!(matches!(err, ModelError::SchemaMismatch(99, 1)));
    }

    /// secret 字段宽容解析：小写、带填充的文本同样可用。
    #[test]
    fn secret反序列化宽容解析() {
        let json = r#"{"schema_version":1,"created_at":0,"entries":[{"id":"018f0000-0000-7000-8000-000000000000","issuer":"A","account":"a","secret":" m z x w 6 y t b o i ","algorithm":"sha512","digits":6,"period":30,"tags":[]}]}"#;
        let body = VaultBody::from_json(json).unwrap();
        let e = &body.entries[0];
        assert_eq!(e.secret.as_text(), "MZXW6YTBOI");
        assert_eq!(e.algorithm, Algorithm::Sha512);
    }

    /// JSON 中 algorithm 字段存大写规范名。
    #[test]
    fn 算法字段为规范名() {
        let entry = Entry::new(
            "A".into(),
            "a".into(),
            SecretKey::from_base32("MZXW6YTBOI").unwrap(),
            Algorithm::Sha512,
            6,
            30,
            Vec::new(),
        )
        .unwrap();
        let json = entry_to_json(&entry);
        assert!(json.contains(r#""algorithm":"SHA512""#), "{json}");
    }

    fn entry_to_json(entry: &Entry) -> String {
        serde_json::to_string(entry).unwrap()
    }
}
