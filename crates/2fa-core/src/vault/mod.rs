//! 保险库存储层：封套加密、KDF、文件格式与 AAD 组装、原子写入、文件锁、内存保护、schema 迁移链。
//!
//! 文件 IO 以字节为单位进行，上层调用方负责传入与写出；
//! 本模块保证任何时刻落盘的都是完整可解析的保险库文件。

mod entries;
mod envelope;
mod format;
mod kdf;
mod key;

pub use entries::{Entry, ModelError, VaultBody, normalize_id};
pub use envelope::{ENVELOPE_LEN, Envelope, EnvelopeError};
pub use format::{FormatError, MAGIC, SCHEMA_VERSION, VaultFile};
pub use kdf::{
    CURRENT_VERSION, KdfError, KdfParams, KdfVersion, derive as kdf_derive, params as kdf_params,
};
pub use key::{KeyError, SecretKey, VaultKey};
