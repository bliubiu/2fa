//! 二维码图片解码（`rqrr` + `image`）。
//!
//! 只接收调用方读入的图片字节，解码出二维码载荷字符串；不碰文件 IO。
//! 这是项目唯一处理不可信外部输入的环节之一（另一处是 otpauth/迁移
//! 载荷解析），因此所有输入先过校验门槛：文件大小上限、像素总数上限、
//! 格式白名单，任何畸形输入都返回中文错误而非 panic。

use image::{DynamicImage, ImageFormat};

/// 图片字节上限（16 MiB）。正常二维码截图远小于此。
pub const MAX_IMAGE_BYTES: usize = 16 * 1024 * 1024;

/// 像素总数上限（约 4000×4000）。超出即拒绝，防止超大图片拖垮解码。
pub const MAX_PIXELS: u64 = 16_000_000;

/// 允许的图片格式白名单（PRD §4.3：PNG / JPEG / GIF / WebP）。
const ALLOWED_FORMATS: [ImageFormat; 4] = [
    ImageFormat::Png,
    ImageFormat::Jpeg,
    ImageFormat::Gif,
    ImageFormat::WebP,
];

/// 图片解码错误。
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum QrError {
    /// 文件字节超过上限。
    #[error("图片过大：{size} 字节，上限 {limit} 字节")]
    TooLarge {
        /// 实际字节数。
        size: usize,
        /// 允许上限。
        limit: usize,
    },
    /// 像素总数超过上限。
    #[error("图片像素过多：{width}×{height}，上限 {limit} 像素，请缩小图片后重试")]
    TooManyPixels {
        /// 图片宽度。
        width: u32,
        /// 图片高度。
        height: u32,
        /// 允许上限。
        limit: u64,
    },
    /// 格式不在白名单内。
    #[error("不支持的图片格式：{0}（仅支持 PNG / JPEG / GIF / WebP）")]
    UnsupportedFormat(String),
    /// 图片损坏或截断，无法解码为图像。
    #[error("图片损坏或格式不完整，无法解码：{0}")]
    InvalidImage(String),
    /// 图片中没有找到二维码。
    #[error("图片中未找到二维码，请确认截图完整、图案清晰")]
    NoQrFound,
    /// 检测到二维码图案但内容解码失败（纠错能力耗尽）。
    #[error("二维码损坏，内容无法解码，请重新截图")]
    DecodeFailed,
    /// 载荷不是 otpauth 格式。
    #[error("二维码内容不是 otpauth 格式：{0}…")]
    NotOtpauth(String),
}

/// 从图片字节解码第一个二维码，返回其载荷字符串。
///
/// 图中出现多个二维码时返回首个成功解码者；全部解码失败则报
/// [`QrError::DecodeFailed`]。
pub fn decode_first(bytes: &[u8]) -> Result<String, QrError> {
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err(QrError::TooLarge {
            size: bytes.len(),
            limit: MAX_IMAGE_BYTES,
        });
    }

    // 格式白名单：既拒绝 SVG/BMP/ICO 等白名单外格式，也把「根本不是
    // 图片」的字节挡在这里
    let format = image::guess_format(bytes)
        .map_err(|_| QrError::InvalidImage("无法识别的图片格式".into()))?;
    if !ALLOWED_FORMATS.contains(&format) {
        return Err(QrError::UnsupportedFormat(format_name(format)));
    }

    let img = image::load_from_memory(bytes).map_err(|e| QrError::InvalidImage(e.to_string()))?;
    let (width, height) = (img.width(), img.height());
    if u64::from(width) * u64::from(height) > MAX_PIXELS {
        return Err(QrError::TooManyPixels {
            width,
            height,
            limit: MAX_PIXELS,
        });
    }

    let mut prepared = rqrr::PreparedImage::prepare(img.to_luma8());
    let grids = prepared.detect_grids();
    for grid in &grids {
        // 该候选图案解码失败（纠错能力耗尽等）时尝试下一个
        if let Ok((_, content)) = grid.decode() {
            return Ok(content);
        }
    }
    if grids.is_empty() {
        Err(QrError::NoQrFound)
    } else {
        Err(QrError::DecodeFailed)
    }
}

/// 白名单外格式的中文/惯例名（错误信息可读性）。
fn format_name(format: ImageFormat) -> String {
    match format {
        ImageFormat::Png => "PNG".into(),
        ImageFormat::Jpeg => "JPEG".into(),
        ImageFormat::Gif => "GIF".into(),
        ImageFormat::WebP => "WebP".into(),
        other => format!("{other:?}"),
    }
}

/// 判断字节是否为白名单内图片格式的魔数（供调用方做输入分派）。
pub fn looks_like_image(bytes: &[u8]) -> bool {
    let starts = |sig: &[u8]| bytes.starts_with(sig);
    starts(b"\x89PNG\r\n\x1a\n")
        || starts(b"\xff\xd8\xff")
        || starts(b"GIF87a")
        || starts(b"GIF89a")
        || (bytes.len() >= 12 && starts(b"RIFF") && &bytes[8..12] == b"WEBP")
}

/// 校验二维码载荷是否可导入：`otpauth://` 与 `otpauth-migration://`
/// 开头原样返回；其他载荷拒绝并截断展示前若干字符。
pub fn validate_payload(payload: &str) -> Result<&str, QrError> {
    let trimmed = payload.trim();
    if trimmed.starts_with("otpauth://")
        || trimmed.starts_with(crate::importexport::MIGRATION_PREFIX)
    {
        return Ok(trimmed);
    }
    Err(QrError::NotOtpauth(trimmed.chars().take(32).collect()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use image::{ExtendedColorType, GrayImage, Luma};
    use std::io::Cursor;

    const PAYLOAD: &str = "otpauth://totp/GitHub:alice?secret=MZXW6YTBOI&issuer=GitHub";

    /// 把内容编码为二维码灰度图（含 4 模块静区，放大 8 倍）。
    fn qr_luma(content: &str) -> GrayImage {
        let code = qrcode::QrCode::new(content.as_bytes()).unwrap();
        let width = code.width() as u32;
        let quiet = 4u32;
        let scale = 8u32;
        let size = (width + quiet * 2) * scale;
        let mut img = GrayImage::new(size, size);
        for y in 0..size {
            for x in 0..size {
                img.put_pixel(x, y, Luma([255]));
            }
        }
        for (i, c) in code.to_colors().iter().enumerate() {
            let mx = (i % width as usize) as u32 + quiet;
            let my = (i / width as usize) as u32 + quiet;
            let value = if *c == qrcode::types::Color::Dark {
                0
            } else {
                255
            };
            for dy in 0..scale {
                for dx in 0..scale {
                    img.put_pixel(mx * scale + dx, my * scale + dy, Luma([value]));
                }
            }
        }
        img
    }

    /// image 内建编码器封装。
    fn encode(img: &GrayImage, format: ImageFormat) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        DynamicImage::ImageLuma8(img.clone())
            .write_to(&mut buf, format)
            .unwrap();
        buf.into_inner()
    }

    /// JPEG 用高质量独立编码（有损压缩，质量不足会破坏模块边界）。
    fn jpeg_encode(img: &GrayImage) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut buf, 95);
        encoder
            .encode_image(&DynamicImage::ImageLuma8(img.clone()))
            .unwrap();
        buf.into_inner()
    }

    /// GIF 走调色板编码器（GIF 不支持 L8 灰度直出，先转 RGBA8 再量化）。
    fn gif_encode(img: &GrayImage) -> Vec<u8> {
        let rgb = DynamicImage::ImageLuma8(img.clone()).to_rgba8();
        let mut buf = Cursor::new(Vec::new());
        {
            let mut encoder = image::codecs::gif::GifEncoder::new(&mut buf);
            encoder.encode_frame(image::Frame::new(rgb)).unwrap();
        }
        buf.into_inner()
    }

    /// WebP 走无损编码器（write_to 不支持 WebP 输出）。
    fn webp_encode(img: &GrayImage) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        let encoder = image::codecs::webp::WebPEncoder::new_lossless(&mut buf);
        encoder
            .encode(
                img.as_raw(),
                img.width(),
                img.height(),
                ExtendedColorType::L8,
            )
            .unwrap();
        buf.into_inner()
    }

    /// PNG / JPEG / GIF / WebP 四格式样图都能解码出原始载荷。
    #[test]
    fn 四格式样图解码() {
        let img = qr_luma(PAYLOAD);
        let cases = [
            ("PNG", encode(&img, ImageFormat::Png)),
            ("JPEG", jpeg_encode(&img)),
            ("GIF", gif_encode(&img)),
            ("WebP", webp_encode(&img)),
        ];
        for (name, bytes) in cases {
            let content = decode_first(&bytes).unwrap_or_else(|e| panic!("{name} 解码失败：{e}"));
            assert_eq!(content, PAYLOAD, "{name} 载荷应一致");
        }
    }

    /// 超过字节上限直接拒绝，不再进入解码。
    #[test]
    fn 超大文件被拒() {
        let bytes = vec![0u8; MAX_IMAGE_BYTES + 1];
        assert_eq!(
            decode_first(&bytes),
            Err(QrError::TooLarge {
                size: bytes.len(),
                limit: MAX_IMAGE_BYTES
            })
        );
    }

    /// 像素总数超限被拒（纯色大图字节很小但像素过多）。
    #[test]
    fn 超大像素被拒() {
        let big = GrayImage::from_pixel(5000, 5000, Luma([255]));
        let bytes = encode(&big, ImageFormat::Png);
        match decode_first(&bytes) {
            Err(QrError::TooManyPixels {
                width,
                height,
                limit,
            }) => {
                assert_eq!((width, height), (5000, 5000));
                assert_eq!(limit, MAX_PIXELS);
            }
            other => panic!("应为像素超限错误：{other:?}"),
        }
    }

    /// 损坏文件返回明确错误而不 panic：无法识别、PNG 魔数损坏、白名单外格式。
    #[test]
    fn 损坏文件不panic() {
        // 乱字节：既不是任何已知图片格式
        assert!(matches!(
            decode_first(b"totally not an image"),
            Err(QrError::InvalidImage(_))
        ));
        // PNG 魔数正确但内容损坏
        let mut broken = Vec::from(&[0x89, b'P', b'N', b'G', b'\r', b'\n', 0x1a, b'\n'][..]);
        broken.extend_from_slice(b"garbage garbage garbage");
        assert!(matches!(
            decode_first(&broken),
            Err(QrError::InvalidImage(_))
        ));
        // BMP 白名单外
        assert!(matches!(
            decode_first(b"BM\x00\x00\x00\x00"),
            Err(QrError::UnsupportedFormat(_))
        ));
    }

    /// 正常图片但不含二维码：明确提示未找到。
    #[test]
    fn 无二维码图返回明确错误() {
        let blank = GrayImage::from_pixel(200, 200, Luma([255]));
        let bytes = encode(&blank, ImageFormat::Png);
        assert_eq!(decode_first(&bytes), Err(QrError::NoQrFound));
    }

    /// 魔数判断：四格式命中、文本/空字节不命中。
    #[test]
    fn 图片魔数判断() {
        assert!(looks_like_image(&encode(
            &qr_luma(PAYLOAD),
            ImageFormat::Png
        )));
        assert!(looks_like_image(b"\xff\xd8\xff\xe0 rest"));
        assert!(looks_like_image(b"GIF89a rest"));
        assert!(looks_like_image(b"RIFF\x00\x00\x00\x00WEBPVP8 "));
        assert!(!looks_like_image(b"otpauth://totp/..."));
        assert!(!looks_like_image(b""));
    }

    /// 载荷校验：otpauth 与迁移前缀放行，其他载荷报错并截断展示。
    #[test]
    fn 载荷校验() {
        assert_eq!(
            validate_payload("  otpauth://totp/GitHub:alice?secret=MZXW6YTBOI  ").unwrap(),
            "otpauth://totp/GitHub:alice?secret=MZXW6YTBOI"
        );
        assert_eq!(
            validate_payload("otpauth-migration://offline?data=ABC").unwrap(),
            "otpauth-migration://offline?data=ABC"
        );
        // 超长非 otpauth 载荷：只展示前 32 字符
        let long = "https://example.com/".repeat(10);
        match validate_payload(&long) {
            Err(QrError::NotOtpauth(head)) => {
                assert_eq!(head.chars().count(), 32);
                assert!(head.starts_with("https://example.com/"));
            }
            other => panic!("应为 NotOtpauth 错误：{other:?}"),
        }
    }
}
