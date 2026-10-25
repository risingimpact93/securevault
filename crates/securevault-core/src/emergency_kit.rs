//! Emergency Kit PDF and Secret Key QR PNG.
//!
//! Labels in the PDF are English Helvetica (WinAnsi). Vault names that cannot
//! be represented are replaced with `?`; the vault id is always printed.

use pdf_writer::{Content, Name, Pdf, Rect, Ref, Str, TextStr};
use png::{BitDepth, ColorType, Encoder};
use qrcode::types::Color;
use qrcode::{EcLevel, QrCode};
use thiserror::Error;

use crate::secret_key::SecretKey;

/// Pixels per QR module in the PNG, not counting the quiet zone.
pub const QR_MODULE_PX: u32 = 8;
/// Quiet-zone modules on each side of the PNG (QR spec default).
pub const QR_QUIET_MODULES: u32 = 4;

const PAGE_W: f32 = 595.0;
const PAGE_H: f32 = 842.0;
const MARGIN: f32 = 48.0;
const QR_PT: f32 = 168.0;

#[derive(Debug, Error)]
pub enum EmergencyKitError {
    #[error("failed to encode QR code")]
    Qr,
    #[error("failed to encode PNG")]
    Png,
}

/// Fields drawn on one Emergency Kit page.
#[derive(Clone, Copy, Debug)]
pub struct EmergencyKitDoc<'a> {
    pub secret_key: &'a str,
    pub vault_name: &'a str,
    pub date: &'a str,
}

/// Render a one-page Emergency Kit PDF. Content streams are uncompressed so
/// the Secret Key text is findable in the raw bytes.
pub fn render_pdf(doc: &EmergencyKitDoc<'_>) -> Result<Vec<u8>, EmergencyKitError> {
    let code = encode_qr(doc.secret_key)?;
    let vault_id = SecretKey::parse(doc.secret_key)
        .map(|sk| sk.vault_id())
        .unwrap_or_else(|_| "unknown".to_string());
    let vault_name = win_ansi(doc.vault_name);
    let date = win_ansi(doc.date);
    let secret_key = win_ansi(doc.secret_key);

    let catalog_id = Ref::new(1);
    let page_tree_id = Ref::new(2);
    let page_id = Ref::new(3);
    let font_id = Ref::new(4);
    let bold_id = Ref::new(5);
    let content_id = Ref::new(6);
    let info_id = Ref::new(7);

    let mut pdf = Pdf::new();
    pdf.document_info(info_id)
        .title(TextStr("SecureVault Emergency Kit"))
        .creator(TextStr("SecureVault"));
    pdf.catalog(catalog_id).pages(page_tree_id);
    pdf.pages(page_tree_id).kids([page_id]).count(1);

    {
        let mut page = pdf.page(page_id);
        page.parent(page_tree_id);
        page.media_box(Rect::new(0.0, 0.0, PAGE_W, PAGE_H));
        page.contents(content_id);
        page.resources()
            .fonts()
            .pair(Name(b"F1"), font_id)
            .pair(Name(b"F2"), bold_id);
    }

    pdf.type1_font(font_id)
        .base_font(Name(b"Helvetica"))
        .encoding_predefined(Name(b"WinAnsiEncoding"));
    pdf.type1_font(bold_id)
        .base_font(Name(b"Helvetica-Bold"))
        .encoding_predefined(Name(b"WinAnsiEncoding"));

    let mut content = Content::with_capacity(16 * 1024);
    let inner_w = PAGE_W - 2.0 * MARGIN;
    let mut y = PAGE_H - MARGIN - 8.0;

    content.set_fill_gray(0.0);
    show_text(&mut content, b"F2", 20.0, MARGIN, y, "SecureVault Emergency Kit");
    y -= 22.0;
    content.set_fill_gray(0.25);
    show_text(
        &mut content,
        b"F1",
        10.0,
        MARGIN,
        y,
        "Keep this paper in a safe place. Anyone with this key can open the vault.",
    );
    y -= 14.0;
    show_text(
        &mut content,
        b"F1",
        10.0,
        MARGIN,
        y,
        "If you lose this key and your devices, the vault cannot be recovered.",
    );
    y -= 28.0;

    content.set_fill_gray(0.35);
    show_text(&mut content, b"F1", 9.0, MARGIN, y, "Vault");
    y -= 14.0;
    content.set_fill_gray(0.0);
    show_text(&mut content, b"F1", 12.0, MARGIN, y, &fit_line(&vault_name, 80));
    y -= 18.0;
    content.set_fill_gray(0.35);
    show_text(&mut content, b"F1", 9.0, MARGIN, y, "Vault ID");
    y -= 14.0;
    content.set_fill_gray(0.0);
    show_text(&mut content, b"F1", 12.0, MARGIN, y, &vault_id);
    y -= 18.0;
    content.set_fill_gray(0.35);
    show_text(&mut content, b"F1", 9.0, MARGIN, y, "Date");
    y -= 14.0;
    content.set_fill_gray(0.0);
    show_text(&mut content, b"F1", 12.0, MARGIN, y, &date);
    y -= 28.0;

    content.set_fill_gray(0.35);
    show_text(&mut content, b"F1", 9.0, MARGIN, y, "Secret Key");
    y -= 16.0;
    content.set_fill_gray(0.0);
    show_text(&mut content, b"F1", 12.0, MARGIN, y, &secret_key);
    y -= 28.0;

    let qr_left = (PAGE_W - QR_PT) / 2.0;
    let qr_top = y;
    draw_qr(&mut content, &code, qr_left, qr_top, QR_PT);
    y = qr_top - QR_PT - 28.0;

    content.set_fill_gray(0.35);
    show_text(&mut content, b"F1", 9.0, MARGIN, y, "Master Password");
    y -= 10.0;
    let box_h = 40.0;
    let box_bottom = y - box_h;
    content.set_stroke_gray(0.45);
    content.set_line_width(1.0);
    content.rect(MARGIN, box_bottom, inner_w, box_h);
    content.stroke();
    content.set_fill_gray(0.55);
    show_text(
        &mut content,
        b"F1",
        10.0,
        MARGIN + 10.0,
        box_bottom + 16.0,
        "Write your master password here by hand.",
    );

    pdf.stream(content_id, &content.finish());
    Ok(pdf.finish())
}

/// Render a grayscale PNG of the Secret Key QR code.
pub fn render_qr_png(secret_key: &str) -> Result<Vec<u8>, EmergencyKitError> {
    let (pixels, size) = qr_pixels(secret_key)?;
    encode_png_gray(&pixels, size)
}

/// Width and height in pixels of [`render_qr_png`].
pub fn qr_png_pixel_size(secret_key: &str) -> Result<u32, EmergencyKitError> {
    let code = encode_qr(secret_key)?;
    Ok(png_size(code.width() as u32))
}

fn encode_qr(secret_key: &str) -> Result<QrCode, EmergencyKitError> {
    QrCode::with_error_correction_level(secret_key.as_bytes(), EcLevel::M)
        .map_err(|_| EmergencyKitError::Qr)
}

fn png_size(modules: u32) -> u32 {
    (modules + 2 * QR_QUIET_MODULES) * QR_MODULE_PX
}

fn qr_pixels(secret_key: &str) -> Result<(Vec<u8>, u32), EmergencyKitError> {
    let code = encode_qr(secret_key)?;
    let modules = code.width() as u32;
    let size = png_size(modules);
    let mut pixels = vec![255u8; (size as usize) * (size as usize)];
    for my in 0..modules {
        for mx in 0..modules {
            if code[(mx as usize, my as usize)] != Color::Dark {
                continue;
            }
            let x0 = (QR_QUIET_MODULES + mx) * QR_MODULE_PX;
            let y0 = (QR_QUIET_MODULES + my) * QR_MODULE_PX;
            for dy in 0..QR_MODULE_PX {
                let row = ((y0 + dy) * size) as usize;
                for dx in 0..QR_MODULE_PX {
                    pixels[row + (x0 + dx) as usize] = 0;
                }
            }
        }
    }
    Ok((pixels, size))
}

fn encode_png_gray(pixels: &[u8], size: u32) -> Result<Vec<u8>, EmergencyKitError> {
    let mut buf = Vec::new();
    {
        let mut encoder = Encoder::new(&mut buf, size, size);
        encoder.set_color(ColorType::Grayscale);
        encoder.set_depth(BitDepth::Eight);
        let mut writer = encoder.write_header().map_err(|_| EmergencyKitError::Png)?;
        writer
            .write_image_data(pixels)
            .map_err(|_| EmergencyKitError::Png)?;
    }
    Ok(buf)
}

fn draw_qr(content: &mut Content, code: &QrCode, left: f32, top: f32, size_pt: f32) {
    let modules = code.width() as f32;
    let total = modules + 2.0 * QR_QUIET_MODULES as f32;
    let module_pt = size_pt / total;
    let bottom = top - size_pt;
    content.set_fill_gray(1.0);
    content.rect(left, bottom, size_pt, size_pt);
    content.fill_nonzero();
    content.set_fill_gray(0.0);
    for my in 0..code.width() {
        for mx in 0..code.width() {
            if code[(mx, my)] != Color::Dark {
                continue;
            }
            let x = left + (QR_QUIET_MODULES as f32 + mx as f32) * module_pt;
            let y = bottom + (QR_QUIET_MODULES as f32 + (modules - 1.0 - my as f32)) * module_pt;
            content.rect(x, y, module_pt, module_pt);
        }
    }
    content.fill_nonzero();
}

fn show_text(content: &mut Content, font: &[u8], size: f32, x: f32, y: f32, text: &str) {
    let bytes = text.as_bytes();
    content.begin_text();
    content.set_font(Name(font), size);
    content.set_text_matrix([1.0, 0.0, 0.0, 1.0, x, y]);
    content.show(Str(bytes));
    content.end_text();
}

/// Replace bytes that Helvetica / WinAnsi cannot print with `?`.
pub fn win_ansi(input: &str) -> String {
    input
        .chars()
        .map(|ch| {
            let code = ch as u32;
            if (0x20..=0x7E).contains(&code) {
                ch
            } else {
                '?'
            }
        })
        .collect()
}

fn fit_line(input: &str, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input.to_string();
    }
    let mut out: String = input.chars().take(max_chars.saturating_sub(3)).collect();
    out.push_str("...");
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use crate::secret_key::{SecretKey, SECRET_KEY_LEN};

    fn dummy_key() -> String {
        SecretKey::from_bytes([0x42; SECRET_KEY_LEN]).format_display()
    }

    fn assert_pdf_ok(bytes: &[u8], secret_key: &str) {
        assert!(bytes.starts_with(b"%PDF-"), "PDF header missing");
        assert!(
            bytes.ends_with(b"%%EOF") || bytes.windows(5).any(|w| w == b"%%EOF"),
            "%%EOF missing"
        );
        assert!(
            bytes.windows(9).any(|w| w == b"startxref"),
            "startxref missing; xref did not parse"
        );
        let sk = secret_key.as_bytes();
        assert!(
            bytes.windows(sk.len()).any(|w| w == sk),
            "Secret Key not found in uncompressed content"
        );
        assert!(bytes.windows(b"Secret Key".len()).any(|w| w == b"Secret Key"));
        assert!(bytes.windows(b"Master Password".len()).any(|w| w == b"Master Password"));
        assert!(bytes.windows(b"Vault ID".len()).any(|w| w == b"Vault ID"));
    }

    #[test]
    fn pdf_starts_with_header_ends_eof_and_contains_sk() {
        let sk = dummy_key();
        let pdf = render_pdf(&EmergencyKitDoc {
            secret_key: &sk,
            vault_name: "Home",
            date: "2026-10-25",
        })
        .unwrap();
        assert_pdf_ok(&pdf, &sk);
        assert!(pdf.windows(b"Home".len()).any(|w| w == b"Home"));
        assert!(pdf.windows(b"2026-10-25".len()).any(|w| w == b"2026-10-25"));
    }

    #[test]
    fn pdf_sanitizes_non_ascii_vault_name_and_prints_vault_id() {
        let sk = SecretKey::from_bytes([0x42; SECRET_KEY_LEN]);
        let displayed = sk.format_display();
        let id = sk.vault_id();
        let pdf = render_pdf(&EmergencyKitDoc {
            secret_key: &displayed,
            vault_name: "가나다 vault",
            date: "2026-10-25",
        })
        .unwrap();
        assert_pdf_ok(&pdf, &displayed);
        assert!(pdf.windows(b"??? vault".len()).any(|w| w == b"??? vault"));
        assert!(pdf.windows(id.len()).any(|w| w == id.as_bytes()));
        assert!(
            !pdf.windows("가나다".len()).any(|w| w == "가나다".as_bytes()),
            "raw Hangul must not appear as broken WinAnsi bytes"
        );
    }

    #[test]
    fn qr_png_signature_and_dimensions() {
        let sk = dummy_key();
        let png = render_qr_png(&sk).unwrap();
        assert!(png.starts_with(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]));
        let expected = qr_png_pixel_size(&sk).unwrap();
        let decoder = png::Decoder::new(Cursor::new(&png));
        let reader = decoder.read_info().unwrap();
        let info = reader.info();
        assert_eq!(info.width, expected);
        assert_eq!(info.height, expected);
        assert_eq!(info.color_type, ColorType::Grayscale);
        assert_eq!(info.bit_depth, BitDepth::Eight);
    }

    #[test]
    fn writes_sample_pdf_for_inspection() {
        let sk = dummy_key();
        let pdf = render_pdf(&EmergencyKitDoc {
            secret_key: &sk,
            vault_name: "Sample Vault",
            date: "2026-10-25",
        })
        .unwrap();
        std::fs::write("/tmp/ek-sample.pdf", &pdf).expect("write /tmp/ek-sample.pdf");
        assert_pdf_ok(&pdf, &sk);
    }
}
