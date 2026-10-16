// Copyright (C) 2026 Qualia2FA contributors
//
// This library is free software; you can redistribute it and/or modify it under
// the terms of the GNU Lesser General Public License as published by the Free
// Software Foundation; either version 3 of the License, or (at your option) any
// later version.
//
// This library is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
// details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this library; if not, see <https://www.gnu.org/licenses/>.

//! Writing the PNG an HTML export draws its QR code in.
//!
//! # It writes one exact shape, and nothing else
//!
//! 8-bit greyscale (colour type 0), no interlacing, filter type 0 on every row, one `IDAT`
//! chunk. That is the smallest thing that is still a PNG, and it is the shape this library's
//! own reader accepts (see [`crate::import::qr_text_from_png`]) as well as every browser - the
//! image ends up on a page.
//!
//! Grey rather than RGBA because a QR code has two colours: black modules, white modules and a
//! white quiet zone. A fourth of the bytes, and the same picture.
//!
//! # Row filters are not applied
//!
//! Filter type 0 stores the row as it stands. The filters exist to help the compressor find
//! repeated patterns, and this image is a grid of identical modules: the deflate stream is
//! already mostly long runs, so a filter would cost a pass over the data and buy little. What
//! matters more is that the writer has one path rather than five.
//!
//! # The CRC is computed, not skipped
//!
//! Every chunk carries a CRC-32 (IEEE 802.3, reflected, polynomial `0xEDB88320`) over its type
//! and data. A reader may check it (many do), and a writer that left it wrong would produce a
//! file that a browser refuses to draw - the one thing an export must not do.

use miniz_oxide::deflate::compress_to_vec_zlib;

use qualia_transport::image::GrayImage;

/// The eight bytes every PNG starts with (PNG specification §5.2).
const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

/// Compression level handed to the deflate encoder.
///
/// The image is a few tens of kilobytes of very regular data, and the level changes the result
/// by a few percent: a middle level keeps an export of a thousand entries from spending a
/// noticeable amount of time on something the user is waiting for.
const COMPRESSION_LEVEL: u8 = 6;

/// Encodes a greyscale image as a PNG.
///
/// The image's own dimensions are written into `IHDR`, and every pixel becomes one sample:
/// dark stays dark, so a QR code's `0` modules come out black.
pub(crate) fn encode(image: &GrayImage) -> Vec<u8> {
    let width = image.width();
    let height = image.height();

    // One filter byte per row, then one sample per pixel.
    let mut raw = Vec::with_capacity((width as usize + 1) * height as usize);
    for row in 0..height {
        raw.push(0);
        for column in 0..width {
            raw.push(image.pixel(column, row).unwrap_or(u8::MAX));
        }
    }

    let mut out = Vec::with_capacity(raw.len() / 4 + 128);
    out.extend_from_slice(&SIGNATURE);

    let mut ihdr = Vec::with_capacity(13);
    ihdr.extend_from_slice(&width.to_be_bytes());
    ihdr.extend_from_slice(&height.to_be_bytes());
    ihdr.push(8);
    ihdr.push(0);
    ihdr.push(0);
    ihdr.push(0);
    ihdr.push(0);
    chunk(&mut out, b"IHDR", &ihdr);

    chunk(
        &mut out,
        b"IDAT",
        &compress_to_vec_zlib(&raw, COMPRESSION_LEVEL),
    );
    chunk(&mut out, b"IEND", &[]);
    out
}

/// Appends one chunk: length, type, data, CRC.
fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    let length = u32::try_from(data.len()).unwrap_or(u32::MAX);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(kind);
    out.extend_from_slice(data);

    let mut crc = Crc::new();
    crc.update(kind);
    crc.update(data);
    out.extend_from_slice(&crc.finish().to_be_bytes());
}

/// The PNG CRC-32, which is the one Ethernet and zlib use.
///
/// Bitwise rather than table-driven: the table would be 1 KiB of constants to review, and the
/// export path is a user action rather than a hot loop.
struct Crc {
    /// The running value, held inverted so that the shift register starts at all ones.
    value: u32,
}

impl Crc {
    /// The polynomial, reflected (`0x04C11DB7` written the other way round).
    const POLYNOMIAL: u32 = 0xEDB8_8320;

    /// A fresh CRC: all ones.
    const fn new() -> Self {
        Self { value: 0xFFFF_FFFF }
    }

    /// Feeds bytes in.
    fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.value ^= u32::from(*byte);
            for _ in 0..8 {
                let mask = (self.value & 1).wrapping_neg();
                self.value = (self.value >> 1) ^ (Self::POLYNOMIAL & mask);
            }
        }
    }

    /// The final value: inverted, as the specification says.
    const fn finish(self) -> u32 {
        !self.value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds an image of the given size, dark where `dark` says so.
    fn image(width: u32, height: u32, dark: impl Fn(u32, u32) -> bool) -> GrayImage {
        let mut pixels = Vec::with_capacity((width * height) as usize);
        for y in 0..height {
            for x in 0..width {
                pixels.push(if dark(x, y) { 0 } else { u8::MAX });
            }
        }
        GrayImage::from_luma8(width, height, pixels).expect("the size is consistent")
    }

    /// The container holds what a reader needs: signature, `IHDR` with these dimensions,
    /// one `IDAT`, `IEND`, and a CRC that matches each chunk.
    #[test]
    fn the_container_carries_the_image_and_its_checksums() {
        let picture = image(7, 3, |x, y| (x + y) % 2 == 0);
        let png = encode(&picture);

        assert_eq!(
            &png[..8],
            &SIGNATURE,
            "the file must start with the signature"
        );

        let mut offset = 8;
        let mut kinds: Vec<[u8; 4]> = Vec::new();
        let mut idat: Vec<u8> = Vec::new();
        let mut header: Vec<u8> = Vec::new();
        loop {
            let length = u32::from_be_bytes(png[offset..offset + 4].try_into().expect("four bytes"))
                as usize;
            let kind: [u8; 4] = png[offset + 4..offset + 8].try_into().expect("four bytes");
            let data = &png[offset + 8..offset + 8 + length];
            let stored = u32::from_be_bytes(
                png[offset + 8 + length..offset + 12 + length]
                    .try_into()
                    .expect("four bytes"),
            );
            let mut crc = Crc::new();
            crc.update(&kind);
            crc.update(data);
            assert_eq!(
                crc.finish(),
                stored,
                "the CRC of {} does not match its contents",
                String::from_utf8_lossy(&kind)
            );

            kinds.push(kind);
            match &kind {
                b"IHDR" => header = data.to_vec(),
                b"IDAT" => idat.extend_from_slice(data),
                b"IEND" => break,
                other => panic!("unexpected chunk {}", String::from_utf8_lossy(other)),
            }
            offset += 12 + length;
        }
        assert_eq!(kinds, vec![*b"IHDR", *b"IDAT", *b"IEND"]);
        assert_eq!(offset + 12, png.len(), "nothing may follow IEND");

        assert_eq!(
            u32::from_be_bytes(header[0..4].try_into().expect("four bytes")),
            7
        );
        assert_eq!(
            u32::from_be_bytes(header[4..8].try_into().expect("four bytes")),
            3
        );
        assert_eq!(
            &header[8..13],
            &[8, 0, 0, 0, 0],
            "8 bits per sample, greyscale, deflate, adaptive filtering, no interlace"
        );

        let raw = miniz_oxide::inflate::decompress_to_vec_zlib(&idat).expect("the stream is zlib");
        assert_eq!(raw.len(), (7 + 1) * 3);
        assert_eq!(raw[0], 0, "every row uses filter type 0");
        assert_eq!(raw[1], 0, "a dark module is written as 0");
        assert_eq!(raw[2], 255, "a light module is written as 255");
    }

    /// A one-pixel image is still a valid container.
    #[test]
    fn a_single_pixel_encodes() {
        let png = encode(&image(1, 1, |_, _| false));
        assert!(png.starts_with(&SIGNATURE));
        assert!(png.ends_with(&[0xAE, 0x42, 0x60, 0x82]), "IEND's own CRC");
    }

    /// A QR code drawn by this writer is read back by this library's own decoder.
    ///
    /// The two halves are one file apart (`src/import/png.rs` reads what this writes), and
    /// nothing else in the crate closes that loop: this is the test that says the container this
    /// writer produces is one the reader accepts.
    #[test]
    fn a_code_written_as_a_png_is_read_back() {
        let text = "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";
        let symbol =
            qualia_transport::qr::encode_text(text, qualia_transport::qr::EcLevel::Low, 40)
                .expect("the URI fits");

        let scale = 6;
        let quiet = 4;
        let side = (symbol.size() + 2 * quiet) * scale;
        let drawn = symbol.render(scale, quiet).expect("the geometry is legal");
        let canvas = image(side.into(), side.into(), |x, y| {
            drawn.pixel(x, y) == Some(0)
        });

        let read = crate::import::qr_text_from_png(&encode(&canvas))
            .expect("the reader must accept what the writer produced");
        assert_eq!(read, text);
    }
}
