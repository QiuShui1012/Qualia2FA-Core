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

//! Reading the QR code that one column of an HTML export embeds.
//!
//! # Why this exists
//!
//! The HTML export's table carries every field of an entry except its time step. That step is
//! inside the QR code the table draws in a column of its own, and the code holds the entry's
//! whole `otpauth://` URI. Reading the step therefore means reading the code, which means
//! decoding the PNG it is drawn as.
//!
//! The alternative - assuming the scheme's default step - produces codes that never match for
//! every entry whose step is not the default, with nothing on screen to say why. The step is
//! worth a decoder.
//!
//! # What is decoded, and what is not
//!
//! Only the container: the eight-byte signature, the chunk stream, `zlib` and the five row
//! filters. No image file is understood anywhere else in this library, and none is understood
//! here either - what comes out is the grayscale plane [`qualia_transport::qr::scan`] takes, and
//! it is that module which reads the code.
//!
//! # Bounds
//!
//! Every dimension is checked before anything is allocated. A PNG states its own size, so a few
//! hundred bytes of input can describe a gigapixel image; the pixel count is bounded against
//! [`MAX_PIXELS`] first, and the decompression itself runs with a limit derived from that
//! bounded size rather than from the input's claims about it.

use miniz_oxide::inflate::decompress_to_vec_zlib_with_limit;
use qualia_transport::image::GrayImage;
use qualia_transport::qr::scan::decode_text;

/// The most pixels a QR code in an export may have: 4096 x 4096.
///
/// A code is drawn at a few hundred pixels a side. The bound is generous enough that no real
/// export is refused, and small enough that a file cannot ask this library to allocate a
/// gigabyte: 4096 x 4096 x 4 bytes is 64 MiB of decoded rows, and the decompression limit is
/// derived from that same number.
pub const MAX_PIXELS: u32 = 4096 * 4096;

/// Why a QR image could not be read.
///
/// The variants are the reader's own: they say what was wrong with the **file**, and the caller
/// turns one into an import problem. They are deliberately not part of the crate's error type,
/// because a document with an unreadable image is a document that can still be imported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PngError {
    /// The bytes are not a PNG at all.
    NotPng,

    /// The file ends before a chunk or a row does.
    Truncated,

    /// A feature outside what an export produces: sixteen-bit samples, a palette, interlacing.
    Unsupported,

    /// The image is larger than this reader accepts; the bound is `MAX_PIXELS`.
    TooLarge,

    /// The compressed data is not a valid stream, or does not decode to the stated size.
    Corrupt,

    /// The image decoded, and no QR code could be read out of it.
    NoCode,
}

impl PngError {
    /// A short explanation for the user, which is what an import problem carries.
    ///
    /// Nothing from the file appears in it: the message is about the reader's own expectations.
    pub fn reason(self) -> &'static str {
        match self {
            Self::NotPng => "the embedded image is not a PNG",
            Self::Truncated => "the embedded image is cut short",
            Self::Unsupported => {
                "the embedded image uses a PNG feature this reader does not support"
            }
            Self::TooLarge => "the embedded image is larger than this reader accepts",
            Self::Corrupt => "the embedded image could not be decompressed",
            Self::NoCode => "no QR code could be read out of the embedded image",
        }
    }
}

/// Reads the text of the QR code drawn in `bytes`, a PNG.
///
/// Returns the code's own text, which for an export is the entry's `otpauth://` URI.
pub fn qr_text_from_png(bytes: &[u8]) -> Result<String, PngError> {
    let image = gray_from_png(bytes)?;
    decode_text(&image).map_err(|_| PngError::NoCode)
}

/// Decodes a PNG into the grayscale plane the QR scanner takes.
fn gray_from_png(bytes: &[u8]) -> Result<GrayImage, PngError> {
    const SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];

    if bytes.len() < SIGNATURE.len() || bytes[..SIGNATURE.len()] != SIGNATURE {
        return Err(PngError::NotPng);
    }

    let mut header: Option<Header> = None;
    let mut compressed: Vec<u8> = Vec::new();
    let mut offset = SIGNATURE.len();

    loop {
        let length = read_u32(bytes, offset)? as usize;
        let kind = bytes
            .get(offset + 4..offset + 8)
            .ok_or(PngError::Truncated)?;
        let data = bytes
            .get(offset + 8..offset + 8 + length)
            .ok_or(PngError::Truncated)?;
        // The chunk's own CRC is read past rather than verified: the QR scan that follows fails
        // on a damaged image anyway, and a bit flip that survives it cannot change what the code
        // says without the code failing to decode at all.
        offset = offset
            .checked_add(12)
            .and_then(|at| at.checked_add(length))
            .ok_or(PngError::Truncated)?;
        if offset > bytes.len() {
            return Err(PngError::Truncated);
        }

        // Compared as slices rather than matched as byte-string patterns: a four-byte name is a
        // slice, and an equality comparison is unambiguously the comparison this wants.
        if kind == b"IHDR" {
            if header.is_some() {
                return Err(PngError::Corrupt);
            }
            header = Some(Header::parse(data)?);
        } else if kind == b"IDAT" {
            compressed.extend_from_slice(data);
        } else if kind == b"IEND" {
            break;
        }
    }

    let header = header.ok_or(PngError::Corrupt)?;
    let pixels = header.width as usize * header.height as usize;
    let channels = header.channels();
    // One filter byte per row, then the samples. The limit is derived from the bounded pixel
    // count rather than from the file, so a small file cannot ask for a large allocation.
    let raw_len = (header.width as usize * channels + 1) * header.height as usize;
    // The stream is the zlib one the format wraps its image data in, not the bare deflate
    // `decompress_to_vec_with_limit` takes: the two are different functions because they are
    // different formats, and using the wrong one fails on a stream this very crate produced.
    //
    // The limit is the exact row size plus a margin, and the exact size is checked immediately
    // after. The margin is not slack for the file: the decompressor reports "there is more output
    // than this" by filling its buffer, so a limit of exactly the expected size is a limit it
    // cannot tell "done" from "more" with. What the limit is really for is that a few hundred
    // bytes of input cannot ask for a gigabyte of output, and that bound holds either way.
    let raw = decompress_to_vec_zlib_with_limit(&compressed, raw_len.saturating_add(64))
        .map_err(|_| PngError::Corrupt)?;
    if raw.len() != raw_len {
        return Err(PngError::Corrupt);
    }

    let rgba = unfilter(&raw, header, channels, pixels)?;
    GrayImage::from_rgba8(header.width, header.height, &rgba).map_err(|_| PngError::TooLarge)
}

/// What an `IHDR` chunk says, once it has been checked against what this reader supports.
#[derive(Debug, Clone, Copy)]
struct Header {
    /// Width in pixels, never zero.
    width: u32,
    /// Height in pixels, never zero.
    height: u32,
    /// The PNG colour type: 0 gray, 2 RGB, 4 gray+alpha, 6 RGBA.
    color_type: u8,
}

impl Header {
    /// Reads an `IHDR` payload, refusing every feature this reader does not implement.
    fn parse(data: &[u8]) -> Result<Self, PngError> {
        if data.len() < 13 {
            return Err(PngError::Truncated);
        }
        let width = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        let height = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let depth = data[8];
        let color_type = data[9];
        let compression = data[10];
        let filter = data[11];
        let interlace = data[12];

        if width == 0 || height == 0 {
            return Err(PngError::Corrupt);
        }
        if width
            .checked_mul(height)
            .is_none_or(|count| count > MAX_PIXELS)
        {
            return Err(PngError::TooLarge);
        }
        // Sixteen-bit samples, palettes and the five colour types this reader does not list are
        // all outside what an export draws. Interlacing is refused for the same reason: it is a
        // different row layout, and refusing it is better than mis-reading it.
        if depth != 8 || compression != 0 || filter != 0 || interlace != 0 {
            return Err(PngError::Unsupported);
        }
        if !matches!(color_type, 0 | 2 | 4 | 6) {
            return Err(PngError::Unsupported);
        }

        Ok(Self {
            width,
            height,
            color_type,
        })
    }

    /// Samples per pixel, which is also the filter's byte offset between rows.
    fn channels(self) -> usize {
        match self.color_type {
            0 => 1,
            2 => 3,
            4 => 2,
            _ => 4,
        }
    }
}

/// Reverses the five row filters and widens every sample to the RGBA the scanner takes.
fn unfilter(
    raw: &[u8],
    header: Header,
    channels: usize,
    pixels: usize,
) -> Result<Vec<u8>, PngError> {
    let stride = header.width as usize * channels;
    let mut out = vec![0u8; pixels * 4];
    let mut previous = vec![0u8; stride];
    let mut current = vec![0u8; stride];

    for row in 0..header.height as usize {
        let start = row * (stride + 1);
        let filter = raw[start];
        current.copy_from_slice(&raw[start + 1..start + 1 + stride]);
        for index in 0..stride {
            let left = if index >= channels {
                current[index - channels]
            } else {
                0
            };
            let up = previous[index];
            let up_left = if index >= channels {
                previous[index - channels]
            } else {
                0
            };
            current[index] = match filter {
                0 => current[index],
                1 => current[index].wrapping_add(left),
                2 => current[index].wrapping_add(up),
                3 => current[index].wrapping_add(((left as u16 + up as u16) / 2) as u8),
                4 => current[index].wrapping_add(paeth(left, up, up_left)),
                _ => return Err(PngError::Corrupt),
            };
        }

        for column in 0..header.width as usize {
            let at = column * channels;
            // Widened to RGBA and no further: the luminance the scanner works on is computed by
            // the scanner's own constructor, from the Rec.601 fixed-point weights, and doing it
            // twice with two different formulas is how an image ends up just light enough to
            // lose a module.
            let (red, green, blue) = match header.color_type {
                0 | 4 => (current[at], current[at], current[at]),
                _ => (current[at], current[at + 1], current[at + 2]),
            };
            let target = (row * header.width as usize + column) * 4;
            out[target] = red;
            out[target + 1] = green;
            out[target + 2] = blue;
            out[target + 3] = 0xFF;
        }

        std::mem::swap(&mut previous, &mut current);
    }

    Ok(out)
}

/// The PNG spec's `Paeth` predictor (filter type 4).
fn paeth(left: u8, up: u8, up_left: u8) -> u8 {
    let (left, up, up_left) = (left as i16, up as i16, up_left as i16);
    let estimate = left + up - up_left;
    let d_left = (estimate - left).abs();
    let d_up = (estimate - up).abs();
    let d_up_left = (estimate - up_left).abs();

    if d_left <= d_up && d_left <= d_up_left {
        left as u8
    } else if d_up <= d_up_left {
        up as u8
    } else {
        up_left as u8
    }
}

/// Reads a big-endian `u32`, or reports that the file ends before it does.
fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, PngError> {
    let slice = bytes.get(offset..offset + 4).ok_or(PngError::Truncated)?;
    Ok(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::indexing_slicing, clippy::unwrap_used)]

    use super::{MAX_PIXELS, PngError, gray_from_png, paeth};

    /// A PNG written by the test itself, with the compression scheme whose decoder is trivial to
    /// check by hand: stored blocks, so the bytes of a row are the bytes in the file.
    fn png(width: u32, height: u32, color_type: u8, rows: &[Vec<u8>]) -> Vec<u8> {
        let channels = match color_type {
            0 => 1,
            2 => 3,
            4 => 2,
            _ => 4,
        };
        let mut raw = Vec::new();
        for row in rows {
            // Filter 0: no prediction, which is what makes this writer's output readable here.
            raw.push(0);
            raw.extend_from_slice(row);
        }
        assert_eq!(raw.len(), (width as usize * channels + 1) * height as usize);

        let mut out = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
        let mut ihdr = Vec::new();
        ihdr.extend_from_slice(&width.to_be_bytes());
        ihdr.extend_from_slice(&height.to_be_bytes());
        ihdr.extend_from_slice(&[8, color_type, 0, 0, 0]);
        chunk(&mut out, b"IHDR", &ihdr);
        chunk(
            &mut out,
            b"IDAT",
            &miniz_oxide::deflate::compress_to_vec_zlib(&raw, 6),
        );
        chunk(&mut out, b"IEND", &[]);
        out
    }

    /// Appends one chunk, with the CRC-32 the format requires.
    fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(kind);
        out.extend_from_slice(data);
        let mut crc_input = kind.to_vec();
        crc_input.extend_from_slice(data);
        out.extend_from_slice(&crc32(&crc_input).to_be_bytes());
    }

    fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0xFFFF_FFFFu32;
        for byte in data {
            crc ^= u32::from(*byte);
            for _ in 0..8 {
                // The polynomial is the one the format names, reflected.
                crc = if crc & 1 == 1 {
                    (crc >> 1) ^ 0xEDB8_8320
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }

    #[test]
    fn a_gray_row_survives_the_decoder() {
        let bytes = png(2, 1, 0, &[vec![0x00, 0xFF]]);
        let image = gray_from_png(&bytes).expect("the test's own PNG must decode");
        assert_eq!(image.pixels(), &[0x00, 0xFF]);
    }

    #[test]
    fn colour_is_reduced_to_the_luminance_the_scanner_wants() {
        // Pure green: the coefficients put it at 587/1000, and the red and blue channels must
        // contribute nothing to it.
        let bytes = png(2, 1, 2, &[vec![0xFF, 0x00, 0x00, 0x00, 0xFF, 0x00]]);
        let image = gray_from_png(&bytes).expect("a truecolour PNG must decode");
        assert_eq!(image.pixels()[0], 76);
        assert_eq!(image.pixels()[1], 149);
    }

    #[test]
    fn every_filter_is_reversed() {
        // Forward and back are written here independently: the encoder below follows the spec's
        // definition of each filter, and the decoder in this module has to undo it. A test that
        // reused the decoder's own code would only prove it agrees with itself.
        let row = [10u8, 20, 30, 40];
        for filter in 0u8..=4 {
            let first = encode_row(filter, &row, None);
            let second = encode_row(filter, &row, Some(&row));
            let mut bytes = png(4, 2, 0, &[vec![0; 4], vec![0; 4]]);
            let mut filtered = vec![filter];
            filtered.extend_from_slice(&first);
            filtered.push(filter);
            filtered.extend_from_slice(&second);
            replace_idat(
                &mut bytes,
                &miniz_oxide::deflate::compress_to_vec_zlib(&filtered, 6),
            );

            let image = gray_from_png(&bytes).expect("every filter must be reversed");
            assert_eq!(
                image.pixels(),
                &[10, 20, 30, 40, 10, 20, 30, 40],
                "filter {filter} did not come back"
            );
        }
    }

    /// One row of samples as a filter would write it, with [above] as the previous row.
    fn encode_row(filter: u8, row: &[u8], above: Option<&[u8]>) -> Vec<u8> {
        row.iter()
            .enumerate()
            .map(|(index, value)| {
                let left = if index == 0 { 0 } else { row[index - 1] };
                let up = above.map_or(0, |previous| previous[index]);
                let up_left = if index == 0 {
                    0
                } else {
                    above.map_or(0, |previous| previous[index - 1])
                };
                let predicted = match filter {
                    1 => left,
                    2 => up,
                    3 => ((u16::from(left) + u16::from(up)) / 2) as u8,
                    4 => paeth(left, up, up_left),
                    _ => 0,
                };
                value.wrapping_sub(predicted)
            })
            .collect()
    }
    /// Swaps the image data of a test PNG for another stream of the same length.
    fn replace_idat(bytes: &mut Vec<u8>, data: &[u8]) {
        let at = bytes
            .windows(4)
            .position(|window| window == b"IDAT")
            .expect("the test PNG has an IDAT");
        let end = bytes
            .windows(4)
            .position(|window| window == b"IEND")
            .expect("the test PNG has an IEND")
            - 4;
        let mut out = Vec::new();
        out.extend_from_slice(&bytes[..at - 4]);
        chunk(&mut out, b"IDAT", data);
        out.extend_from_slice(&bytes[end..]);
        *bytes = out;
    }

    #[test]
    fn what_is_not_a_png_is_refused() {
        assert_eq!(gray_from_png(b"").unwrap_err(), PngError::NotPng);
        assert_eq!(
            gray_from_png(b"not a png at all").unwrap_err(),
            PngError::NotPng
        );
    }

    #[test]
    fn a_cut_short_file_is_refused_rather_than_read_past() {
        let bytes = png(2, 1, 0, &[vec![0x00, 0xFF]]);
        for cut in 8..bytes.len() - 4 {
            assert!(
                gray_from_png(&bytes[..cut]).is_err(),
                "a file cut at {cut} of {} must be refused",
                bytes.len()
            );
        }
    }

    #[test]
    fn a_feature_outside_the_format_is_refused() {
        // Sixteen-bit samples.
        let mut bytes = png(2, 1, 0, &[vec![0x00, 0xFF]]);
        bytes[16 + 8] = 16;
        assert_eq!(gray_from_png(&bytes).unwrap_err(), PngError::Unsupported);

        // An interlaced image, same idea.
        let mut interlaced = png(2, 1, 0, &[vec![0x00, 0xFF]]);
        interlaced[16 + 12] = 1;
        assert_eq!(
            gray_from_png(&interlaced).unwrap_err(),
            PngError::Unsupported
        );

        // A palette, which this reader does not translate.
        let mut palette = png(2, 1, 0, &[vec![0x00, 0xFF]]);
        palette[16 + 9] = 3;
        assert_eq!(gray_from_png(&palette).unwrap_err(), PngError::Unsupported);
    }

    #[test]
    fn an_image_larger_than_the_bound_is_refused_before_anything_is_allocated() {
        let mut bytes = png(2, 1, 0, &[vec![0x00, 0xFF]]);
        let side = MAX_PIXELS + 1;
        bytes[16..20].copy_from_slice(&side.to_be_bytes());
        bytes[20..24].copy_from_slice(&1u32.to_be_bytes());
        assert_eq!(gray_from_png(&bytes).unwrap_err(), PngError::TooLarge);
    }

    #[test]
    fn the_paeth_predictor_picks_the_nearest_neighbour() {
        // p = 10 + 20 - 30 = 0, so the distances are 10, 20 and 30: the left sample wins, even
        // though the one above it is numerically closer to the value being predicted.
        assert_eq!(paeth(10, 20, 30), 10);
        assert_eq!(paeth(0, 0, 0), 0);
        assert_eq!(paeth(255, 0, 0), 255);
    }
}
