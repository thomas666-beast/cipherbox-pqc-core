//! Polynomial compression, Centered Binomial Distribution (CBD) sampling,
//! and byte encoding for ML-KEM-768 (FIPS 203 Algorithms 4–8 and 10–12).

use crate::field::{FieldElement, Q};

// ============================================================================
// Compress / Decompress (FIPS 203 Algorithms 4 and 5)
// ============================================================================

/// Compress_d(x) = round(2^d / q * x) mod 2^d. Input `x` in [0, Q).
pub fn compress_d(x: u16, d: u32) -> u16 {
    debug_assert!(x < Q);
    debug_assert!((1..=12).contains(&d));
    let numerator = ((x as u32) << d) + (Q as u32 / 2);
    let rounded = numerator / (Q as u32);
    (rounded as u16) & ((1 << d) - 1)
}

/// Decompress_d(y) = round(q / 2^d * y). Input `y` in [0, 2^d).
/// Output in [0, Q).
pub fn decompress_d(y: u16, d: u32) -> u16 {
    debug_assert!(d >= 1);
    debug_assert!((y as u32) < (1u32 << d));
    let numerator = (y as u32) * (Q as u32) + (1u32 << (d - 1));
    (numerator >> d) as u16
}

// ============================================================================
// CBD sampling (FIPS 203 Algorithm 8), eta = 2
// ============================================================================

#[inline]
fn bit(input: &[u8], pos: usize) -> u16 {
    ((input[pos >> 3] >> (pos & 7)) & 1) as u16
}

/// CBD_2: 128 input bytes, 256 output coefficients.
///
/// For each i, take 4 consecutive bits (starting at bit 4*i) from the
/// input stream: the first 2 are summed for `a`, the next 2 for `b`,
/// and f[i] = a - b mod q.
pub fn cbd_eta2(input: &[u8; 128]) -> [FieldElement; 256] {
    let mut f = [FieldElement::ZERO; 256];
    for (i, coeff) in f.iter_mut().enumerate() {
        let base = 4 * i;
        let a = bit(input, base) + bit(input, base + 1);
        let b = bit(input, base + 2) + bit(input, base + 3);
        let val = (a as i32) - (b as i32);
        let val_u16 = if val < 0 {
            (Q as i32 + val) as u16
        } else {
            val as u16
        };
        *coeff = FieldElement::from_u16(val_u16);
    }
    f
}

// ============================================================================
// Byte encoding (FIPS 203 Algorithms 10, 11, 12)
// ============================================================================

/// ByteEncode_12: 256 coefficients (each < Q) → 384 bytes.
/// 2 coefficients → 3 bytes.
pub fn byte_encode_12(f: &[u16; 256]) -> [u8; 384] {
    let mut out = [0u8; 384];
    for i in 0..128 {
        let a = f[2 * i] as u32;
        let b = f[2 * i + 1] as u32;
        let combined = a | (b << 12);
        out[3 * i] = (combined & 0xFF) as u8;
        out[3 * i + 1] = ((combined >> 8) & 0xFF) as u8;
        out[3 * i + 2] = ((combined >> 16) & 0xFF) as u8;
    }
    out
}

/// ByteDecode_12: 384 bytes → 256 coefficients, each < 4096.
pub fn byte_decode_12(input: &[u8; 384]) -> [u16; 256] {
    let mut f = [0u16; 256];
    for i in 0..128 {
        let combined = (input[3 * i] as u32)
            | ((input[3 * i + 1] as u32) << 8)
            | ((input[3 * i + 2] as u32) << 16);
        f[2 * i] = (combined & 0xFFF) as u16;
        f[2 * i + 1] = ((combined >> 12) & 0xFFF) as u16;
    }
    f
}

/// ByteEncode_10: 256 coefficients (each < 1024) → 320 bytes.
/// 4 coefficients → 5 bytes.
pub fn byte_encode_10(f: &[u16; 256]) -> [u8; 320] {
    let mut out = [0u8; 320];
    for i in 0..64 {
        let a = f[4 * i] as u64;
        let b = f[4 * i + 1] as u64;
        let c = f[4 * i + 2] as u64;
        let d = f[4 * i + 3] as u64;
        let combined = a | (b << 10) | (c << 20) | (d << 30);
        out[5 * i] = (combined & 0xFF) as u8;
        out[5 * i + 1] = ((combined >> 8) & 0xFF) as u8;
        out[5 * i + 2] = ((combined >> 16) & 0xFF) as u8;
        out[5 * i + 3] = ((combined >> 24) & 0xFF) as u8;
        out[5 * i + 4] = ((combined >> 32) & 0xFF) as u8;
    }
    out
}

/// ByteDecode_10: 320 bytes → 256 coefficients, each < 1024.
pub fn byte_decode_10(input: &[u8; 320]) -> [u16; 256] {
    let mut f = [0u16; 256];
    for i in 0..64 {
        let combined = (input[5 * i] as u64)
            | ((input[5 * i + 1] as u64) << 8)
            | ((input[5 * i + 2] as u64) << 16)
            | ((input[5 * i + 3] as u64) << 24)
            | ((input[5 * i + 4] as u64) << 32);
        f[4 * i] = (combined & 0x3FF) as u16;
        f[4 * i + 1] = ((combined >> 10) & 0x3FF) as u16;
        f[4 * i + 2] = ((combined >> 20) & 0x3FF) as u16;
        f[4 * i + 3] = ((combined >> 30) & 0x3FF) as u16;
    }
    f
}

/// ByteEncode_4: 256 coefficients (each < 16) → 128 bytes.
/// 2 coefficients → 1 byte.
pub fn byte_encode_4(f: &[u16; 256]) -> [u8; 128] {
    let mut out = [0u8; 128];
    for i in 0..128 {
        let a = (f[2 * i] & 0xF) as u8;
        let b = (f[2 * i + 1] & 0xF) as u8;
        out[i] = a | (b << 4);
    }
    out
}

/// ByteDecode_4: 128 bytes → 256 coefficients, each < 16.
pub fn byte_decode_4(input: &[u8; 128]) -> [u16; 256] {
    let mut f = [0u16; 256];
    for i in 0..128 {
        f[2 * i] = (input[i] & 0xF) as u16;
        f[2 * i + 1] = ((input[i] >> 4) & 0xF) as u16;
    }
    f
}

// ============================================================================
// Convenience conversions
// ============================================================================

pub fn poly_to_u16(f: &[FieldElement; 256]) -> [u16; 256] {
    let mut out = [0u16; 256];
    for (i, c) in f.iter().enumerate() {
        out[i] = c.to_u16();
    }
    out
}

pub fn poly_from_u16(f: &[u16; 256]) -> [FieldElement; 256] {
    let mut out = [FieldElement::ZERO; 256];
    for (i, c) in f.iter().enumerate() {
        out[i] = FieldElement::from_u16(*c);
    }
    out
}
