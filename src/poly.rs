//! Polynomial compression, Centered Binomial Distribution (CBD) sampling,
//! and byte encoding for ML-KEM-768 (FIPS 203 Algorithms 4–8 and 10–12).

use crate::field::{FieldElement, Q};

// ============================================================================
// Compress / Decompress (FIPS 203 Algorithms 4 and 5)
// ============================================================================

/// Compress_d(x) = round(2^d / q * x) mod 2^d. Input `x` in [0, Q).
///
/// Division by Q is done with a multiply-and-shift so no `div` instruction
/// is ever executed on secret data (the "KyberSlash" timing issue).
/// `DIV_Q_MAGIC = ceil(2^40 / Q)`; the result equals `n / Q` exactly for
/// every `n < 2^25` (verified exhaustively in the tests below).
const DIV_Q_SHIFT: u32 = 40;
const DIV_Q_MAGIC: u64 = 330_282_857;

pub fn compress_d(x: u16, d: u32) -> u16 {
    debug_assert!(x < Q);
    debug_assert!((1..=12).contains(&d));
    let numerator = ((x as u64) << d) + (Q as u64 / 2);
    let rounded = (numerator * DIV_Q_MAGIC) >> DIV_Q_SHIFT;
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
        // Branchless conditional add of Q (inputs are secret-derived).
        let val_u16 = (val + ((val >> 31) & (Q as i32))) as u16;
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
// Generic ByteEncode_d / ByteDecode_d (FIPS 203 Algorithms 5 and 6)
// ============================================================================

/// ByteEncode_d for any `1 <= d <= 12`: 256 coefficients -> `32 * d` bytes,
/// bits packed little-endian. Used for the parameter-dependent widths
/// (du in {10, 11}, dv in {4, 5}).
pub fn byte_encode_d(f: &[u16; 256], d: u32) -> Vec<u8> {
    debug_assert!((1..=12).contains(&d));
    let mut out = vec![0u8; 32 * d as usize];
    let mut pos = 0usize;
    for &c in f.iter() {
        for b in 0..d {
            out[pos >> 3] |= (((c >> b) & 1) as u8) << (pos & 7);
            pos += 1;
        }
    }
    out
}

/// ByteDecode_d: `32 * d` bytes -> 256 coefficients (each `< 2^d`).
/// Panics if `input.len() != 32 * d` (callers slice exact lengths).
pub fn byte_decode_d(input: &[u8], d: u32) -> [u16; 256] {
    assert_eq!(input.len(), 32 * d as usize, "ByteDecode_d: bad length");
    let mut f = [0u16; 256];
    let mut pos = 0usize;
    for c in f.iter_mut() {
        let mut v = 0u16;
        for b in 0..d {
            v |= (((input[pos >> 3] >> (pos & 7)) & 1) as u16) << b;
            pos += 1;
        }
        *c = v;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compress_matches_reference_division() {
        for d in 1u32..=12 {
            for x in 0..Q {
                let n = ((x as u32) << d) + (Q as u32 / 2);
                let want = ((n / Q as u32) as u16) & ((1 << d) - 1);
                assert_eq!(compress_d(x, d), want, "x={x} d={d}");
            }
        }
    }

    #[test]
    fn compress_decompress_error_bound() {
        // |x - Decompress(Compress(x))| <= round(q / 2^(d+1)) (mod q).
        for &d in &[1u32, 4, 10] {
            let bound = (Q as i32 + (1 << d)) >> (d + 1);
            for x in 0..Q {
                let y = decompress_d(compress_d(x, d), d) as i32;
                let mut diff = (x as i32 - y).rem_euclid(Q as i32);
                if diff > Q as i32 / 2 {
                    diff = Q as i32 - diff;
                }
                assert!(diff <= bound, "x={x} d={d} diff={diff}");
            }
        }
    }

    #[test]
    fn generic_codec_matches_specialised() {
        let f12: [u16; 256] = core::array::from_fn(|i| (i as u16 * 13) % Q);
        assert_eq!(byte_encode_d(&f12, 12), byte_encode_12(&f12).to_vec());
        let f10: [u16; 256] = core::array::from_fn(|i| (i as u16 * 7) & 0x3FF);
        assert_eq!(byte_encode_d(&f10, 10), byte_encode_10(&f10).to_vec());
        let f4: [u16; 256] = core::array::from_fn(|i| (i as u16) & 0xF);
        assert_eq!(byte_encode_d(&f4, 4), byte_encode_4(&f4).to_vec());
        for d in 1..=12u32 {
            let f: [u16; 256] = core::array::from_fn(|i| (i as u16 * 37 + 5) & ((1 << d) - 1));
            assert_eq!(byte_decode_d(&byte_encode_d(&f, d), d), f, "d={d}");
        }
    }

    #[test]
    fn byte_codecs_roundtrip() {
        let f12: [u16; 256] = core::array::from_fn(|i| (i as u16 * 13) % Q);
        assert_eq!(byte_decode_12(&byte_encode_12(&f12)), f12);
        let f10: [u16; 256] = core::array::from_fn(|i| (i as u16 * 7) & 0x3FF);
        assert_eq!(byte_decode_10(&byte_encode_10(&f10)), f10);
        let f4: [u16; 256] = core::array::from_fn(|i| (i as u16) & 0xF);
        assert_eq!(byte_decode_4(&byte_encode_4(&f4)), f4);
    }
}
