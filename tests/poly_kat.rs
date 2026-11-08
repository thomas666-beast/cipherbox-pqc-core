//! Tests for compression, CBD sampling, and byte encoding.

use cipherbox_pqc_core::field::{FieldElement, Q};
use cipherbox_pqc_core::poly::{
    byte_decode_4, byte_decode_10, byte_decode_12, byte_encode_4, byte_encode_10, byte_encode_12,
    cbd_eta2, compress_d, decompress_d,
};

// ---- Compress / Decompress ----

#[test]
fn compress_decompress_10_roundtrip() {
    for y in 0u16..1024 {
        let x = decompress_d(y, 10);
        assert!(x < Q);
        let recovered = compress_d(x, 10);
        assert_eq!(recovered, y, "d=10 roundtrip at y = {y}");
    }
}

#[test]
fn compress_decompress_4_roundtrip() {
    for y in 0u16..16 {
        let x = decompress_d(y, 4);
        assert!(x < Q);
        let recovered = compress_d(x, 4);
        assert_eq!(recovered, y, "d=4 roundtrip at y = {y}");
    }
}

#[test]
fn compress_range() {
    for x in 0u16..Q {
        assert!(compress_d(x, 10) < 1024);
        assert!(compress_d(x, 4) < 16);
    }
}

// ---- CBD ----

#[test]
fn cbd_eta2_all_zero_input() {
    let input = [0u8; 128];
    let f = cbd_eta2(&input);
    for (i, c) in f.iter().enumerate() {
        assert_eq!(c.to_u16(), 0, "at index {i}");
    }
}

#[test]
fn cbd_eta2_all_ff_input() {
    // 0xFF = 11111111: each i takes [1,1,1,1] → a=2, b=2, f=0.
    let input = [0xFFu8; 128];
    let f = cbd_eta2(&input);
    for (i, c) in f.iter().enumerate() {
        assert_eq!(c.to_u16(), 0, "at index {i}");
    }
}

#[test]
fn cbd_eta2_0x33_input() {
    // 0x33 = 00110011: bits [1,1,0,0, 1,1,0,0].
    // For i: a = bit0 + bit1 = 1 + 1 = 2, b = bit2 + bit3 = 0 + 0 = 0.
    // f[i] = 2 for all i.
    let input = [0x33u8; 128];
    let f = cbd_eta2(&input);
    for (i, c) in f.iter().enumerate() {
        assert_eq!(c.to_u16(), 2, "at index {i}");
    }
}

#[test]
fn cbd_eta2_0xcc_input() {
    // 0xCC = 11001100: bits [0,0,1,1, 0,0,1,1].
    // For i: a = 0+0 = 0, b = 1+1 = 2. f[i] = -2 = Q-2 = 3327.
    let input = [0xCCu8; 128];
    let f = cbd_eta2(&input);
    for (i, c) in f.iter().enumerate() {
        assert_eq!(c.to_u16(), Q - 2, "at index {i}");
    }
}

#[test]
fn cbd_eta2_coefficient_range() {
    // Pseudorandom input: all coefficients must be in [Q-2, 2] mod Q.
    let mut input = [0u8; 128];
    for (i, b) in input.iter_mut().enumerate() {
        *b = (i.wrapping_mul(41).wrapping_add(17) & 0xFF) as u8;
    }
    let f = cbd_eta2(&input);
    for (i, c) in f.iter().enumerate() {
        let v = c.to_u16();
        assert!(
            v <= 2 || v >= Q - 2,
            "coefficient {i} = {v} out of CBD_2 range"
        );
    }
}

// ---- Byte encoding ----

#[test]
fn byte_encode_decode_12_roundtrip() {
    let mut f = [0u16; 256];
    for (i, c) in f.iter_mut().enumerate() {
        *c = ((i * 13 + 7) % Q as usize) as u16;
    }
    let encoded = byte_encode_12(&f);
    let decoded = byte_decode_12(&encoded);
    assert_eq!(decoded, f);
}

#[test]
fn byte_encode_12_all_zeros() {
    let f = [0u16; 256];
    let encoded = byte_encode_12(&f);
    assert!(encoded.iter().all(|&b| b == 0));
    let decoded = byte_decode_12(&encoded);
    assert_eq!(decoded, f);
}

#[test]
fn byte_encode_12_all_fff() {
    // 0xFFF = 4095, encodes to all 0xFF bytes.
    let mut f = [0u16; 256];
    for c in f.iter_mut() {
        *c = 0xFFF;
    }
    let encoded = byte_encode_12(&f);
    assert!(encoded.iter().all(|&b| b == 0xFF));
    let decoded = byte_decode_12(&encoded);
    assert_eq!(decoded, f);
}

#[test]
fn byte_encode_decode_10_roundtrip() {
    let mut f = [0u16; 256];
    for (i, c) in f.iter_mut().enumerate() {
        *c = ((i * 17 + 3) % 1024) as u16;
    }
    let encoded = byte_encode_10(&f);
    let decoded = byte_decode_10(&encoded);
    assert_eq!(decoded, f);
}

#[test]
fn byte_encode_10_all_3ff() {
    // 0x3FF = 1023, encodes to all 0xFF bytes.
    let mut f = [0u16; 256];
    for c in f.iter_mut() {
        *c = 0x3FF;
    }
    let encoded = byte_encode_10(&f);
    assert!(encoded.iter().all(|&b| b == 0xFF));
    let decoded = byte_decode_10(&encoded);
    assert_eq!(decoded, f);
}

#[test]
fn byte_encode_decode_4_roundtrip() {
    let mut f = [0u16; 256];
    for (i, c) in f.iter_mut().enumerate() {
        *c = ((i * 7 + 1) % 16) as u16;
    }
    let encoded = byte_encode_4(&f);
    let decoded = byte_decode_4(&encoded);
    assert_eq!(decoded, f);
}

#[test]
fn byte_encode_4_all_f() {
    // 0xF = 15, encodes to all 0xFF bytes.
    let mut f = [0u16; 256];
    for c in f.iter_mut() {
        *c = 0xF;
    }
    let encoded = byte_encode_4(&f);
    assert!(encoded.iter().all(|&b| b == 0xFF));
    let decoded = byte_decode_4(&encoded);
    assert_eq!(decoded, f);
}

#[test]
fn byte_encode_10_with_compress_roundtrip() {
    // Compress a FieldElement polynomial, encode as 10 bits, decode, decompress.
    // The compressed value must survive the roundtrip.
    let mut f = [FieldElement::ZERO; 256];
    for (i, c) in f.iter_mut().enumerate() {
        *c = FieldElement::from_u16(((i * 37 + 11) % Q as usize) as u16);
    }
    let mut compressed = [0u16; 256];
    for (i, c) in f.iter().enumerate() {
        compressed[i] = compress_d(c.to_u16(), 10);
    }
    let encoded = byte_encode_10(&compressed);
    let decoded = byte_decode_10(&encoded);
    assert_eq!(decoded, compressed);

    // Decompress to FieldElement and re-compress — must be stable.
    let mut recompressed = [0u16; 256];
    for (i, c) in decoded.iter().enumerate() {
        let x = decompress_d(*c, 10);
        recompressed[i] = compress_d(x, 10);
    }
    assert_eq!(recompressed, compressed);
}
