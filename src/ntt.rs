//! Number-Theoretic Transform for ML-KEM-768, following FIPS 203.

use crate::field::{FieldElement, Q, QINV};

const fn bitrev7(x: u8) -> u8 {
    let mut result = 0u8;
    let mut i = 0u8;
    while i < 7 {
        if x & (1 << i) != 0 {
            result |= 1 << (6 - i);
        }
        i += 1;
    }
    result
}

const fn pow_zeta(exp: u32) -> u16 {
    let mut result: u32 = 1;
    let mut base: u32 = 17;
    let mut e = exp;
    while e > 0 {
        if e & 1 == 1 {
            result = (result * base) % (Q as u32);
        }
        base = (base * base) % (Q as u32);
        e >>= 1;
    }
    result as u16
}

const fn mont_reduce(a: u32) -> u16 {
    let a_i32 = a as i32;
    let t = (a_i32 as i16).wrapping_mul(QINV) as i32;
    let u = (a_i32 - t * (Q as i32)) >> 16;
    let u = u + ((u >> 31) & (Q as i32));
    u as u16
}

const fn to_mont(x: u16) -> u16 {
    mont_reduce((x as u32) * 1353)
}

/// ZETAS[k] = ζ^bitrev7(k) * R mod Q (Montgomery form of ζ^bitrev7(k)).
const ZETAS: [u16; 128] = {
    let mut zetas = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        let exp = bitrev7(i as u8) as u32;
        let z = pow_zeta(exp);
        zetas[i] = to_mont(z);
        i += 1;
    }
    zetas
};

// F_INV_NTT is R / 128 mod q = 512. Multiplying each coefficient by
// this in Montgomery form undoes the 128× scaling of the inverse NTT
// while keeping the result in Montgomery representation.
const F_INV_NTT: u16 = 512;

pub fn ntt(f: &mut [FieldElement; 256]) {
    let mut k = 1;
    let mut len = 128;
    while len >= 2 {
        let mut start = 0;
        while start < 256 {
            let zeta = FieldElement::from_mont(ZETAS[k]);
            k += 1;
            let mut j = start;
            while j < start + len {
                let t = f[j + len] * zeta;
                f[j + len] = f[j] - t;
                f[j] = f[j] + t;
                j += 1;
            }
            start = j + len;
        }
        len >>= 1;
    }
}

pub fn inv_ntt(f: &mut [FieldElement; 256]) {
    let mut k = 127;
    let mut len = 2;
    while len <= 128 {
        let mut start = 0;
        while start < 256 {
            let zeta = FieldElement::from_mont(ZETAS[k]);
            k = k.wrapping_sub(1);
            let mut j = start;
            while j < start + len {
                let t = f[j];
                f[j] = t + f[j + len];
                f[j + len] = (f[j + len] - t) * zeta;
                j += 1;
            }
            start = j + len;
        }
        len <<= 1;
    }
    let f_inv = FieldElement::from_mont(F_INV_NTT);
    for x in f.iter_mut() {
        *x = *x * f_inv;
    }
}

pub fn basemul(a: &[FieldElement; 256], b: &[FieldElement; 256]) -> [FieldElement; 256] {
    let mut result = [FieldElement::ZERO; 256];
    let mut i = 0;
    while i < 64 {
        let zeta = FieldElement::from_mont(ZETAS[64 + i]);
        let neg_zeta = -zeta;

        result[4 * i] = a[4 * i] * b[4 * i] + (a[4 * i + 1] * b[4 * i + 1]) * zeta;
        result[4 * i + 1] = a[4 * i] * b[4 * i + 1] + a[4 * i + 1] * b[4 * i];

        result[4 * i + 2] = a[4 * i + 2] * b[4 * i + 2] + (a[4 * i + 3] * b[4 * i + 3]) * neg_zeta;
        result[4 * i + 3] = a[4 * i + 2] * b[4 * i + 3] + a[4 * i + 3] * b[4 * i + 2];

        i += 1;
    }
    result
}

pub fn poly_mul(a: &[FieldElement; 256], b: &[FieldElement; 256]) -> [FieldElement; 256] {
    let mut ah = *a;
    let mut bh = *b;
    ntt(&mut ah);
    ntt(&mut bh);
    let mut product = basemul(&ah, &bh);
    inv_ntt(&mut product);
    product
}
