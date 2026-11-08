//! IND-CPA public-key encryption (K-PKE) for ML-KEM-768.
//! FIPS 203 Algorithms 13, 14, 15.

use crate::field::{FieldElement, Q};
use crate::keccak::{sha3_512, shake_128, shake_256};
use crate::ntt::{basemul, inv_ntt, ntt};
use crate::poly::{
    byte_decode_4, byte_decode_10, byte_decode_12, byte_encode_4, byte_encode_10, byte_encode_12,
    cbd_eta2, compress_d, decompress_d, poly_from_u16, poly_to_u16,
};

pub const K: usize = 3;
pub const ETA1: u32 = 2;
pub const ETA2: u32 = 2;
pub const DU: u32 = 10;
pub const DV: u32 = 4;

pub const PKE_PUBLIC_KEY_BYTES: usize = 384 * K + 32; // 1184
pub const PKE_SECRET_KEY_BYTES: usize = 384 * K; // 1152
pub const PKE_CIPHERTEXT_BYTES: usize = 32 * DU as usize * K + 32 * DV as usize; // 1088

type Poly = [FieldElement; 256];
type PolyVec = [Poly; K];
type PolyMat = [[Poly; K]; K];

fn sample_ntt(seed: &[u8; 34]) -> Poly {
    let xof = shake_128(seed, 1024);
    let mut coeffs = [0u16; 256];
    let mut ctr = 0;
    let mut pos = 0;
    while ctr < 256 && pos + 3 <= xof.len() {
        let val0 = (xof[pos] as u16) | (((xof[pos + 1] as u16) & 0x0F) << 8);
        let val1 = ((xof[pos + 1] as u16) >> 4) | ((xof[pos + 2] as u16) << 4);
        pos += 3;
        if val0 < Q {
            coeffs[ctr] = val0;
            ctr += 1;
        }
        if ctr < 256 && val1 < Q {
            coeffs[ctr] = val1;
            ctr += 1;
        }
    }
    assert_eq!(ctr, 256, "SampleNTT failed to produce 256 coefficients");
    poly_from_u16(&coeffs)
}

fn gen_matrix(rho: &[u8; 32], transposed: bool) -> PolyMat {
    core::array::from_fn(|i| {
        core::array::from_fn(|j| {
            let mut seed = [0u8; 34];
            seed[..32].copy_from_slice(rho);
            if transposed {
                seed[32] = i as u8;
                seed[33] = j as u8;
            } else {
                seed[32] = j as u8;
                seed[33] = i as u8;
            }
            sample_ntt(&seed)
        })
    })
}

fn sample_cbd(sigma: &[u8; 32], n: u8, eta: u32) -> Poly {
    debug_assert_eq!(eta, 2, "only eta=2 supported");
    let mut input = [0u8; 33];
    input[..32].copy_from_slice(sigma);
    input[32] = n;
    let bytes = shake_256(&input, 128);
    let mut fixed = [0u8; 128];
    fixed.copy_from_slice(&bytes);
    cbd_eta2(&fixed)
}

fn poly_add(a: &Poly, b: &Poly) -> Poly {
    core::array::from_fn(|i| a[i] + b[i])
}

fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    core::array::from_fn(|i| a[i] - b[i])
}

fn poly_zero() -> Poly {
    [FieldElement::ZERO; 256]
}

// ============================================================================
// K-PKE.KeyGen (FIPS 203 Algorithm 13)
// ============================================================================

pub fn pke_keygen(d: &[u8; 32]) -> ([u8; PKE_PUBLIC_KEY_BYTES], [u8; PKE_SECRET_KEY_BYTES]) {
    let mut g_input = [0u8; 33];
    g_input[..32].copy_from_slice(d);
    g_input[32] = K as u8;
    let g_out = sha3_512(&g_input);
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];
    rho.copy_from_slice(&g_out[..32]);
    sigma.copy_from_slice(&g_out[32..]);

    let a_hat = gen_matrix(&rho, false);

    let mut n: u8 = 0;
    let mut s: PolyVec = core::array::from_fn(|_| {
        let p = sample_cbd(&sigma, n, ETA1);
        n += 1;
        p
    });
    let mut e: PolyVec = core::array::from_fn(|_| {
        let p = sample_cbd(&sigma, n, ETA1);
        n += 1;
        p
    });

    for i in 0..K {
        ntt(&mut s[i]);
        ntt(&mut e[i]);
    }

    let t_hat: PolyVec = core::array::from_fn(|i| {
        let mut acc = poly_zero();
        for j in 0..K {
            acc = poly_add(&acc, &basemul(&a_hat[i][j], &s[j]));
        }
        poly_add(&acc, &e[i])
    });

    let mut ek = [0u8; PKE_PUBLIC_KEY_BYTES];
    for i in 0..K {
        let t_u16 = poly_to_u16(&t_hat[i]);
        ek[i * 384..(i + 1) * 384].copy_from_slice(&byte_encode_12(&t_u16));
    }
    ek[384 * K..].copy_from_slice(&rho);

    let mut dk = [0u8; PKE_SECRET_KEY_BYTES];
    for i in 0..K {
        let s_u16 = poly_to_u16(&s[i]);
        dk[i * 384..(i + 1) * 384].copy_from_slice(&byte_encode_12(&s_u16));
    }

    (ek, dk)
}

// ============================================================================
// K-PKE.Encrypt (FIPS 203 Algorithm 14)
// ============================================================================

pub fn pke_encrypt(
    ek: &[u8; PKE_PUBLIC_KEY_BYTES],
    m: &[u8; 32],
    r: &[u8; 32],
) -> [u8; PKE_CIPHERTEXT_BYTES] {
    let t_hat: PolyVec = core::array::from_fn(|i| {
        let mut chunk = [0u8; 384];
        chunk.copy_from_slice(&ek[i * 384..(i + 1) * 384]);
        poly_from_u16(&byte_decode_12(&chunk))
    });
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[384 * K..]);

    let a_t = gen_matrix(&rho, true);

    let mut n: u8 = 0;
    let mut r_vec: PolyVec = core::array::from_fn(|_| {
        let p = sample_cbd(r, n, ETA1);
        n += 1;
        p
    });
    let e1: PolyVec = core::array::from_fn(|_| {
        let p = sample_cbd(r, n, ETA2);
        n += 1;
        p
    });
    let e2 = sample_cbd(r, n, ETA2);

    for poly in r_vec.iter_mut() {
        ntt(poly);
    }

    let u: PolyVec = core::array::from_fn(|i| {
        let mut acc = poly_zero();
        for j in 0..K {
            acc = poly_add(&acc, &basemul(&a_t[i][j], &r_vec[j]));
        }
        inv_ntt(&mut acc);
        poly_add(&acc, &e1[i])
    });

    let mut v = poly_zero();
    for j in 0..K {
        v = poly_add(&v, &basemul(&t_hat[j], &r_vec[j]));
    }
    inv_ntt(&mut v);
    let v = poly_add(&v, &e2);

    // Step 10: μ = Decompress_1(ByteDecode_1(m))
    let mut mu = [FieldElement::ZERO; 256];
    for k in 0..256 {
        let bit = ((m[k / 8] >> (k % 8)) & 1) as u16;
        mu[k] = FieldElement::from_u16(decompress_d(bit, 1));
    }

    // Step 11: v = InvNTT(t̂ᵀ ∘ r̂) + e₂ + μ
    let v = poly_add(&v, &mu);

    let mut c = [0u8; PKE_CIPHERTEXT_BYTES];
    for i in 0..K {
        let u_u16 = poly_to_u16(&u[i]);
        let compressed: [u16; 256] = core::array::from_fn(|k| compress_d(u_u16[k], DU));
        c[i * 320..(i + 1) * 320].copy_from_slice(&byte_encode_10(&compressed));
    }
    let v_u16 = poly_to_u16(&v);
    let compressed_v: [u16; 256] = core::array::from_fn(|k| compress_d(v_u16[k], DV));
    c[320 * K..].copy_from_slice(&byte_encode_4(&compressed_v));

    c
}

// ============================================================================
// K-PKE.Decrypt (FIPS 203 Algorithm 15)
// ============================================================================

pub fn pke_decrypt(dk: &[u8; PKE_SECRET_KEY_BYTES], c: &[u8; PKE_CIPHERTEXT_BYTES]) -> [u8; 32] {
    let u_prime: PolyVec = core::array::from_fn(|i| {
        let mut chunk = [0u8; 320];
        chunk.copy_from_slice(&c[i * 320..(i + 1) * 320]);
        let u_u16 = byte_decode_10(&chunk);
        let mut coeffs = [FieldElement::ZERO; 256];
        for k in 0..256 {
            coeffs[k] = FieldElement::from_u16(decompress_d(u_u16[k], DU));
        }
        coeffs
    });
    let mut v_chunk = [0u8; 128];
    v_chunk.copy_from_slice(&c[320 * K..]);
    let v_u16 = byte_decode_4(&v_chunk);
    let mut v_prime = [FieldElement::ZERO; 256];
    for k in 0..256 {
        v_prime[k] = FieldElement::from_u16(decompress_d(v_u16[k], DV));
    }

    let s_hat: PolyVec = core::array::from_fn(|i| {
        let mut chunk = [0u8; 384];
        chunk.copy_from_slice(&dk[i * 384..(i + 1) * 384]);
        poly_from_u16(&byte_decode_12(&chunk))
    });

    let mut u_hat = u_prime;
    for poly in u_hat.iter_mut() {
        ntt(poly);
    }
    let mut acc = poly_zero();
    for j in 0..K {
        acc = poly_add(&acc, &basemul(&s_hat[j], &u_hat[j]));
    }
    inv_ntt(&mut acc);
    let w = poly_sub(&v_prime, &acc);

    let w_u16 = poly_to_u16(&w);
    let mut m = [0u8; 32];
    for k in 0..256 {
        let bit = compress_d(w_u16[k], 1);
        m[k / 8] |= (bit as u8) << (k % 8);
    }
    m
}
