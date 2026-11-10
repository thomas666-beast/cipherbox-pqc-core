//! IND-CPA public-key encryption (K-PKE), FIPS 203 Algorithms 13, 14, 15,
//! generic over the parameter set (ML-KEM-768 and ML-KEM-1024).

use crate::field::{FieldElement, Q};
use crate::keccak::{sha3_512, shake_128, shake_256};
use crate::ntt::{basemul, inv_ntt, ntt};
use crate::params::{ETA1, ETA2, KemLevel};
use crate::poly::{
    byte_decode_d, byte_encode_d, cbd_eta2, compress_d, decompress_d, poly_from_u16, poly_to_u16,
};
use zeroize::Zeroize;

type Poly = [FieldElement; 256];

fn sample_ntt(seed: &[u8; 34]) -> Poly {
    // 1008 bytes almost always suffice; if not, re-squeeze a longer prefix
    // of the same XOF stream instead of panicking.
    let mut xof_len = 1008usize;
    loop {
        let xof = shake_128(seed, xof_len);
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
        if ctr == 256 {
            return poly_from_u16(&coeffs);
        }
        xof_len *= 2;
    }
}

/// `A[i][j] = SampleNTT(rho || j || i)`; with `transposed`, entry `[i][j]`
/// is `A[j][i]` (seed bytes `i`, `j`).
fn gen_matrix(rho: &[u8; 32], k: usize, transposed: bool) -> Vec<Vec<Poly>> {
    (0..k)
        .map(|i| {
            (0..k)
                .map(|j| {
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
                .collect()
        })
        .collect()
}

fn sample_cbd(sigma: &[u8; 32], n: u8, eta: u32) -> Poly {
    debug_assert_eq!(eta, 2, "only eta=2 supported");
    let mut input = [0u8; 33];
    input[..32].copy_from_slice(sigma);
    input[32] = n;
    let mut bytes = shake_256(&input, 128);
    let mut fixed = [0u8; 128];
    fixed.copy_from_slice(&bytes);
    let p = cbd_eta2(&fixed);
    bytes.zeroize();
    fixed.zeroize();
    input.zeroize();
    p
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

fn sample_vec(seed: &[u8; 32], n: &mut u8, k: usize, eta: u32) -> Vec<Poly> {
    let mut v = Vec::with_capacity(k);
    for _ in 0..k {
        v.push(sample_cbd(seed, *n, eta));
        *n += 1;
    }
    v
}

fn decode_poly_12(bytes: &[u8]) -> Poly {
    poly_from_u16(&byte_decode_d(bytes, 12))
}

// ============================================================================
// K-PKE.KeyGen (FIPS 203 Algorithm 13)
// ============================================================================

/// Returns `(ek_pke, dk_pke)` of sizes `level.ek_bytes()` / `level.pke_dk_bytes()`.
pub fn pke_keygen(level: KemLevel, d: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let k = level.k();

    let mut g_input = [0u8; 33];
    g_input[..32].copy_from_slice(d);
    g_input[32] = k as u8;
    let mut g_out = sha3_512(&g_input);
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];
    rho.copy_from_slice(&g_out[..32]);
    sigma.copy_from_slice(&g_out[32..]);

    let a_hat = gen_matrix(&rho, k, false);

    let mut n: u8 = 0;
    let mut s = sample_vec(&sigma, &mut n, k, ETA1);
    let mut e = sample_vec(&sigma, &mut n, k, ETA1);
    for i in 0..k {
        ntt(&mut s[i]);
        ntt(&mut e[i]);
    }

    let mut ek = Vec::with_capacity(level.ek_bytes());
    for i in 0..k {
        let mut acc = poly_zero();
        for j in 0..k {
            acc = poly_add(&acc, &basemul(&a_hat[i][j], &s[j]));
        }
        let t_i = poly_add(&acc, &e[i]);
        ek.extend_from_slice(&byte_encode_d(&poly_to_u16(&t_i), 12));
    }
    ek.extend_from_slice(&rho);

    let mut dk = Vec::with_capacity(level.pke_dk_bytes());
    for p in s.iter() {
        dk.extend_from_slice(&byte_encode_d(&poly_to_u16(p), 12));
    }

    g_input.zeroize();
    g_out.zeroize();
    sigma.zeroize();

    (ek, dk)
}

// ============================================================================
// K-PKE.Encrypt (FIPS 203 Algorithm 14)
// ============================================================================

/// `ek` must have length `level.ek_bytes()` (validated by the KEM layer).
pub fn pke_encrypt(level: KemLevel, ek: &[u8], m: &[u8; 32], r: &[u8; 32]) -> Vec<u8> {
    assert_eq!(ek.len(), level.ek_bytes(), "pke_encrypt: bad ek length");
    let k = level.k();
    let (du, dv) = (level.du(), level.dv());

    let t_hat: Vec<Poly> = (0..k)
        .map(|i| decode_poly_12(&ek[i * 384..(i + 1) * 384]))
        .collect();
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[384 * k..]);

    let a_t = gen_matrix(&rho, k, true);

    let mut n: u8 = 0;
    let mut r_vec = sample_vec(r, &mut n, k, ETA1);
    let e1 = sample_vec(r, &mut n, k, ETA2);
    let e2 = sample_cbd(r, n, ETA2);

    for poly in r_vec.iter_mut() {
        ntt(poly);
    }

    let u: Vec<Poly> = (0..k)
        .map(|i| {
            let mut acc = poly_zero();
            for j in 0..k {
                acc = poly_add(&acc, &basemul(&a_t[i][j], &r_vec[j]));
            }
            inv_ntt(&mut acc);
            poly_add(&acc, &e1[i])
        })
        .collect();

    let mut v = poly_zero();
    for j in 0..k {
        v = poly_add(&v, &basemul(&t_hat[j], &r_vec[j]));
    }
    inv_ntt(&mut v);
    let v = poly_add(&v, &e2);

    // mu = Decompress_1(ByteDecode_1(m))
    let mut mu = poly_zero();
    for (idx, slot) in mu.iter_mut().enumerate() {
        let bit = ((m[idx / 8] >> (idx % 8)) & 1) as u16;
        *slot = FieldElement::from_u16(decompress_d(bit, 1));
    }
    let v = poly_add(&v, &mu);

    let mut c = Vec::with_capacity(level.ct_bytes());
    for poly in u.iter() {
        let u16s = poly_to_u16(poly);
        let compressed: [u16; 256] = core::array::from_fn(|i| compress_d(u16s[i], du));
        c.extend_from_slice(&byte_encode_d(&compressed, du));
    }
    let v16 = poly_to_u16(&v);
    let compressed_v: [u16; 256] = core::array::from_fn(|i| compress_d(v16[i], dv));
    c.extend_from_slice(&byte_encode_d(&compressed_v, dv));

    debug_assert_eq!(c.len(), level.ct_bytes());
    r_vec.clear();
    c
}

// ============================================================================
// K-PKE.Decrypt (FIPS 203 Algorithm 15)
// ============================================================================

/// `dk` must be `level.pke_dk_bytes()` long and `c` `level.ct_bytes()` long.
pub fn pke_decrypt(level: KemLevel, dk: &[u8], c: &[u8]) -> [u8; 32] {
    assert_eq!(dk.len(), level.pke_dk_bytes(), "pke_decrypt: bad dk length");
    assert_eq!(
        c.len(),
        level.ct_bytes(),
        "pke_decrypt: bad ciphertext length"
    );
    let k = level.k();
    let (du, dv) = (level.du(), level.dv());
    let u_len = 32 * du as usize;

    let u_prime: Vec<Poly> = (0..k)
        .map(|i| {
            let y = byte_decode_d(&c[i * u_len..(i + 1) * u_len], du);
            let mut coeffs = poly_zero();
            for idx in 0..256 {
                coeffs[idx] = FieldElement::from_u16(decompress_d(y[idx], du));
            }
            coeffs
        })
        .collect();
    let v_y = byte_decode_d(&c[k * u_len..], dv);
    let mut v_prime = poly_zero();
    for idx in 0..256 {
        v_prime[idx] = FieldElement::from_u16(decompress_d(v_y[idx], dv));
    }

    let s_hat: Vec<Poly> = (0..k)
        .map(|i| decode_poly_12(&dk[i * 384..(i + 1) * 384]))
        .collect();

    let mut u_hat = u_prime;
    for poly in u_hat.iter_mut() {
        ntt(poly);
    }
    let mut acc = poly_zero();
    for j in 0..k {
        acc = poly_add(&acc, &basemul(&s_hat[j], &u_hat[j]));
    }
    inv_ntt(&mut acc);
    let w = poly_sub(&v_prime, &acc);

    let mut w_u16 = poly_to_u16(&w);
    let mut m = [0u8; 32];
    for idx in 0..256 {
        let bit = compress_d(w_u16[idx], 1);
        m[idx / 8] |= (bit as u8) << (idx % 8);
    }
    w_u16.zeroize();
    m
}
