//! ML-KEM KEM (FIPS 203 Algorithms 16, 17, 18) for ML-KEM-768 and
//! ML-KEM-1024, plus the input checks from FIPS 203 sections 7.2 and 7.3.
//!
//! The `*_level` functions are generic over [`KemLevel`] and work on slices.
//! The un-suffixed functions and the `*_BYTES` constants are the original
//! fixed-size ML-KEM-768 API and are kept for compatibility.

use crate::CipherboxError;
use crate::field::Q;
use crate::keccak::{sha3_256, sha3_512, shake_256};
use crate::params::KemLevel;
use crate::pke::{pke_decrypt, pke_encrypt, pke_keygen};
use crate::poly::byte_decode_d;
use zeroize::Zeroize;

// ---- ML-KEM-768 (compatibility constants) ----
pub const EK_BYTES: usize = KemLevel::MlKem768.ek_bytes(); // 1184
pub const DK_BYTES: usize = KemLevel::MlKem768.dk_bytes(); // 2400
pub const CT_BYTES: usize = KemLevel::MlKem768.ct_bytes(); // 1088
pub const SS_BYTES: usize = 32;

// ---- ML-KEM-1024 ----
pub const EK_BYTES_1024: usize = KemLevel::MlKem1024.ek_bytes(); // 1568
pub const DK_BYTES_1024: usize = KemLevel::MlKem1024.dk_bytes(); // 3168
pub const CT_BYTES_1024: usize = KemLevel::MlKem1024.ct_bytes(); // 1568

/// Constant-time equality. Returns 1 if `a == b`, 0 otherwise.
/// Requires `a.len() == b.len()`; callers guarantee this in ML-KEM.
fn ct_eq_bytes(a: &[u8], b: &[u8]) -> u8 {
    debug_assert_eq!(a.len(), b.len());
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    ((acc as u16).wrapping_sub(1) >> 15) as u8
}

fn len_err(expected: usize, got: usize) -> CipherboxError {
    CipherboxError::InvalidKeyLength { expected, got }
}

// ============================================================================
// Input validation (public data only, so not constant-time)
// ============================================================================

/// Modulus check (FIPS 203 section 7.2): length is right and every 12-bit
/// coefficient of the encoded `t_hat` is `< Q`.
pub fn check_ek_level(level: KemLevel, ek: &[u8]) -> bool {
    if ek.len() != level.ek_bytes() {
        return false;
    }
    let mut ok = true;
    for i in 0..level.k() {
        for c in byte_decode_d(&ek[i * 384..(i + 1) * 384], 12).iter() {
            if *c >= Q {
                ok = false;
            }
        }
    }
    ok
}

fn dk_offsets(level: KemLevel) -> (usize, usize, usize) {
    let ek_off = level.pke_dk_bytes();
    let h_off = ek_off + level.ek_bytes();
    (ek_off, h_off, h_off + 32)
}

/// Decapsulation-key check (FIPS 203 section 7.3): right length, embedded
/// `ek` passes the modulus check, and the stored hash equals `H(ek)`.
pub fn check_dk_level(level: KemLevel, dk: &[u8]) -> bool {
    if dk.len() != level.dk_bytes() {
        return false;
    }
    let (ek_off, h_off, z_off) = dk_offsets(level);
    let ek = &dk[ek_off..h_off];
    check_ek_level(level, ek) && sha3_256(ek).as_slice() == &dk[h_off..z_off]
}

// ============================================================================
// ML-KEM.KeyGen (FIPS 203 Algorithm 16)
// ============================================================================

/// Returns `(ek, dk)` with sizes `level.ek_bytes()` / `level.dk_bytes()`.
pub fn keygen_level(level: KemLevel, d: &[u8; 32], z: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let (ek, mut dk_pke) = pke_keygen(level, d);
    let h_ek = sha3_256(&ek);

    let mut dk = Vec::with_capacity(level.dk_bytes());
    dk.extend_from_slice(&dk_pke);
    dk.extend_from_slice(&ek);
    dk.extend_from_slice(&h_ek);
    dk.extend_from_slice(z);
    debug_assert_eq!(dk.len(), level.dk_bytes());

    dk_pke.zeroize();
    (ek, dk)
}

// ============================================================================
// ML-KEM.Encaps (FIPS 203 Algorithm 17)
// ============================================================================

/// Deterministic encapsulation with randomness `m`. Returns `(ct, ss)`.
/// Callers should run [`check_ek_level`] on untrusted keys first.
pub fn encaps_level(
    level: KemLevel,
    ek: &[u8],
    m: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 32]), CipherboxError> {
    if ek.len() != level.ek_bytes() {
        return Err(len_err(level.ek_bytes(), ek.len()));
    }
    // (K, r) = G(m || H(ek))
    let h_ek = sha3_256(ek);
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(m);
    g_input[32..].copy_from_slice(&h_ek);
    let mut g_out = sha3_512(&g_input);

    let mut k = [0u8; 32];
    let mut r = [0u8; 32];
    k.copy_from_slice(&g_out[..32]);
    r.copy_from_slice(&g_out[32..]);

    let ct = pke_encrypt(level, ek, m, &r);

    g_input.zeroize();
    g_out.zeroize();
    r.zeroize();

    Ok((ct, k))
}

// ============================================================================
// ML-KEM.Decaps (FIPS 203 Algorithm 18)
// ============================================================================

/// Decapsulate with implicit rejection. The only errors are wrong lengths
/// (public information); a forged ciphertext yields a pseudorandom secret.
/// Callers should run [`check_dk_level`] on untrusted keys first.
pub fn decaps_level(level: KemLevel, dk: &[u8], ct: &[u8]) -> Result<[u8; 32], CipherboxError> {
    if dk.len() != level.dk_bytes() {
        return Err(len_err(level.dk_bytes(), dk.len()));
    }
    if ct.len() != level.ct_bytes() {
        return Err(len_err(level.ct_bytes(), ct.len()));
    }
    let (ek_off, h_off, z_off) = dk_offsets(level);
    let dk_pke = &dk[..ek_off];
    let ek = &dk[ek_off..h_off];

    let mut h = [0u8; 32];
    h.copy_from_slice(&dk[h_off..z_off]);
    let mut z = [0u8; 32];
    z.copy_from_slice(&dk[z_off..]);

    // m' = K-PKE.Decrypt(dk_pke, c)
    let mut m_prime = pke_decrypt(level, dk_pke, ct);

    // (K', r') = G(m' || h)
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&m_prime);
    g_input[32..].copy_from_slice(&h);
    let mut g_out = sha3_512(&g_input);

    let mut k_prime = [0u8; 32];
    let mut r_prime = [0u8; 32];
    k_prime.copy_from_slice(&g_out[..32]);
    r_prime.copy_from_slice(&g_out[32..]);

    // c' = K-PKE.Encrypt(ek, m', r')
    let c_prime = pke_encrypt(level, ek, &m_prime, &r_prime);

    // K_bar = J(z || c), J = SHAKE-256 with 32-byte output
    let mut j_input = Vec::with_capacity(32 + ct.len());
    j_input.extend_from_slice(&z);
    j_input.extend_from_slice(ct);
    let mut k_bar_bytes = shake_256(&j_input, 32);
    let mut k_bar = [0u8; 32];
    k_bar.copy_from_slice(&k_bar_bytes);

    // Constant-time select: equal -> K', different -> K_bar.
    let eq = ct_eq_bytes(&c_prime, ct);
    let mask = eq.wrapping_neg(); // 0xFF if equal, 0x00 otherwise
    let mut ss = [0u8; 32];
    for i in 0..32 {
        ss[i] = (k_prime[i] & mask) | (k_bar[i] & !mask);
    }

    h.zeroize();
    z.zeroize();
    m_prime.zeroize();
    g_input.zeroize();
    g_out.zeroize();
    k_prime.zeroize();
    r_prime.zeroize();
    j_input.zeroize();
    k_bar_bytes.zeroize();
    k_bar.zeroize();

    Ok(ss)
}

// ============================================================================
// Fixed-size ML-KEM-768 API (unchanged signatures)
// ============================================================================

const L768: KemLevel = KemLevel::MlKem768;

pub fn check_ek(ek: &[u8; EK_BYTES]) -> bool {
    check_ek_level(L768, ek)
}

pub fn check_dk(dk: &[u8; DK_BYTES]) -> bool {
    check_dk_level(L768, dk)
}

pub fn keygen(d: &[u8; 32], z: &[u8; 32]) -> ([u8; EK_BYTES], [u8; DK_BYTES]) {
    let (ek_v, mut dk_v) = keygen_level(L768, d, z);
    let mut ek = [0u8; EK_BYTES];
    let mut dk = [0u8; DK_BYTES];
    ek.copy_from_slice(&ek_v);
    dk.copy_from_slice(&dk_v);
    dk_v.zeroize();
    (ek, dk)
}

pub fn encaps(ek: &[u8; EK_BYTES], m: &[u8; 32]) -> ([u8; CT_BYTES], [u8; SS_BYTES]) {
    let (ct_v, ss) = encaps_level(L768, ek, m).expect("fixed-size input");
    let mut ct = [0u8; CT_BYTES];
    ct.copy_from_slice(&ct_v);
    (ct, ss)
}

pub fn decaps(dk: &[u8; DK_BYTES], ct: &[u8; CT_BYTES]) -> [u8; SS_BYTES] {
    decaps_level(L768, dk, ct).expect("fixed-size input")
}
