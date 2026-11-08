//! ML-KEM-768 KEM (FIPS 203 Algorithms 16, 17, 18).

use crate::keccak::{sha3_256, sha3_512, shake_256};
use crate::pke::{
    PKE_CIPHERTEXT_BYTES, PKE_PUBLIC_KEY_BYTES, PKE_SECRET_KEY_BYTES, pke_decrypt, pke_encrypt,
    pke_keygen,
};

pub const EK_BYTES: usize = PKE_PUBLIC_KEY_BYTES; // 1184
pub const DK_BYTES: usize = PKE_SECRET_KEY_BYTES + PKE_PUBLIC_KEY_BYTES + 32 + 32; // 2400
pub const CT_BYTES: usize = PKE_CIPHERTEXT_BYTES; // 1088
pub const SS_BYTES: usize = 32;

/// Constant-time equality. Returns 1 if `a == b`, 0 otherwise.
/// Requires `a.len() == b.len()`; callers guarantee this in ML-KEM.
fn ct_eq_bytes(a: &[u8], b: &[u8]) -> u8 {
    debug_assert_eq!(a.len(), b.len());
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    // acc == 0 -> 1, else -> 0
    ((acc as u16).wrapping_sub(1) >> 15) as u8
}

// ============================================================================
// ML-KEM.KeyGen (FIPS 203 Algorithm 16)
// ============================================================================

pub fn keygen(d: &[u8; 32], z: &[u8; 32]) -> ([u8; EK_BYTES], [u8; DK_BYTES]) {
    let (ek_pke, dk_pke) = pke_keygen(d);

    let mut ek = [0u8; EK_BYTES];
    ek.copy_from_slice(&ek_pke);

    let h_ek = sha3_256(&ek_pke);

    let mut dk = [0u8; DK_BYTES];
    dk[..PKE_SECRET_KEY_BYTES].copy_from_slice(&dk_pke);
    dk[PKE_SECRET_KEY_BYTES..PKE_SECRET_KEY_BYTES + PKE_PUBLIC_KEY_BYTES].copy_from_slice(&ek_pke);
    dk[PKE_SECRET_KEY_BYTES + PKE_PUBLIC_KEY_BYTES
        ..PKE_SECRET_KEY_BYTES + PKE_PUBLIC_KEY_BYTES + 32]
        .copy_from_slice(&h_ek);
    dk[PKE_SECRET_KEY_BYTES + PKE_PUBLIC_KEY_BYTES + 32..].copy_from_slice(z);

    (ek, dk)
}

// ============================================================================
// ML-KEM.Encaps (FIPS 203 Algorithm 17)
// ============================================================================

pub fn encaps(ek: &[u8; EK_BYTES], m: &[u8; 32]) -> ([u8; CT_BYTES], [u8; SS_BYTES]) {
    // (K, r) = G(m || H(ek))
    let h_ek = sha3_256(ek);
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(m);
    g_input[32..].copy_from_slice(&h_ek);
    let g_out = sha3_512(&g_input);

    let mut k = [0u8; 32];
    let mut r = [0u8; 32];
    k.copy_from_slice(&g_out[..32]);
    r.copy_from_slice(&g_out[32..]);

    let c = pke_encrypt(ek, m, &r);

    let mut ct = [0u8; CT_BYTES];
    ct.copy_from_slice(&c);

    (ct, k)
}

// ============================================================================
// ML-KEM.Decaps (FIPS 203 Algorithm 18)
// ============================================================================

pub fn decaps(dk: &[u8; DK_BYTES], ct: &[u8; CT_BYTES]) -> [u8; SS_BYTES] {
    // Split dk = dk_pke || ek || h || z
    let mut dk_pke = [0u8; PKE_SECRET_KEY_BYTES];
    dk_pke.copy_from_slice(&dk[..PKE_SECRET_KEY_BYTES]);

    let mut ek = [0u8; EK_BYTES];
    ek.copy_from_slice(&dk[PKE_SECRET_KEY_BYTES..PKE_SECRET_KEY_BYTES + PKE_PUBLIC_KEY_BYTES]);

    let mut h = [0u8; 32];
    h.copy_from_slice(
        &dk[PKE_SECRET_KEY_BYTES + PKE_PUBLIC_KEY_BYTES
            ..PKE_SECRET_KEY_BYTES + PKE_PUBLIC_KEY_BYTES + 32],
    );

    let mut z = [0u8; 32];
    z.copy_from_slice(&dk[PKE_SECRET_KEY_BYTES + PKE_PUBLIC_KEY_BYTES + 32..]);

    // m' = K-PKE.Decrypt(dk_pke, c)
    let mut ct_inner = [0u8; PKE_CIPHERTEXT_BYTES];
    ct_inner.copy_from_slice(ct);
    let m_prime = pke_decrypt(&dk_pke, &ct_inner);

    // (K', r') = G(m' || h)
    let mut g_input = [0u8; 64];
    g_input[..32].copy_from_slice(&m_prime);
    g_input[32..].copy_from_slice(&h);
    let g_out = sha3_512(&g_input);

    let mut k_prime = [0u8; 32];
    let mut r_prime = [0u8; 32];
    k_prime.copy_from_slice(&g_out[..32]);
    r_prime.copy_from_slice(&g_out[32..]);

    // c' = K-PKE.Encrypt(ek, m', r')
    let c_prime = pke_encrypt(&ek, &m_prime, &r_prime);

    // K̄ = J(z || c)  where J = SHAKE-256 with 32-byte output
    let mut j_input = [0u8; 32 + CT_BYTES];
    j_input[..32].copy_from_slice(&z);
    j_input[32..].copy_from_slice(ct);
    let k_bar_bytes = shake_256(&j_input, 32);
    let mut k_bar = [0u8; 32];
    k_bar.copy_from_slice(&k_bar_bytes);

    // Constant-time compare of c and c'; if equal, return K'; else return K̄.
    let eq = ct_eq_bytes(&c_prime, ct);
    let mask = eq.wrapping_neg(); // 0xFF if equal, 0x00 if different

    // If equal, take k_prime; if different, take k_bar.
    // mask = 0xFF -> select k_prime (a), mask = 0x00 -> select k_bar (b).
    // So we want: out = select_32(b=k_bar, a=k_prime, mask=eq*0xFF... )
    // Simplest: out = k_prime masked by eq, k_bar masked by !eq.
    let mut ss = [0u8; 32];
    for i in 0..32 {
        ss[i] = (k_prime[i] & mask) | (k_bar[i] & !mask);
    }
    ss
}
