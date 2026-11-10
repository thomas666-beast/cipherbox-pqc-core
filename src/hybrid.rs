//! Hybrid X25519 + ML-KEM key encapsulation.
//!
//! The shared secret is secure as long as *either* X25519 or ML-KEM holds,
//! so a flaw in the newer post-quantum code does not break confidentiality.
//!
//! ## Construction (X-Wing style, but NOT byte-compatible with X-Wing)
//!
//! ```text
//! (d || z || x25519_sk) = SHAKE-256("cipherbox-hybrid-v1" || level_id || seed32, 96)
//! public key  = ek_mlkem || x25519_pk                 (1216 B for 768, 1600 B for 1024)
//! ciphertext  = ct_mlkem || x25519_ephemeral_pk       (1120 B for 768, 1600 B for 1024)
//! ss = SHA3-256("cipherbox-hybrid-v1" || level_id || ss_mlkem || ss_x25519
//!               || ct_mlkem || ct_x25519 || public_key)
//! ```
//!
//! The combiner hashes the whole transcript (both shared secrets, both
//! ciphertexts and the full public key), so the result is bound to this exact
//! key and exchange. The seed expansion is domain-separated by level.
//!
//! Sender side: an X25519 public key that yields an all-zero shared secret
//! (low-order point) is rejected. Receiver side never errors on the X25519
//! part; a malformed ciphertext simply produces an unrelated secret, because
//! both ciphertexts are inside the hash.

use crate::keccak::{sha3_256, shake_256};
use crate::params::{KemLevel, Suite, X25519_BYTES};
use crate::{CipherboxError, Decapsulator, MlKemKeyPair, kem};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

const LABEL: &[u8] = b"cipherbox-hybrid-v1";

/// Length of an exported hybrid secret: `version (1) || level id (1) || seed (32)`.
pub const SECRET_BYTES: usize = 34;
const SECRET_VERSION: u8 = 0x01;

fn fill_random(buf: &mut [u8]) -> Result<(), CipherboxError> {
    getrandom::getrandom(buf).map_err(|e| CipherboxError::Crypto(format!("RNG failure: {e}")))
}

fn x_public(sk: &[u8; 32]) -> [u8; 32] {
    let secret = StaticSecret::from(*sk);
    PublicKey::from(&secret).to_bytes()
}

/// Returns `(shared_secret, contributory)`; `contributory` is false for
/// low-order points (all-zero output).
fn x_dh(sk: &[u8; 32], pk: &[u8; 32]) -> ([u8; 32], bool) {
    let secret = StaticSecret::from(*sk);
    let shared = secret.diffie_hellman(&PublicKey::from(*pk));
    (shared.to_bytes(), shared.was_contributory())
}

/// `(d || z, x25519_sk)` from a 32-byte seed.
fn derive(seed: &[u8; 32], level: KemLevel) -> ([u8; 64], [u8; 32]) {
    let mut input = Vec::with_capacity(LABEL.len() + 1 + 32);
    input.extend_from_slice(LABEL);
    input.push(level.id());
    input.extend_from_slice(seed);
    let mut out = shake_256(&input, 96);
    let mut dz = [0u8; 64];
    let mut xsk = [0u8; 32];
    dz.copy_from_slice(&out[..64]);
    xsk.copy_from_slice(&out[64..]);
    input.zeroize();
    out.zeroize();
    (dz, xsk)
}

fn combine(
    level: KemLevel,
    ss_m: &[u8; 32],
    ss_x: &[u8; 32],
    ct_m: &[u8],
    ct_x: &[u8; 32],
    ek: &[u8],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(LABEL.len() + 1 + 64 + ct_m.len() + 32 + ek.len());
    input.extend_from_slice(LABEL);
    input.push(level.id());
    input.extend_from_slice(ss_m);
    input.extend_from_slice(ss_x);
    input.extend_from_slice(ct_m);
    input.extend_from_slice(ct_x);
    input.extend_from_slice(ek);
    let ss = sha3_256(&input);
    input.zeroize();
    ss
}

// ============================================================================
// Public-key validation
// ============================================================================

/// Validate a hybrid public key and return its level. The ML-KEM half must
/// pass the FIPS 203 modulus check.
pub fn validate_hybrid_public_key(ek: &[u8]) -> Result<KemLevel, CipherboxError> {
    match Suite::from_ek_len(ek.len()) {
        Some(Suite::Hybrid(level)) => {
            if kem::check_ek_level(level, &ek[..level.ek_bytes()]) {
                Ok(level)
            } else {
                Err(CipherboxError::Encapsulation(
                    "ML-KEM part of the hybrid key failed the FIPS 203 modulus check".into(),
                ))
            }
        }
        _ => Err(CipherboxError::Crypto(format!(
            "not a hybrid public key (length {}; expected {} or {})",
            ek.len(),
            Suite::Hybrid(KemLevel::MlKem768).ek_bytes(),
            Suite::Hybrid(KemLevel::MlKem1024).ek_bytes()
        ))),
    }
}

/// Validate any supported public key (plain ML-KEM or hybrid) and return
/// its suite.
pub fn validate_public_key(ek: &[u8]) -> Result<Suite, CipherboxError> {
    match Suite::from_ek_len(ek.len()) {
        Some(Suite::Kem(level)) => {
            if kem::check_ek_level(level, ek) {
                Ok(Suite::Kem(level))
            } else {
                Err(CipherboxError::Encapsulation(
                    "encapsulation key failed the FIPS 203 modulus check".into(),
                ))
            }
        }
        Some(Suite::Hybrid(_)) => validate_hybrid_public_key(ek).map(Suite::Hybrid),
        None => Err(CipherboxError::Crypto(format!(
            "unsupported public key length {} (expected 1184, 1568, 1216 or 1600)",
            ek.len()
        ))),
    }
}

// ============================================================================
// Encapsulation
// ============================================================================

/// Deterministic hybrid encapsulation with explicit randomness: `m` for
/// ML-KEM and `eph_sk` for the X25519 ephemeral key. Returns `(ct, ss)`.
pub fn encaps_deterministic(
    ek: &[u8],
    m: &[u8; 32],
    eph_sk: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 32]), CipherboxError> {
    let level = validate_hybrid_public_key(ek)?;
    let (ek_m, pk_x_bytes) = ek.split_at(level.ek_bytes());
    let mut pk_x = [0u8; X25519_BYTES];
    pk_x.copy_from_slice(pk_x_bytes);

    let (ct_m, mut ss_m) = kem::encaps_level(level, ek_m, m)?;
    let ct_x = x_public(eph_sk);
    let (mut ss_x, contributory) = x_dh(eph_sk, &pk_x);
    if !contributory {
        ss_m.zeroize();
        ss_x.zeroize();
        return Err(CipherboxError::Encapsulation(
            "X25519 public key is a low-order point".into(),
        ));
    }

    let ss = combine(level, &ss_m, &ss_x, &ct_m, &ct_x, ek);
    ss_m.zeroize();
    ss_x.zeroize();

    let mut ct = ct_m;
    ct.extend_from_slice(&ct_x);
    Ok((ct, ss))
}

/// Encapsulate to a hybrid public key with fresh randomness.
/// Returns `(ciphertext, shared_secret_32)`.
pub fn encapsulate_hybrid_to(ek: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CipherboxError> {
    let mut m = [0u8; 32];
    let mut eph = [0u8; 32];
    fill_random(&mut m)?;
    fill_random(&mut eph)?;
    let res = encaps_deterministic(ek, &m, &eph);
    m.zeroize();
    eph.zeroize();
    let (ct, ss) = res?;
    Ok((ct, ss.to_vec()))
}

/// Encapsulate to any supported public key (plain or hybrid, inferred from
/// its length) with fresh randomness. Returns `(suite, ct, ss)`.
pub fn encapsulate_any(ek: &[u8]) -> Result<(Suite, Vec<u8>, [u8; 32]), CipherboxError> {
    let suite = validate_public_key(ek)?;
    let mut m = [0u8; 32];
    fill_random(&mut m)?;
    let res = match suite {
        Suite::Kem(level) => kem::encaps_level(level, ek, &m),
        Suite::Hybrid(_) => {
            let mut eph = [0u8; 32];
            let r = fill_random(&mut eph).and_then(|_| encaps_deterministic(ek, &m, &eph));
            eph.zeroize();
            r
        }
    };
    m.zeroize();
    let (ct, ss) = res?;
    Ok((suite, ct, ss))
}

// ============================================================================
// Key pair
// ============================================================================

/// X25519 + ML-KEM key pair, derived from a single 32-byte seed.
pub struct HybridKeyPair {
    level: KemLevel,
    seed: [u8; 32],
    kem: MlKemKeyPair,
    x_sk: [u8; 32],
    ek: Vec<u8>,
}

impl Drop for HybridKeyPair {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.x_sk.zeroize();
    }
}

impl HybridKeyPair {
    pub fn new(level: KemLevel) -> Result<Self, CipherboxError> {
        let mut seed = [0u8; 32];
        fill_random(&mut seed)?;
        let kp = Self::from_seed(&seed, level);
        seed.zeroize();
        kp
    }

    pub fn from_seed(seed: &[u8], level: KemLevel) -> Result<Self, CipherboxError> {
        if seed.len() != 32 {
            return Err(CipherboxError::InvalidKeyLength {
                expected: 32,
                got: seed.len(),
            });
        }
        let mut s = [0u8; 32];
        s.copy_from_slice(seed);
        let (mut dz, x_sk) = derive(&s, level);
        let kem_kp = MlKemKeyPair::from_seed_with_level(&dz, level);
        dz.zeroize();
        let kem_kp = kem_kp?;

        let mut ek = Vec::with_capacity(Suite::Hybrid(level).ek_bytes());
        ek.extend_from_slice(kem_kp.encapsulation_key());
        ek.extend_from_slice(&x_public(&x_sk));

        Ok(Self {
            level,
            seed: s,
            kem: kem_kp,
            x_sk,
            ek,
        })
    }

    /// Self-describing 34-byte secret: `0x01 || level id || seed32`.
    pub fn export_secret(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(SECRET_BYTES);
        v.push(SECRET_VERSION);
        v.push(self.level.id());
        v.extend_from_slice(&self.seed);
        v
    }

    pub fn from_secret(secret: &[u8]) -> Result<Self, CipherboxError> {
        if secret.len() != SECRET_BYTES {
            return Err(CipherboxError::InvalidKeyLength {
                expected: SECRET_BYTES,
                got: secret.len(),
            });
        }
        if secret[0] != SECRET_VERSION {
            return Err(CipherboxError::Crypto(format!(
                "unsupported hybrid secret version {}",
                secret[0]
            )));
        }
        let level = KemLevel::from_id(secret[1])
            .ok_or_else(|| CipherboxError::Crypto("unknown level in hybrid secret".into()))?;
        Self::from_seed(&secret[2..], level)
    }

    pub fn level(&self) -> KemLevel {
        self.level
    }

    /// `ek_mlkem || x25519_pk` (1216 or 1600 bytes).
    pub fn public_key(&self) -> &[u8] {
        &self.ek
    }

    /// Decapsulate, returning the 32-byte shared secret.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<Vec<u8>, CipherboxError> {
        Ok(self.decapsulate_raw(ct)?.to_vec())
    }
}

impl Decapsulator for HybridKeyPair {
    fn suite(&self) -> Suite {
        Suite::Hybrid(self.level)
    }

    fn public_key_bytes(&self) -> &[u8] {
        &self.ek
    }

    fn decapsulate_raw(&self, ct: &[u8]) -> Result<[u8; 32], CipherboxError> {
        let ct_len = Suite::Hybrid(self.level).ct_bytes();
        if ct.len() != ct_len {
            return Err(CipherboxError::InvalidKeyLength {
                expected: ct_len,
                got: ct.len(),
            });
        }
        let (ct_m, ct_x_bytes) = ct.split_at(self.level.ct_bytes());
        let mut ct_x = [0u8; X25519_BYTES];
        ct_x.copy_from_slice(ct_x_bytes);

        let mut ss_m = kem::decaps_level(self.level, self.kem.decapsulation_key(), ct_m)?;
        // Contributory check deliberately ignored here: ct_x is hashed below.
        let (mut ss_x, _) = x_dh(&self.x_sk, &ct_x);

        let ss = combine(self.level, &ss_m, &ss_x, ct_m, &ct_x, &self.ek);
        ss_m.zeroize();
        ss_x.zeroize();
        Ok(ss)
    }
}
