//! Cipherbox PQC core: from-scratch ML-KEM-768 / ML-KEM-1024, ML-DSA-65 /
//! ML-DSA-87 (via the `ml-dsa` crate), chunked file encryption, passphrase
//! encryption and key wrapping, shared by the native and WASM crates.
//!
//! **Status:** the ML-KEM, Keccak and file-encryption code is a from-scratch
//! implementation and has not been independently audited.

#![forbid(unsafe_code)]

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use getrandom::getrandom;
use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{Generate, MlDsa65, MlDsa87, Signature, SigningKey, VerifyingKey};
use zeroize::Zeroize;

pub mod field;
pub mod file;
pub mod hybrid;
pub mod keccak;
pub mod kem;
pub mod ntt;
pub mod params;
pub mod pke;
pub mod poly;
pub mod room;

pub use hybrid::{
    HybridKeyPair, encapsulate_any, encapsulate_hybrid_to, validate_hybrid_public_key,
    validate_public_key,
};
pub use params::{KemLevel, Suite};
pub use room::{RekeyBundle, Room, RoomKdfParams, RoomSecret};

use keccak::sha3_256;

// ==========================================
// Error type
// ==========================================

#[derive(Debug)]
pub enum CipherboxError {
    KeyGen(String),
    Encapsulation(String),
    Decapsulation(String),
    InvalidKeyLength { expected: usize, got: usize },
    Crypto(String),
}

impl std::fmt::Display for CipherboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyGen(e) => write!(f, "key generation failed: {e}"),
            Self::Encapsulation(e) => write!(f, "encapsulation failed: {e}"),
            Self::Decapsulation(e) => write!(f, "decapsulation failed: {e}"),
            Self::InvalidKeyLength { expected, got } => {
                write!(f, "invalid key length: expected {expected}, got {got}")
            }
            Self::Crypto(e) => write!(f, "crypto error: {e}"),
        }
    }
}

impl std::error::Error for CipherboxError {}

fn fill_random(buf: &mut [u8]) -> Result<(), CipherboxError> {
    getrandom(buf).map_err(|e| CipherboxError::Crypto(format!("RNG failure: {e}")))
}

// ==========================================
// ML-KEM: public-key-only API
// ==========================================

/// Validate an untrusted encapsulation key and return its level: the length
/// must be 1184 (ML-KEM-768) or 1568 (ML-KEM-1024), and every coefficient
/// must pass the FIPS 203 modulus check.
pub fn validate_encapsulation_key(ek_bytes: &[u8]) -> Result<KemLevel, CipherboxError> {
    let level = KemLevel::from_ek_len(ek_bytes.len()).ok_or_else(|| {
        CipherboxError::Crypto(format!(
            "unsupported encapsulation key length {} (expected {} for ML-KEM-768 or {} for ML-KEM-1024)",
            ek_bytes.len(),
            KemLevel::MlKem768.ek_bytes(),
            KemLevel::MlKem1024.ek_bytes()
        ))
    })?;
    if !kem::check_ek_level(level, ek_bytes) {
        return Err(CipherboxError::Encapsulation(
            "encapsulation key failed the FIPS 203 modulus check".into(),
        ));
    }
    Ok(level)
}

/// Encapsulate to someone else's public key (level inferred from its
/// length). No private key needed. Returns `(ciphertext, shared_secret_32)`.
pub fn encapsulate_to(ek_bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CipherboxError> {
    let level = validate_encapsulation_key(ek_bytes)?;
    let mut m = [0u8; 32];
    fill_random(&mut m)?;
    let res = kem::encaps_level(level, ek_bytes, &m);
    m.zeroize();
    let (ct, ss) = res?;
    Ok((ct, ss.to_vec()))
}

// ==========================================
// ML-KEM key pair
// ==========================================

pub struct MlKemKeyPair {
    level: KemLevel,
    d: [u8; 32],
    z: [u8; 32],
    ek: Vec<u8>,
    dk: Vec<u8>,
}

impl Drop for MlKemKeyPair {
    fn drop(&mut self) {
        self.d.zeroize();
        self.z.zeroize();
        self.dk.zeroize();
    }
}

impl MlKemKeyPair {
    /// New ML-KEM-768 key pair (the original default).
    pub fn new() -> Result<Self, CipherboxError> {
        Self::new_with_level(KemLevel::MlKem768)
    }

    pub fn new_with_level(level: KemLevel) -> Result<Self, CipherboxError> {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        fill_random(&mut d)?;
        fill_random(&mut z)?;
        let (ek, dk) = kem::keygen_level(level, &d, &z);
        Ok(Self {
            level,
            d,
            z,
            ek,
            dk,
        })
    }

    /// Encapsulate to this key pair's own public key (mostly for tests).
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), CipherboxError> {
        encapsulate_to(&self.ek)
    }

    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CipherboxError> {
        if ciphertext.len() != self.level.ct_bytes() {
            return Err(CipherboxError::InvalidKeyLength {
                expected: self.level.ct_bytes(),
                got: ciphertext.len(),
            });
        }
        let ss = kem::decaps_level(self.level, &self.dk, ciphertext)?;
        Ok(ss.to_vec())
    }

    /// Export (dk_seed_64, ek). The seed is `d || z`; together with the
    /// level it determines the whole key pair. The level is recoverable from
    /// the length of `ek` (1184 or 1568 bytes).
    pub fn export_keys(&self) -> (Vec<u8>, Vec<u8>) {
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(&self.d);
        seed.extend_from_slice(&self.z);
        (seed, self.ek.clone())
    }

    /// Import from (dk_seed_64, ek). The level comes from the length of
    /// `ek`; the `ek` is re-derived from the seed and must match.
    pub fn import_keys(dk_seed: &[u8], ek_bytes: &[u8]) -> Result<Self, CipherboxError> {
        let level =
            KemLevel::from_ek_len(ek_bytes.len()).ok_or(CipherboxError::InvalidKeyLength {
                expected: kem::EK_BYTES,
                got: ek_bytes.len(),
            })?;
        let kp = Self::from_seed_with_level(dk_seed, level)?;
        if kp.ek.as_slice() != ek_bytes {
            return Err(CipherboxError::Crypto("ek does not match dk_seed".into()));
        }
        Ok(kp)
    }

    /// Reconstruct an ML-KEM-768 key pair from the 64-byte seed.
    pub fn from_seed(dk_seed: &[u8]) -> Result<Self, CipherboxError> {
        Self::from_seed_with_level(dk_seed, KemLevel::MlKem768)
    }

    pub fn from_seed_with_level(dk_seed: &[u8], level: KemLevel) -> Result<Self, CipherboxError> {
        if dk_seed.len() != 64 {
            return Err(CipherboxError::InvalidKeyLength {
                expected: 64,
                got: dk_seed.len(),
            });
        }
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        d.copy_from_slice(&dk_seed[..32]);
        z.copy_from_slice(&dk_seed[32..]);
        let (ek, dk) = kem::keygen_level(level, &d, &z);
        Ok(Self {
            level,
            d,
            z,
            ek,
            dk,
        })
    }

    pub fn level(&self) -> KemLevel {
        self.level
    }

    /// The encapsulation key (1184 or 1568 bytes).
    pub fn encapsulation_key(&self) -> &[u8] {
        &self.ek
    }

    /// The decapsulation key (2400 or 3168 bytes).
    pub fn decapsulation_key(&self) -> &[u8] {
        &self.dk
    }
}

// ==========================================
// Decapsulator: anything that can open a KEM ciphertext (plain or hybrid)
// ==========================================

/// A private key that can decapsulate. Implemented by [`MlKemKeyPair`] and
/// [`HybridKeyPair`]; the unwrap functions accept either.
pub trait Decapsulator {
    fn suite(&self) -> Suite;
    /// The matching public key (what the sender encapsulated to).
    fn public_key_bytes(&self) -> &[u8];
    fn decapsulate_raw(&self, ct: &[u8]) -> Result<[u8; 32], CipherboxError>;
}

impl Decapsulator for MlKemKeyPair {
    fn suite(&self) -> Suite {
        Suite::Kem(self.level)
    }

    fn public_key_bytes(&self) -> &[u8] {
        &self.ek
    }

    fn decapsulate_raw(&self, ct: &[u8]) -> Result<[u8; 32], CipherboxError> {
        kem::decaps_level(self.level, &self.dk, ct)
    }
}

// ==========================================
// ML-DSA (Dilithium), via the ml-dsa crate. The same code is instantiated
// for ML-DSA-65 and ML-DSA-87.
// ==========================================

macro_rules! define_ml_dsa {
    ($name:ident, $param:ty, $vk_len:expr, $doc:expr) => {
        #[doc = $doc]
        pub struct $name {
            sk: SigningKey<$param>,
            vk: VerifyingKey<$param>,
        }

        impl $name {
            pub fn new() -> Self {
                let sk = SigningKey::<$param>::generate();
                let vk = sk.verifying_key();
                Self { sk, vk }
            }

            pub fn sign(&self, message: &[u8]) -> Vec<u8> {
                let sig = self.sk.sign(message);
                sig.encode().to_vec()
            }

            pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
                let Ok(sig_arr) = signature.try_into() else {
                    return false;
                };
                let Some(sig) = Signature::<$param>::decode(sig_arr) else {
                    return false;
                };
                self.vk.verify(message, &sig).is_ok()
            }

            pub fn export_keys(&self) -> (Vec<u8>, Vec<u8>) {
                let seed = self.sk.to_seed();
                let vk_bytes = self.vk.encode();
                (seed.to_vec(), vk_bytes.as_slice().to_vec())
            }

            pub fn import_keys(seed: &[u8], vk_bytes: &[u8]) -> Result<Self, CipherboxError> {
                const SEED_LEN: usize = 32;
                const VK_LEN: usize = $vk_len;

                if seed.len() != SEED_LEN {
                    return Err(CipherboxError::InvalidKeyLength {
                        expected: SEED_LEN,
                        got: seed.len(),
                    });
                }
                if vk_bytes.len() != VK_LEN {
                    return Err(CipherboxError::InvalidKeyLength {
                        expected: VK_LEN,
                        got: vk_bytes.len(),
                    });
                }

                let seed_arr: &ml_dsa::Seed = seed
                    .try_into()
                    .map_err(|_| CipherboxError::Crypto("invalid seed".into()))?;
                let sk = SigningKey::<$param>::from_seed(seed_arr);

                let vk_arr: &ml_dsa::EncodedVerifyingKey<$param> = vk_bytes
                    .try_into()
                    .map_err(|_| CipherboxError::Crypto("invalid vk length".into()))?;
                let vk = VerifyingKey::<$param>::decode(vk_arr);

                Ok(Self { sk, vk })
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }
    };
}

define_ml_dsa!(
    MlDsaKeyPair,
    MlDsa65,
    1952,
    "ML-DSA-65 key pair (verifying key 1952 bytes, signature 3309 bytes)."
);
define_ml_dsa!(
    MlDsa87KeyPair,
    MlDsa87,
    2592,
    "ML-DSA-87 key pair (verifying key 2592 bytes, signature 4627 bytes; CNSA 2.0 level)."
);

// ==========================================
// ML-DSA verification with only a public key
// ==========================================

macro_rules! define_ml_dsa_verify {
    ($fn_name:ident, $param:ty) => {
        fn $fn_name(vk_bytes: &[u8], message: &[u8], signature: &[u8]) -> bool {
            let vk_arr: &ml_dsa::EncodedVerifyingKey<$param> = match vk_bytes.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            };
            let sig_arr: &ml_dsa::EncodedSignature<$param> = match signature.try_into() {
                Ok(a) => a,
                Err(_) => return false,
            };
            let vk = VerifyingKey::<$param>::decode(vk_arr);
            let sig = match Signature::<$param>::decode(sig_arr) {
                Some(s) => s,
                None => return false,
            };
            vk.verify(message, &sig).is_ok()
        }
    };
}

define_ml_dsa_verify!(ml_dsa_65_verify, MlDsa65);
define_ml_dsa_verify!(ml_dsa_87_verify, MlDsa87);

/// Verify an ML-DSA signature knowing only the verifying key. The parameter
/// set follows from the key length: 1952 bytes = ML-DSA-65, 2592 = ML-DSA-87.
/// Returns `false` for anything malformed.
pub fn ml_dsa_verify(vk_bytes: &[u8], message: &[u8], signature: &[u8]) -> bool {
    match vk_bytes.len() {
        1952 => ml_dsa_65_verify(vk_bytes, message, signature),
        2592 => ml_dsa_87_verify(vk_bytes, message, signature),
        _ => false,
    }
}

// ==========================================
// Passphrase encryption (Argon2id + ChaCha20-Poly1305)
//
// v2 blob: "CBPK" | 0x02 | m_cost u32 LE (KiB) | t_cost u32 LE | p_cost u32 LE
//          | salt 16 | nonce 12 | ciphertext+tag
// The 17-byte header is authenticated as AAD, so the KDF parameters cannot
// be tampered with. Legacy blobs (salt 16 | nonce 12 | ct, default Argon2id
// parameters) are still accepted by `decrypt_private_key`.
// ==========================================

const PK_MAGIC: &[u8; 4] = b"CBPK";
const PK_VERSION: u8 = 2;
const PK_HEADER_BYTES: usize = 4 + 1 + 4 + 4 + 4;
const PK_SALT_BYTES: usize = 16;
const PK_NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;

// Upper bounds applied to untrusted headers (denial-of-service guard).
const PK_MAX_M_COST: u32 = 512 * 1024; // 512 MiB
const PK_MAX_T_COST: u32 = 16;
const PK_MAX_P_COST: u32 = 16;

fn argon2_derive(
    passphrase: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; 32], CipherboxError> {
    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| CipherboxError::Crypto(format!("Argon2 params: {e:?}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| CipherboxError::Crypto(format!("Argon2: {e:?}")))?;
    Ok(key)
}

pub fn encrypt_private_key(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, CipherboxError> {
    encrypt_private_key_with_params(
        plaintext,
        passphrase,
        Params::DEFAULT_M_COST,
        Params::DEFAULT_T_COST,
        Params::DEFAULT_P_COST,
    )
}

/// Like [`encrypt_private_key`] with explicit Argon2id cost parameters
/// (`m_cost` in KiB). Parameters are stored in the blob.
pub fn encrypt_private_key_with_params(
    plaintext: &[u8],
    passphrase: &str,
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<Vec<u8>, CipherboxError> {
    if m_cost > PK_MAX_M_COST
        || !(1..=PK_MAX_T_COST).contains(&t_cost)
        || !(1..=PK_MAX_P_COST).contains(&p_cost)
    {
        return Err(CipherboxError::Crypto(
            "Argon2 parameters outside the supported range".into(),
        ));
    }

    let mut header = Vec::with_capacity(PK_HEADER_BYTES);
    header.extend_from_slice(PK_MAGIC);
    header.push(PK_VERSION);
    header.extend_from_slice(&m_cost.to_le_bytes());
    header.extend_from_slice(&t_cost.to_le_bytes());
    header.extend_from_slice(&p_cost.to_le_bytes());

    let mut salt = [0u8; PK_SALT_BYTES];
    let mut nonce_bytes = [0u8; PK_NONCE_BYTES];
    fill_random(&mut salt)?;
    fill_random(&mut nonce_bytes)?;

    let mut key_bytes = argon2_derive(passphrase, &salt, m_cost, t_cost, p_cost)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    key_bytes.zeroize();

    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|e| CipherboxError::Crypto(format!("encrypt: {e:?}")))?;

    let mut result = header;
    result.extend_from_slice(&salt);
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

fn read_u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

pub fn decrypt_private_key(encrypted: &[u8], passphrase: &str) -> Result<Vec<u8>, CipherboxError> {
    let wrong =
        || CipherboxError::Crypto("decrypt failed (wrong passphrase or tampered data)".into());

    if encrypted.len() >= PK_HEADER_BYTES && &encrypted[..4] == PK_MAGIC {
        // ---- v2 ----
        let version = encrypted[4];
        if version != PK_VERSION {
            return Err(CipherboxError::Crypto(format!(
                "unsupported key blob version: {version}"
            )));
        }
        let min_len = PK_HEADER_BYTES + PK_SALT_BYTES + PK_NONCE_BYTES + TAG_BYTES;
        if encrypted.len() < min_len {
            return Err(CipherboxError::InvalidKeyLength {
                expected: min_len,
                got: encrypted.len(),
            });
        }
        let m_cost = read_u32_le(&encrypted[5..9]);
        let t_cost = read_u32_le(&encrypted[9..13]);
        let p_cost = read_u32_le(&encrypted[13..17]);
        if m_cost > PK_MAX_M_COST
            || !(1..=PK_MAX_T_COST).contains(&t_cost)
            || !(1..=PK_MAX_P_COST).contains(&p_cost)
        {
            return Err(CipherboxError::Crypto(
                "Argon2 parameters in blob outside the supported range".into(),
            ));
        }
        let header = &encrypted[..PK_HEADER_BYTES];
        let salt = &encrypted[PK_HEADER_BYTES..PK_HEADER_BYTES + PK_SALT_BYTES];
        let nonce_off = PK_HEADER_BYTES + PK_SALT_BYTES;
        let nonce = Nonce::from_slice(&encrypted[nonce_off..nonce_off + PK_NONCE_BYTES]);
        let ct = &encrypted[nonce_off + PK_NONCE_BYTES..];

        let mut key_bytes = argon2_derive(passphrase, salt, m_cost, t_cost, p_cost)?;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
        key_bytes.zeroize();
        return cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ct,
                    aad: header,
                },
            )
            .map_err(|_| wrong());
    }

    // ---- legacy: salt 16 | nonce 12 | ct, Argon2id default parameters ----
    if encrypted.len() < 28 {
        return Err(CipherboxError::InvalidKeyLength {
            expected: 28,
            got: encrypted.len(),
        });
    }
    let salt = &encrypted[0..16];
    let nonce = Nonce::from_slice(&encrypted[16..28]);
    let ct = &encrypted[28..];
    let mut key_bytes = argon2_derive(
        passphrase,
        salt,
        Params::DEFAULT_M_COST,
        Params::DEFAULT_T_COST,
        Params::DEFAULT_P_COST,
    )?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key_bytes));
    key_bytes.zeroize();
    cipher.decrypt(nonce, ct).map_err(|_| wrong())
}

// ==========================================
// Key wrapping (ML-KEM + ChaCha20-Poly1305)
//
// wrap key = SHA3-256("cipherbox-wrap-v1" || ct || SHA3-256(ek) || shared_secret)
// which binds the key to the ciphertext and to the recipient. Works for
// both ML-KEM levels; the level is taken from the key (wrap) or from the
// key pair (unwrap).
// ==========================================

const WRAP_MAGIC: &[u8; 4] = b"CBWK";
const WRAP_VERSION: u8 = 0x01;
const WRAP_HEADER_BYTES: usize = 5;
const WRAP_KDF_DOMAIN: &[u8] = b"cipherbox-wrap-v1";
const ROOM_KEY_AAD: &[u8] = b"cipherbox-room-key-v2";

fn derive_wrap_key(ss: &[u8; 32], ct: &[u8], ek: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(WRAP_KDF_DOMAIN.len() + ct.len() + 64);
    input.extend_from_slice(WRAP_KDF_DOMAIN);
    input.extend_from_slice(ct);
    input.extend_from_slice(&sha3_256(ek));
    input.extend_from_slice(ss);
    let key = sha3_256(&input);
    input.zeroize();
    key
}

/// `(kem_ct, nonce, aead_ct)`
type Sealed = (Vec<u8>, [u8; 12], Vec<u8>);

/// Returns `(kem_ct, nonce, aead_ct)`. `ek` may be a plain ML-KEM or a
/// hybrid public key (validated here).
fn seal(ek: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Sealed, CipherboxError> {
    let (_suite, ct, mut ss) = hybrid::encapsulate_any(ek)?;

    let mut key = derive_wrap_key(&ss, &ct, ek);
    ss.zeroize();
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    key.zeroize();

    let mut nonce = [0u8; 12];
    fill_random(&mut nonce)?;
    let enc = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| CipherboxError::Crypto(format!("encrypt: {e:?}")))?;
    Ok((ct, nonce, enc))
}

/// `legacy = true` reproduces the old v1 behaviour (raw shared secret as
/// the AEAD key, no AAD). It exists only to migrate old data.
fn open<K: Decapsulator + ?Sized>(
    kp: &K,
    ct: &[u8],
    nonce: &[u8],
    enc: &[u8],
    aad: &[u8],
    legacy: bool,
) -> Result<Vec<u8>, CipherboxError> {
    let ct_len = kp.suite().ct_bytes();
    if ct.len() != ct_len {
        return Err(CipherboxError::InvalidKeyLength {
            expected: ct_len,
            got: ct.len(),
        });
    }
    if nonce.len() != 12 {
        return Err(CipherboxError::InvalidKeyLength {
            expected: 12,
            got: nonce.len(),
        });
    }
    let mut ss = kp.decapsulate_raw(ct)?;

    let mut key = if legacy {
        ss
    } else {
        derive_wrap_key(&ss, ct, kp.public_key_bytes())
    };
    ss.zeroize();
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    key.zeroize();

    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: enc,
                aad: if legacy { &[] } else { aad },
            },
        )
        .map_err(|_| CipherboxError::Crypto("unwrap failed (wrong key or tampered data)".into()))
}

/// Binary wrap: `"CBWK" | 0x01 | kem_ct | nonce 12 | aead_ct`. Works for
/// plain ML-KEM and hybrid public keys; the suite follows from the key length.
pub fn wrap_key(ek_bytes: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, CipherboxError> {
    validate_public_key(ek_bytes)?;
    let mut header = [0u8; WRAP_HEADER_BYTES];
    header[..4].copy_from_slice(WRAP_MAGIC);
    header[4] = WRAP_VERSION;
    let (ct, nonce, enc) = seal(ek_bytes, plaintext, &header)?;

    let mut out = Vec::with_capacity(WRAP_HEADER_BYTES + ct.len() + 12 + enc.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&enc);
    Ok(out)
}

pub fn unwrap_key<K: Decapsulator + ?Sized>(
    kp: &K,
    blob: &[u8],
) -> Result<Vec<u8>, CipherboxError> {
    let ct_len = kp.suite().ct_bytes();
    let min = WRAP_HEADER_BYTES + ct_len + 12 + TAG_BYTES;
    if blob.len() < min {
        return Err(CipherboxError::InvalidKeyLength {
            expected: min,
            got: blob.len(),
        });
    }
    if &blob[..4] != WRAP_MAGIC || blob[4] != WRAP_VERSION {
        return Err(CipherboxError::Crypto("bad wrapped-key header".into()));
    }
    let ct_end = WRAP_HEADER_BYTES + ct_len;
    open(
        kp,
        &blob[WRAP_HEADER_BYTES..ct_end],
        &blob[ct_end..ct_end + 12],
        &blob[ct_end + 12..],
        &blob[..WRAP_HEADER_BYTES],
        false,
    )
}

/// Server-side helper. Output (version 2):
/// `{"v":2,"ct":"..","iv":"..","enc_aes":".."}` (standard base64).
/// The public key may be plain ML-KEM (768/1024) or hybrid; the suite is
/// taken from its length.
///
/// **Breaking change vs 0.3:** version 1 used the raw KEM shared secret as
/// the AEAD key. Version 2 uses a domain-separated KDF; decrypt old data
/// with [`unwrap_room_key`] and `version = 1`.
pub fn wrap_room_key_for_user(
    user_pk_b64: &str,
    room_key_plaintext: &str,
) -> Result<String, CipherboxError> {
    let pk_bytes = general_purpose::STANDARD
        .decode(user_pk_b64)
        .map_err(|e| CipherboxError::Crypto(format!("invalid pk b64: {e}")))?;
    validate_public_key(&pk_bytes)?;
    let (ct, iv, enc) = seal(&pk_bytes, room_key_plaintext.as_bytes(), ROOM_KEY_AAD)?;

    Ok(format!(
        r#"{{"v":2,"ct":"{}","iv":"{}","enc_aes":"{}"}}"#,
        general_purpose::STANDARD.encode(&ct),
        general_purpose::STANDARD.encode(iv),
        general_purpose::STANDARD.encode(&enc)
    ))
}

/// Inverse of [`wrap_room_key_for_user`]. `version` is the JSON `"v"`
/// field (missing means 1, the legacy format).
pub fn unwrap_room_key<K: Decapsulator + ?Sized>(
    kp: &K,
    version: u8,
    ct_b64: &str,
    iv_b64: &str,
    enc_aes_b64: &str,
) -> Result<String, CipherboxError> {
    let dec = |s: &str, what: &str| {
        general_purpose::STANDARD
            .decode(s)
            .map_err(|e| CipherboxError::Crypto(format!("invalid {what} b64: {e}")))
    };
    let ct = dec(ct_b64, "ct")?;
    let iv = dec(iv_b64, "iv")?;
    let enc = dec(enc_aes_b64, "enc_aes")?;
    let legacy = match version {
        1 => true,
        2 => false,
        v => {
            return Err(CipherboxError::Crypto(format!(
                "unsupported room key version: {v}"
            )));
        }
    };
    let mut pt = open(kp, &ct, &iv, &enc, ROOM_KEY_AAD, legacy)?;
    let s = String::from_utf8(pt.clone())
        .map_err(|_| CipherboxError::Crypto("room key is not valid UTF-8".into()));
    pt.zeroize();
    s
}
