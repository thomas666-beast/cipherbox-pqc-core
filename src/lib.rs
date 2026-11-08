//! Cipherbox PQC core: from-scratch ML-KEM-768 plus ML-DSA, passphrase
//! encryption, and key wrapping helpers shared by the native and WASM
//! crates.

use argon2::Argon2;
use base64::{Engine as _, engine::general_purpose};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use getrandom::getrandom;
use ml_dsa::signature::{Keypair, Signer, Verifier};
use ml_dsa::{Generate, MlDsa65, Signature, SigningKey, VerifyingKey};

pub mod field;
pub mod file;
pub mod keccak;
pub mod kem;
pub mod ntt;
pub mod pke;
pub mod poly;

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
// ML-KEM (Kyber) — from-scratch implementation
// ==========================================

pub struct MlKemKeyPair {
    d: [u8; 32],
    z: [u8; 32],
    ek: [u8; kem::EK_BYTES],
    dk: [u8; kem::DK_BYTES],
}

impl MlKemKeyPair {
    pub fn new() -> Result<Self, CipherboxError> {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        fill_random(&mut d)?;
        fill_random(&mut z)?;
        let (ek, dk) = kem::keygen(&d, &z);
        Ok(Self { d, z, ek, dk })
    }

    pub fn encapsulate(&self) -> Result<(Vec<u8>, Vec<u8>), CipherboxError> {
        let mut m = [0u8; 32];
        fill_random(&mut m)?;
        let (ct, ss) = kem::encaps(&self.ek, &m);
        Ok((ct.to_vec(), ss.to_vec()))
    }

    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Vec<u8>, CipherboxError> {
        if ciphertext.len() != kem::CT_BYTES {
            return Err(CipherboxError::InvalidKeyLength {
                expected: kem::CT_BYTES,
                got: ciphertext.len(),
            });
        }
        let mut ct = [0u8; kem::CT_BYTES];
        ct.copy_from_slice(ciphertext);
        let ss = kem::decaps(&self.dk, &ct);
        Ok(ss.to_vec())
    }

    /// Export (dk_seed_64, ek_1184). The seed is `d || z` and uniquely
    /// determines both halves of the keypair.
    pub fn export_keys(&self) -> (Vec<u8>, Vec<u8>) {
        let mut seed = Vec::with_capacity(64);
        seed.extend_from_slice(&self.d);
        seed.extend_from_slice(&self.z);
        (seed, self.ek.to_vec())
    }

    /// Import from (dk_seed_64, ek_1184). The `ek` is re-derived from the
    /// seed and validated against the provided bytes.
    pub fn import_keys(dk_seed: &[u8], ek_bytes: &[u8]) -> Result<Self, CipherboxError> {
        if dk_seed.len() != 64 {
            return Err(CipherboxError::InvalidKeyLength {
                expected: 64,
                got: dk_seed.len(),
            });
        }
        if ek_bytes.len() != kem::EK_BYTES {
            return Err(CipherboxError::InvalidKeyLength {
                expected: kem::EK_BYTES,
                got: ek_bytes.len(),
            });
        }
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        d.copy_from_slice(&dk_seed[..32]);
        z.copy_from_slice(&dk_seed[32..]);
        let (ek, dk) = kem::keygen(&d, &z);
        if ek.as_slice() != ek_bytes {
            return Err(CipherboxError::Crypto("ek does not match dk_seed".into()));
        }
        Ok(Self { d, z, ek, dk })
    }

    /// Reconstruct a keypair from the 64-byte seed (`d || z`).
    pub fn from_seed(dk_seed: &[u8]) -> Result<Self, CipherboxError> {
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
        let (ek, dk) = kem::keygen(&d, &z);
        Ok(Self { d, z, ek, dk })
    }

    /// Access the 1184-byte encapsulation key.
    pub fn encapsulation_key(&self) -> &[u8; kem::EK_BYTES] {
        &self.ek
    }

    /// Access the 2400-byte decapsulation key.
    pub fn decapsulation_key(&self) -> &[u8; kem::DK_BYTES] {
        &self.dk
    }
}

// ==========================================
// ML-DSA (Dilithium) — unchanged, still uses ml-dsa crate
// ==========================================

pub struct MlDsaKeyPair {
    sk: SigningKey<MlDsa65>,
    vk: VerifyingKey<MlDsa65>,
}

impl MlDsaKeyPair {
    pub fn new() -> Self {
        let sk = SigningKey::<MlDsa65>::generate();
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
        let Some(sig) = Signature::<MlDsa65>::decode(sig_arr) else {
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
        const VK_LEN: usize = 1952;

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
        let sk = SigningKey::<MlDsa65>::from_seed(seed_arr);

        let vk_arr: &ml_dsa::EncodedVerifyingKey<MlDsa65> = vk_bytes
            .try_into()
            .map_err(|_| CipherboxError::Crypto("invalid vk length".into()))?;
        let vk = VerifyingKey::<MlDsa65>::decode(vk_arr);

        Ok(Self { sk, vk })
    }
}

impl Default for MlDsaKeyPair {
    fn default() -> Self {
        Self::new()
    }
}

// ==========================================
// Passphrase encryption (Argon2 + ChaCha20-Poly1305)
// ==========================================

pub fn encrypt_private_key(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, CipherboxError> {
    let mut salt_bytes = [0u8; 16];
    fill_random(&mut salt_bytes)?;

    let argon2 = Argon2::default();
    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt_bytes, &mut key_bytes)
        .map_err(|e| CipherboxError::Crypto(format!("Argon2: {e:?}")))?;

    let key = Key::from_slice(&key_bytes);
    let mut nonce_bytes = [0u8; 12];
    fill_random(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = ChaCha20Poly1305::new(key);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| CipherboxError::Crypto(format!("encrypt: {e:?}")))?;

    let mut result = salt_bytes.to_vec();
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub fn decrypt_private_key(encrypted: &[u8], passphrase: &str) -> Result<Vec<u8>, CipherboxError> {
    if encrypted.len() < 28 {
        return Err(CipherboxError::InvalidKeyLength {
            expected: 28,
            got: encrypted.len(),
        });
    }

    let salt_bytes = &encrypted[0..16];
    let nonce_bytes = &encrypted[16..28];
    let nonce = Nonce::from_slice(nonce_bytes);
    let ciphertext = &encrypted[28..];

    let argon2 = Argon2::default();
    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt_bytes, &mut key_bytes)
        .map_err(|e| CipherboxError::Crypto(format!("Argon2: {e:?}")))?;

    let key = Key::from_slice(&key_bytes);
    let cipher = ChaCha20Poly1305::new(key);
    cipher.decrypt(nonce, ciphertext).map_err(|_| {
        CipherboxError::Crypto("decrypt failed (wrong passphrase or tampered data)".into())
    })
}

// ==========================================
// Server-side helpers (key wrapping)
// ==========================================

pub fn wrap_room_key_for_user(
    user_pk_b64: &str,
    room_key_plaintext: &str,
) -> Result<String, CipherboxError> {
    let pk_bytes = general_purpose::STANDARD
        .decode(user_pk_b64)
        .map_err(|e| CipherboxError::Crypto(format!("invalid pk b64: {e}")))?;

    if pk_bytes.len() != kem::EK_BYTES {
        return Err(CipherboxError::InvalidKeyLength {
            expected: kem::EK_BYTES,
            got: pk_bytes.len(),
        });
    }
    let mut ek = [0u8; kem::EK_BYTES];
    ek.copy_from_slice(&pk_bytes);

    let mut m = [0u8; 32];
    fill_random(&mut m)?;
    let (ct, ss) = kem::encaps(&ek, &m);

    let aes_key = Key::from_slice(&ss);
    let cipher = ChaCha20Poly1305::new(aes_key);

    let mut iv_bytes = [0u8; 12];
    fill_random(&mut iv_bytes)?;
    let nonce = Nonce::from_slice(&iv_bytes);

    let enc_aes = cipher
        .encrypt(nonce, room_key_plaintext.as_bytes())
        .map_err(|e| CipherboxError::Crypto(format!("encrypt: {e:?}")))?;

    Ok(format!(
        r#"{{"ct":"{}","iv":"{}","enc_aes":"{}"}}"#,
        general_purpose::STANDARD.encode(&ct[..]),
        general_purpose::STANDARD.encode(iv_bytes),
        general_purpose::STANDARD.encode(&enc_aes)
    ))
}
