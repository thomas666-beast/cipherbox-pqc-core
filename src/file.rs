//! Chunked large-file encryption (STREAM construction) using the
//! from-scratch ML-KEM implementation for key transport.
//!
//! ## File format
//!
//! ```text
//! v1 (ML-KEM-768):  magic "CBOX" | 0x01 | chunk_size u32 LE | kem_ct (1088 B) | chunks...
//! v2 (any suite):   magic "CBOX" | 0x02 | suite id u8 | chunk_size u32 LE | kem_ct | chunks...
//! ```
//!
//! Files for plain ML-KEM-768 keys are still written as v1 (so older readers
//! keep working); everything else uses v2. Suite ids: 3 = ML-KEM-768,
//! 5 = ML-KEM-1024, 0x13 = X25519+ML-KEM-768, 0x15 = X25519+ML-KEM-1024
//! (for hybrids `kem_ct` is `ct_mlkem || ct_x25519`).
//!
//! ## Key derivation
//!
//! ```text
//! aead_key = SHA3-256(domain || header || shared_secret)
//! ```
//!
//! `domain` is `"cipherbox-file-v1"` for v1 and `"cipherbox-file-v2"` for v2;
//! `header` is every byte from `magic` through the end of `kem_ct`, so
//! modifying any header field makes every chunk fail authentication.
//!
//! ## Chunk framing
//!
//! ChaCha20-Poly1305 with nonce `counter (u64 LE) || 00 00 00 || last_flag`.
//! The last chunk has `last_flag = 0x01`, all others `0x00`. The last chunk
//! is always present and may be empty. Stripping trailing chunks therefore
//! leaves a final chunk authenticated with `last_flag = 0`, which fails.

use crate::hybrid::{self, HybridKeyPair};
use crate::keccak::sha3_256;
use crate::params::{KemLevel, Suite};
use crate::{CipherboxError, Decapsulator, kem};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use zeroize::Zeroize;

pub const MAGIC: &[u8; 4] = b"CBOX";
/// Legacy format (ML-KEM-768 only).
pub const VERSION: u8 = 0x01;
/// Format that records the ML-KEM level in the header.
pub const VERSION_2: u8 = 0x02;
pub const TAG_BYTES: usize = 16;
/// v1 header size (ML-KEM-768).
pub const HEADER_BYTES: usize = 4 + 1 + 4 + kem::CT_BYTES;

pub const CHUNK_SIZE_DEFAULT: usize = 65536;
pub const CHUNK_SIZE_MIN: usize = 64;
pub const CHUNK_SIZE_MAX: usize = 1024 * 1024;

const KDF_DOMAIN_V1: &[u8] = b"cipherbox-file-v1";
const KDF_DOMAIN_V2: &[u8] = b"cipherbox-file-v2";
const CHUNK_AAD: &[u8] = b"CBOX-v1-chunk";

/// Format version used when writing a file for `suite`.
fn version_for(suite: Suite) -> u8 {
    match suite {
        Suite::Kem(KemLevel::MlKem768) => VERSION,
        _ => VERSION_2,
    }
}

/// (offset of chunk_size, offset of kem_ct) for a format version.
fn offsets(version: u8) -> (usize, usize) {
    if version == VERSION { (5, 9) } else { (6, 10) }
}

/// Total header length produced for files written for `suite`.
pub fn header_len_suite(suite: Suite) -> usize {
    offsets(version_for(suite)).1 + suite.ct_bytes()
}

/// Total header length for files written for a plain ML-KEM `level`.
pub fn header_len(level: KemLevel) -> usize {
    header_len_suite(Suite::Kem(level))
}

fn kdf_domain(version: u8) -> &'static [u8] {
    if version == VERSION {
        KDF_DOMAIN_V1
    } else {
        KDF_DOMAIN_V2
    }
}

fn build_nonce(counter: u64, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&counter.to_le_bytes());
    n[11] = if last { 0x01 } else { 0x00 };
    n
}

fn derive_aead_key(version: u8, shared_secret: &[u8; 32], header: &[u8]) -> [u8; 32] {
    let domain = kdf_domain(version);
    let mut input = Vec::with_capacity(domain.len() + header.len() + 32);
    input.extend_from_slice(domain);
    input.extend_from_slice(header);
    input.extend_from_slice(shared_secret);
    let key = sha3_256(&input);
    input.zeroize();
    key
}

fn validate_chunk_size(chunk_size: usize) -> Result<(), CipherboxError> {
    if !(CHUNK_SIZE_MIN..=CHUNK_SIZE_MAX).contains(&chunk_size) {
        return Err(CipherboxError::Crypto(format!(
            "chunk_size {chunk_size} outside allowed range [{CHUNK_SIZE_MIN}, {CHUNK_SIZE_MAX}]"
        )));
    }
    Ok(())
}

fn bump(counter: u64) -> Result<u64, CipherboxError> {
    counter
        .checked_add(1)
        .ok_or_else(|| CipherboxError::Crypto("chunk counter overflow".into()))
}

// ==========================================
// Streaming encryptor
// ==========================================

pub struct FileEncryptor {
    cipher: ChaCha20Poly1305,
    chunk_size: usize,
    counter: u64,
    buffer: Vec<u8>,
    header: Vec<u8>,
    header_written: bool,
    finished: bool,
}

impl FileEncryptor {
    /// The suite is inferred from the public key length: 1184 / 1568 for
    /// plain ML-KEM-768 / 1024, 1216 / 1600 for X25519 hybrids. The key must
    /// pass validation (FIPS 203 modulus check on the ML-KEM part).
    pub fn new(recipient_ek: &[u8], chunk_size: usize) -> Result<Self, CipherboxError> {
        validate_chunk_size(chunk_size)?;
        let (suite, kem_ct, mut shared_secret) = hybrid::encapsulate_any(recipient_ek)?;

        let version = version_for(suite);
        let mut header = Vec::with_capacity(header_len_suite(suite));
        header.extend_from_slice(MAGIC);
        header.push(version);
        if version == VERSION_2 {
            header.push(suite.id());
        }
        header.extend_from_slice(&(chunk_size as u32).to_le_bytes());
        header.extend_from_slice(&kem_ct);
        debug_assert_eq!(header.len(), header_len_suite(suite));

        let mut aead_key = derive_aead_key(version, &shared_secret, &header);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
        shared_secret.zeroize();
        aead_key.zeroize();

        Ok(Self {
            cipher,
            chunk_size,
            counter: 0,
            buffer: Vec::with_capacity(chunk_size),
            header,
            header_written: false,
            finished: false,
        })
    }

    pub fn update(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<(), CipherboxError> {
        if self.finished {
            return Err(CipherboxError::Crypto("encryptor already finished".into()));
        }
        if !self.header_written {
            out.extend_from_slice(&self.header);
            self.header_written = true;
        }
        self.buffer.extend_from_slice(plaintext);
        while self.buffer.len() >= self.chunk_size {
            let nonce_bytes = build_nonce(self.counter, false);
            let nonce = Nonce::from_slice(&nonce_bytes);
            let ct = self
                .cipher
                .encrypt(
                    nonce,
                    Payload {
                        msg: &self.buffer[..self.chunk_size],
                        aad: CHUNK_AAD,
                    },
                )
                .map_err(|e| CipherboxError::Crypto(format!("encrypt: {e:?}")))?;
            out.extend_from_slice(&ct);
            self.buffer.drain(..self.chunk_size);
            self.counter = bump(self.counter)?;
        }
        Ok(())
    }

    pub fn finish(mut self, out: &mut Vec<u8>) -> Result<(), CipherboxError> {
        if self.finished {
            return Err(CipherboxError::Crypto("encryptor already finished".into()));
        }
        if !self.header_written {
            out.extend_from_slice(&self.header);
            self.header_written = true;
        }
        let nonce_bytes = build_nonce(self.counter, true);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ct = self
            .cipher
            .encrypt(
                nonce,
                Payload {
                    msg: &self.buffer,
                    aad: CHUNK_AAD,
                },
            )
            .map_err(|e| CipherboxError::Crypto(format!("encrypt: {e:?}")))?;
        out.extend_from_slice(&ct);
        self.buffer.clear();
        self.finished = true;
        Ok(())
    }
}

impl Drop for FileEncryptor {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

// ==========================================
// Streaming decryptor
// ==========================================

enum KeySource {
    /// A full decapsulation key of a known level.
    Dk { level: KemLevel, dk: Vec<u8> },
    /// A 64-byte seed (`d || z`); the key for the file's level is derived
    /// once the header has been read.
    Seed([u8; 64]),
    /// An X25519 + ML-KEM hybrid key pair.
    Hybrid(HybridKeyPair),
}

pub struct FileDecryptor {
    key: KeySource,
    cipher: Option<ChaCha20Poly1305>,
    chunk_size: usize,
    counter: u64,
    buffer: Vec<u8>,
    header_parsed: bool,
}

impl FileDecryptor {
    /// From a full decapsulation key (level inferred from its length).
    /// Fails if the key is internally inconsistent (FIPS 203 section 7.3).
    pub fn new(recipient_dk: &[u8]) -> Result<Self, CipherboxError> {
        let level =
            KemLevel::from_dk_len(recipient_dk.len()).ok_or(CipherboxError::InvalidKeyLength {
                expected: kem::DK_BYTES,
                got: recipient_dk.len(),
            })?;
        if !kem::check_dk_level(level, recipient_dk) {
            return Err(CipherboxError::Crypto(
                "decapsulation key failed the FIPS 203 consistency check".into(),
            ));
        }
        Ok(Self::with_key(KeySource::Dk {
            level,
            dk: recipient_dk.to_vec(),
        }))
    }

    /// From the 64-byte seed. Works for files of either ML-KEM level.
    pub fn from_seed(seed: &[u8]) -> Result<Self, CipherboxError> {
        if seed.len() != 64 {
            return Err(CipherboxError::InvalidKeyLength {
                expected: 64,
                got: seed.len(),
            });
        }
        let mut s = [0u8; 64];
        s.copy_from_slice(seed);
        Ok(Self::with_key(KeySource::Seed(s)))
    }

    /// From the 34-byte secret of a [`HybridKeyPair`] (the level is part of
    /// the secret). Only reads files encrypted to the matching hybrid suite.
    pub fn from_hybrid_secret(secret: &[u8]) -> Result<Self, CipherboxError> {
        Ok(Self::with_key(KeySource::Hybrid(
            HybridKeyPair::from_secret(secret)?,
        )))
    }

    fn with_key(key: KeySource) -> Self {
        Self {
            key,
            cipher: None,
            chunk_size: 0,
            counter: 0,
            buffer: Vec::new(),
            header_parsed: false,
        }
    }

    fn try_parse_header(&mut self) -> Result<(), CipherboxError> {
        if self.header_parsed || self.buffer.len() < 5 {
            return Ok(());
        }
        if &self.buffer[..4] != MAGIC {
            return Err(CipherboxError::Crypto("bad magic".into()));
        }
        let version = self.buffer[4];
        let suite = match version {
            VERSION => Suite::Kem(KemLevel::MlKem768),
            VERSION_2 => {
                if self.buffer.len() < 6 {
                    return Ok(());
                }
                Suite::from_id(self.buffer[5]).ok_or_else(|| {
                    CipherboxError::Crypto(format!("unknown suite id 0x{:02x}", self.buffer[5]))
                })?
            }
            v => {
                return Err(CipherboxError::Crypto(format!(
                    "unsupported version: 0x{v:02x}"
                )));
            }
        };
        let (cs_off, ct_off) = offsets(version);
        let header_len = ct_off + suite.ct_bytes();
        if self.buffer.len() < header_len {
            return Ok(());
        }

        // The key must match the suite the file was encrypted for.
        let key_suite = match &self.key {
            KeySource::Dk { level, .. } => Some(Suite::Kem(*level)),
            KeySource::Hybrid(kp) => Some(kp.suite()),
            KeySource::Seed(_) => None,
        };
        if let Some(ks) = key_suite {
            if ks != suite {
                return Err(CipherboxError::Crypto(format!(
                    "file was encrypted for {} but the key is {}",
                    suite.name(),
                    ks.name()
                )));
            }
        } else if suite.is_hybrid() {
            return Err(CipherboxError::Crypto(format!(
                "file was encrypted for {}: a hybrid key is required",
                suite.name()
            )));
        }

        let chunk_size = u32::from_le_bytes([
            self.buffer[cs_off],
            self.buffer[cs_off + 1],
            self.buffer[cs_off + 2],
            self.buffer[cs_off + 3],
        ]) as usize;
        validate_chunk_size(chunk_size)?;

        let header_bytes: Vec<u8> = self.buffer[..header_len].to_vec();
        let kem_ct = &self.buffer[ct_off..header_len];

        let mut shared_secret = match &self.key {
            KeySource::Dk { level, dk } => kem::decaps_level(*level, dk, kem_ct)?,
            KeySource::Hybrid(kp) => kp.decapsulate_raw(kem_ct)?,
            KeySource::Seed(seed) => {
                let level = suite.level();
                let mut d = [0u8; 32];
                let mut z = [0u8; 32];
                d.copy_from_slice(&seed[..32]);
                z.copy_from_slice(&seed[32..]);
                let (_ek, mut dk) = kem::keygen_level(level, &d, &z);
                d.zeroize();
                z.zeroize();
                let ss = kem::decaps_level(level, &dk, kem_ct);
                dk.zeroize();
                ss?
            }
        };
        let mut aead_key = derive_aead_key(version, &shared_secret, &header_bytes);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));
        shared_secret.zeroize();
        aead_key.zeroize();

        self.buffer.drain(..header_len);
        self.cipher = Some(cipher);
        self.chunk_size = chunk_size;
        self.header_parsed = true;
        Ok(())
    }

    pub fn update(&mut self, ciphertext: &[u8], out: &mut Vec<u8>) -> Result<(), CipherboxError> {
        self.buffer.extend_from_slice(ciphertext);
        self.try_parse_header()?;
        if !self.header_parsed {
            return Ok(());
        }
        let ct_full = self.chunk_size + TAG_BYTES;
        while self.buffer.len() > ct_full {
            let pt = {
                let cipher = self
                    .cipher
                    .as_ref()
                    .ok_or_else(|| CipherboxError::Crypto("cipher not initialized".into()))?;
                let nonce_bytes = build_nonce(self.counter, false);
                let nonce = Nonce::from_slice(&nonce_bytes);
                cipher
                    .decrypt(
                        nonce,
                        Payload {
                            msg: &self.buffer[..ct_full],
                            aad: CHUNK_AAD,
                        },
                    )
                    .map_err(|_| {
                        CipherboxError::Crypto(format!(
                            "chunk {} failed to authenticate",
                            self.counter
                        ))
                    })?
            };
            out.extend_from_slice(&pt);
            self.buffer.drain(..ct_full);
            self.counter = bump(self.counter)?;
        }
        Ok(())
    }

    pub fn finish(mut self, out: &mut Vec<u8>) -> Result<(), CipherboxError> {
        self.try_parse_header()?;
        if !self.header_parsed {
            return Err(CipherboxError::Crypto("incomplete header".into()));
        }
        if self.cipher.is_none() {
            return Err(CipherboxError::Crypto("decryptor already finished".into()));
        }
        let remaining = std::mem::take(&mut self.buffer);
        if remaining.len() < TAG_BYTES {
            return Err(CipherboxError::Crypto(
                "missing last chunk (stream truncated?)".into(),
            ));
        }
        if remaining.len() > self.chunk_size + TAG_BYTES {
            return Err(CipherboxError::Crypto(
                "last chunk larger than declared chunk_size".into(),
            ));
        }
        let pt = {
            let cipher = self
                .cipher
                .as_ref()
                .ok_or_else(|| CipherboxError::Crypto("cipher not initialized".into()))?;
            let nonce_bytes = build_nonce(self.counter, true);
            let nonce = Nonce::from_slice(&nonce_bytes);
            cipher
                .decrypt(
                    nonce,
                    Payload {
                        msg: &remaining,
                        aad: CHUNK_AAD,
                    },
                )
                .map_err(|_| {
                    CipherboxError::Crypto(
                        "last chunk failed to authenticate (truncation or wrong key)".into(),
                    )
                })?
        };
        out.extend_from_slice(&pt);
        self.cipher = None;
        Ok(())
    }
}

impl Drop for FileDecryptor {
    fn drop(&mut self) {
        match &mut self.key {
            KeySource::Dk { dk, .. } => dk.zeroize(),
            KeySource::Seed(s) => s.zeroize(),
            KeySource::Hybrid(_) => {} // HybridKeyPair zeroizes itself on drop
        }
        self.buffer.zeroize();
    }
}

// ==========================================
// One-shot convenience wrappers
// ==========================================

pub fn encrypt_file(
    plaintext: &[u8],
    recipient_ek: &[u8],
    chunk_size: usize,
) -> Result<Vec<u8>, CipherboxError> {
    let mut enc = FileEncryptor::new(recipient_ek, chunk_size)?;
    let mut out = Vec::with_capacity(plaintext.len() + HEADER_BYTES + chunk_size);
    enc.update(plaintext, &mut out)?;
    enc.finish(&mut out)?;
    Ok(out)
}

/// Decrypt with a full decapsulation key (768 or 1024).
pub fn decrypt_file(ciphertext: &[u8], recipient_dk: &[u8]) -> Result<Vec<u8>, CipherboxError> {
    let mut dec = FileDecryptor::new(recipient_dk)?;
    let mut out = Vec::new();
    dec.update(ciphertext, &mut out)?;
    dec.finish(&mut out)?;
    Ok(out)
}

/// Decrypt with the 64-byte seed; the level is taken from the file header.
pub fn decrypt_file_with_seed(ciphertext: &[u8], seed: &[u8]) -> Result<Vec<u8>, CipherboxError> {
    let mut dec = FileDecryptor::from_seed(seed)?;
    let mut out = Vec::new();
    dec.update(ciphertext, &mut out)?;
    dec.finish(&mut out)?;
    Ok(out)
}

/// Decrypt with the 34-byte secret of a hybrid key pair.
pub fn decrypt_file_with_hybrid_secret(
    ciphertext: &[u8],
    secret: &[u8],
) -> Result<Vec<u8>, CipherboxError> {
    let mut dec = FileDecryptor::from_hybrid_secret(secret)?;
    let mut out = Vec::new();
    dec.update(ciphertext, &mut out)?;
    dec.finish(&mut out)?;
    Ok(out)
}
