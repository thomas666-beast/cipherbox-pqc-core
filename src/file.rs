//! Chunked large-file encryption (STREAM construction) using the
//! from-scratch ML-KEM-768 implementation for key transport.
//!
//! ## File format (v1)
//!
//! ```text
//! +--------+---------+--------------+-------------+---------+-----+------------+
//! | magic  | version | chunk_size   | kem_ct      | chunk_0 | ... | chunk_last |
//! | 4 B    | 1 B     | 4 B (LE u32) | 1088 B      | var     |     | var (last) |
//! +--------+---------+--------------+-------------+---------+-----+------------+
//! ```
//!
//! `magic` = b"CBOX", `version` = 0x01.
//!
//! ## Key derivation
//!
//! The recipient decapsulates `kem_ct` with their ML-KEM decapsulation key
//! to obtain a 32-byte shared secret. The AEAD key is:
//!
//! ```text
//! aead_key = SHA3-256("cipherbox-file-v1" || header || shared_secret)
//! ```
//!
//! where `header` is every byte from `magic` through the end of `kem_ct`.
//! This binds the header to the derived key, so modifying any header field
//! makes every chunk fail authentication.
//!
//! ## Chunk framing
//!
//! ChaCha20-Poly1305 with nonce `counter (u64 LE) || 00 00 00 || last_flag`.
//! The last chunk has `last_flag = 0x01`; all others use `0x00`. The last
//! chunk is always present and may be empty (when the plaintext length is an
//! exact multiple of `chunk_size`). This prevents truncation: an attacker
//! who strips trailing chunks leaves a final chunk whose tag was computed
//! with `last_flag = 0`, which fails when decrypted as the last chunk.

use crate::keccak::sha3_256;
use crate::{CipherboxError, kem};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit, Payload},
};

pub const MAGIC: &[u8; 4] = b"CBOX";
pub const VERSION: u8 = 0x01;
pub const TAG_BYTES: usize = 16;
pub const HEADER_BYTES: usize = 4 + 1 + 4 + kem::CT_BYTES;

pub const CHUNK_SIZE_DEFAULT: usize = 65536;
pub const CHUNK_SIZE_MIN: usize = 64;
pub const CHUNK_SIZE_MAX: usize = 1024 * 1024;

const KDF_DOMAIN: &[u8] = b"cipherbox-file-v1";
const CHUNK_AAD: &[u8] = b"CBOX-v1-chunk";

fn build_nonce(counter: u64, last: bool) -> [u8; 12] {
    let mut n = [0u8; 12];
    n[..8].copy_from_slice(&counter.to_le_bytes());
    n[11] = if last { 0x01 } else { 0x00 };
    n
}

fn derive_aead_key(shared_secret: &[u8; 32], header: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(KDF_DOMAIN.len() + header.len() + 32);
    input.extend_from_slice(KDF_DOMAIN);
    input.extend_from_slice(header);
    input.extend_from_slice(shared_secret);
    sha3_256(&input)
}

fn fill_random(buf: &mut [u8]) -> Result<(), CipherboxError> {
    getrandom::getrandom(buf).map_err(|e| CipherboxError::Crypto(format!("RNG: {e}")))
}

fn validate_chunk_size(chunk_size: usize) -> Result<(), CipherboxError> {
    if !(CHUNK_SIZE_MIN..=CHUNK_SIZE_MAX).contains(&chunk_size) {
        return Err(CipherboxError::Crypto(format!(
            "chunk_size {chunk_size} outside allowed range [{CHUNK_SIZE_MIN}, {CHUNK_SIZE_MAX}]"
        )));
    }
    Ok(())
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
    pub fn new(
        recipient_ek: &[u8; kem::EK_BYTES],
        chunk_size: usize,
    ) -> Result<Self, CipherboxError> {
        validate_chunk_size(chunk_size)?;

        let mut m = [0u8; 32];
        fill_random(&mut m)?;
        let (kem_ct, shared_secret) = kem::encaps(recipient_ek, &m);

        let mut header = Vec::with_capacity(HEADER_BYTES);
        header.extend_from_slice(MAGIC);
        header.push(VERSION);
        header.extend_from_slice(&(chunk_size as u32).to_le_bytes());
        header.extend_from_slice(&kem_ct);
        debug_assert_eq!(header.len(), HEADER_BYTES);

        let aead_key = derive_aead_key(&shared_secret, &header);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));

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
            self.counter += 1;
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

// ==========================================
// Streaming decryptor
// ==========================================

pub struct FileDecryptor {
    cipher: Option<ChaCha20Poly1305>,
    chunk_size: usize,
    counter: u64,
    buffer: Vec<u8>,
    header_parsed: bool,
    dk: [u8; kem::DK_BYTES],
}

impl FileDecryptor {
    pub fn new(recipient_dk: &[u8; kem::DK_BYTES]) -> Self {
        Self {
            cipher: None,
            chunk_size: 0,
            counter: 0,
            buffer: Vec::new(),
            header_parsed: false,
            dk: *recipient_dk,
        }
    }

    fn try_parse_header(&mut self) -> Result<(), CipherboxError> {
        if self.header_parsed {
            return Ok(());
        }
        if self.buffer.len() < HEADER_BYTES {
            return Ok(());
        }

        if &self.buffer[..4] != MAGIC {
            return Err(CipherboxError::Crypto("bad magic".into()));
        }
        let version = self.buffer[4];
        if version != VERSION {
            return Err(CipherboxError::Crypto(format!(
                "unsupported version: 0x{version:02x}"
            )));
        }
        let chunk_size = u32::from_le_bytes([
            self.buffer[5],
            self.buffer[6],
            self.buffer[7],
            self.buffer[8],
        ]) as usize;
        validate_chunk_size(chunk_size)?;

        let kem_ct_offset = 9;
        let mut kem_ct = [0u8; kem::CT_BYTES];
        kem_ct.copy_from_slice(&self.buffer[kem_ct_offset..kem_ct_offset + kem::CT_BYTES]);

        let header_bytes: Vec<u8> = self.buffer[..HEADER_BYTES].to_vec();

        let shared_secret = kem::decaps(&self.dk, &kem_ct);
        let aead_key = derive_aead_key(&shared_secret, &header_bytes);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&aead_key));

        self.buffer.drain(..HEADER_BYTES);
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
            self.counter += 1;
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

// ==========================================
// One-shot convenience wrappers
// ==========================================

pub fn encrypt_file(
    plaintext: &[u8],
    recipient_ek: &[u8; kem::EK_BYTES],
    chunk_size: usize,
) -> Result<Vec<u8>, CipherboxError> {
    let mut enc = FileEncryptor::new(recipient_ek, chunk_size)?;
    let mut out = Vec::with_capacity(plaintext.len() + HEADER_BYTES + chunk_size);
    enc.update(plaintext, &mut out)?;
    enc.finish(&mut out)?;
    Ok(out)
}

pub fn decrypt_file(
    ciphertext: &[u8],
    recipient_dk: &[u8; kem::DK_BYTES],
) -> Result<Vec<u8>, CipherboxError> {
    let mut dec = FileDecryptor::new(recipient_dk);
    let mut out = Vec::new();
    dec.update(ciphertext, &mut out)?;
    dec.finish(&mut out)?;
    Ok(out)
}
