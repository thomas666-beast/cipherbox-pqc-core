//! Secret-derived rooms with per-sender symmetric ratchets.
//!
//! A *room* is identified and keyed purely by a shared secret that members
//! obtain out of band (a passphrase, the hash of a photo, a QR code ...).
//! The server never needs a member list, an invitation or any key:
//!
//! ```text
//! k_i      = Argon2id(source_i, salt = H(context, params))        one per source
//! root     = H("root", context, params, n, sort(k_1 .. k_n))      order of sources is irrelevant
//! room_id  = H("room-id", root)       routing key; permits offline guessing of weak roots
//! auth     = H("auth", root)          bearer token; server stores only H("auth-verify", auth)
//! epoch_0  = H("epoch0", root)
//! ```
//!
//! (`H` = domain-separated, length-prefixed SHA3-256; see [`kdf`].)
//!
//! ## Messages
//!
//! Every sender has a random 16-byte id and its own hash chain per epoch:
//!
//! ```text
//! chain_0    = H("chain0", epoch_key, sender_id, epoch)
//! msg_key_n  = H("msg-key", chain_n)     nonce_n = H("msg-nonce", chain_n)[..12]
//! chain_n+1  = H("chain-next", chain_n)
//! ```
//!
//! Chain keys advance after each message, but retained epoch keys can
//! regenerate every message key in their epoch.
//! The ratchet state only advances after a message authenticates, so garbage
//! cannot be used to burn keys. Plaintexts are padded to 256-byte blocks.
//!
//! ## What this does and does not give you
//!
//! * State compromise exposes all retained epochs. Retiring an epoch helps
//!   only if its key and any material that can reconstruct it are gone.
//! * Against leak of the **root secret** (a stolen passphrase): no. Anyone
//!   with the root and a recording of the traffic can derive epoch 0. That is
//!   inherent to secret-derived rooms. Use [`Room::rekey`] to inject fresh
//!   randomness wrapped to members' hybrid/ML-KEM keys. Recovery after a
//!   compromise requires any compromised recipient/signing keys to be
//!   rotated or excluded, and does not protect against a compromised endpoint.
//! * Sender authenticity: optional ML-DSA signatures on envelopes and on
//!   rekey bundles. Without signatures any holder of the root can impersonate
//!   any sender id.
//! * Strength of a room = entropy of its sources. One short passphrase makes a
//!   weak room.
//!
//! ## Envelope (version 1)
//!
//! ```text
//! "CBRM" | 0x01 | flags u8 | room_id 32 | epoch u32 LE | sender_id 16 | index u32 LE   (62 B header)
//! | ct_len u32 LE | ct (ChaCha20-Poly1305, AAD = header) | [flags&1: sig_len u16 LE | sig]
//! ```
//!
//! The signature (if any) covers `"cipherbox-room-v1/msg-sig" || header || ct_len || ct`.

use crate::keccak::sha3_256;
use crate::{CipherboxError, Decapsulator, Suite};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};

const BASE: &str = "cipherbox-room-v1/";

/// Maximum number of skipped (not yet received) messages tracked per chain.
pub const MAX_SKIP: u32 = 1000;
/// Maximum number of live receive chains (sender x epoch) per room.
pub const MAX_CHAINS: usize = 1024;
/// Maximum plaintext size of one room message. Use `file` for large data.
pub const MAX_MESSAGE_BYTES: usize = 1 << 20;
/// Plaintexts are padded to a multiple of this many bytes.
pub const PAD_BLOCK: usize = 256;

const MAGIC: &[u8; 4] = b"CBRM";
const VERSION: u8 = 1;
const FLAG_SIGNED: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 1 + 32 + 4 + 16 + 4; // 62
const MAX_SIG: usize = 8192;
const TAG: usize = 16;
const SIG_DOMAIN: &[u8] = b"cipherbox-room-v1/msg-sig";
const REKEY_DOMAIN: &[u8] = b"cipherbox-room-v1/rekey-sig";
const MAX_EPOCHS: usize = 4096;
const MAX_REKEY_MEMBERS: usize = 1024;
const STATE_MAGIC: &[u8; 5] = b"CBSX\x01";
const STATE_NONCE_LEN: usize = 24;
const MAX_STATE_BYTES: usize =
    97 + 4 + MAX_EPOCHS * 36 + MAX_CHAINS * (60 + MAX_SKIP as usize * 36);

fn err(msg: impl Into<String>) -> CipherboxError {
    CipherboxError::Crypto(msg.into())
}

/// Domain-separated, length-prefixed SHA3-256:
/// `H(u32le(len(label)) || label || (u32le(len(p)) || p)*)`, `label = BASE + suffix`.
pub fn kdf(suffix: &str, parts: &[&[u8]]) -> [u8; 32] {
    let label_len = BASE.len() + suffix.len();
    let mut input =
        Vec::with_capacity(4 + label_len + parts.iter().map(|p| 4 + p.len()).sum::<usize>());
    input.extend_from_slice(&(label_len as u32).to_le_bytes());
    input.extend_from_slice(BASE.as_bytes());
    input.extend_from_slice(suffix.as_bytes());
    for p in parts {
        input.extend_from_slice(&(p.len() as u32).to_le_bytes());
        input.extend_from_slice(p);
    }
    let out = sha3_256(&input);
    input.zeroize();
    out
}

fn fill_random(buf: &mut [u8]) -> Result<(), CipherboxError> {
    getrandom::getrandom(buf).map_err(|e| err(format!("RNG failure: {e}")))
}

// ============================================================================
// Room secret
// ============================================================================

/// Argon2id cost parameters used to stretch each source. They are part of the
/// derivation: members using different parameters end up in different rooms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RoomKdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl RoomKdfParams {
    /// 64 MiB, 3 passes, 1 lane. Use at least this in production.
    pub const DEFAULT: RoomKdfParams = RoomKdfParams {
        m_kib: 65536,
        t_cost: 3,
        p_cost: 1,
    };

    pub const fn new(m_kib: u32, t_cost: u32, p_cost: u32) -> Self {
        Self {
            m_kib,
            t_cost,
            p_cost,
        }
    }
}

impl Default for RoomKdfParams {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The root secret of a room. Zeroized on drop.
pub struct RoomSecret {
    root: [u8; 32],
}

impl Drop for RoomSecret {
    fn drop(&mut self) {
        self.root.zeroize();
    }
}

impl RoomSecret {
    /// Generate a high-entropy room root. Share it only over an authenticated,
    /// confidential channel; anyone who learns it can derive the epoch-0 key.
    pub fn generate() -> Result<Self, CipherboxError> {
        let mut root = Zeroizing::new([0u8; 32]);
        fill_random(&mut root[..])?;
        Ok(Self::from_root(*root))
    }

    /// Derive a room secret from 1..=16 non-empty sources. The order of
    /// `sources` does not matter. `context` (for example a server name or
    /// room label) separates unrelated rooms that share sources.
    pub fn derive(
        context: &str,
        sources: &[&[u8]],
        params: RoomKdfParams,
    ) -> Result<Self, CipherboxError> {
        if sources.is_empty() || sources.len() > 16 {
            return Err(err("a room needs between 1 and 16 sources"));
        }
        if sources.iter().any(|s| s.is_empty()) {
            return Err(err("room sources must not be empty"));
        }
        if params.m_kib > 512 * 1024
            || !(1..=16).contains(&params.t_cost)
            || !(1..=16).contains(&params.p_cost)
        {
            return Err(err("Argon2 parameters outside the supported range"));
        }

        let ctx = context.as_bytes();
        let (m_b, t_b, p_b) = (
            params.m_kib.to_le_bytes(),
            params.t_cost.to_le_bytes(),
            params.p_cost.to_le_bytes(),
        );
        let salt_full = kdf("salt", &[ctx, &m_b, &t_b, &p_b]);
        let salt = &salt_full[..16];

        let a2_params = Params::new(params.m_kib, params.t_cost, params.p_cost, Some(32))
            .map_err(|e| err(format!("Argon2 params: {e:?}")))?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, a2_params);

        let mut stretched: Vec<[u8; 32]> = Vec::with_capacity(sources.len());
        for s in sources {
            let mut k = [0u8; 32];
            if let Err(e) = argon2.hash_password_into(s, salt, &mut k) {
                for x in stretched.iter_mut() {
                    x.zeroize();
                }
                return Err(err(format!("Argon2: {e:?}")));
            }
            stretched.push(k);
        }
        stretched.sort(); // order-independent
        let n_b = (sources.len() as u32).to_le_bytes();

        let mut parts: Vec<&[u8]> = vec![ctx, &m_b, &t_b, &p_b, &n_b];
        for k in stretched.iter() {
            parts.push(k.as_slice());
        }
        let root = kdf("root", &parts);
        for x in stretched.iter_mut() {
            x.zeroize();
        }
        Ok(Self { root })
    }

    /// Rebuild from a previously stored root (see [`RoomSecret::root_bytes`]).
    pub fn from_root(root: [u8; 32]) -> Self {
        Self { root }
    }

    /// The 32-byte root. Store it only encrypted (e.g. `encrypt_private_key`).
    pub fn root_bytes(&self) -> &[u8; 32] {
        &self.root
    }

    /// Routing key for the server. Reveals nothing about the root.
    pub fn room_id(&self) -> [u8; 32] {
        kdf("room-id", &[&self.root])
    }

    /// Bearer token proving knowledge of the secret. Give the server only
    /// [`auth_verifier`] of it.
    pub fn auth_token(&self) -> [u8; 32] {
        kdf("auth", &[&self.root])
    }

    /// Key for epoch 0.
    pub fn epoch0_key(&self) -> [u8; 32] {
        kdf("epoch0", &[&self.root])
    }
}

/// What the server stores to check an `auth_token` without learning it.
pub fn auth_verifier(auth_token: &[u8; 32]) -> [u8; 32] {
    kdf("auth-verify", &[auth_token])
}

/// Fingerprint of a public key, used to address rekey entries.
pub fn public_key_fingerprint(public_key: &[u8]) -> [u8; 32] {
    kdf("pk-fp", &[public_key])
}

/// Epoch key after a rekey: `H("epoch-next", old_key, seed, new_epoch)`.
pub fn next_epoch_key(old: &[u8; 32], seed: &[u8; 32], new_epoch: u32) -> [u8; 32] {
    kdf("epoch-next", &[old, seed, &new_epoch.to_le_bytes()])
}

fn chain0(epoch_key: &[u8; 32], sender: &[u8; 16], epoch: u32) -> [u8; 32] {
    kdf("chain0", &[epoch_key, sender, &epoch.to_le_bytes()])
}

fn chain_next(ck: &[u8; 32]) -> [u8; 32] {
    kdf("chain-next", &[ck])
}

fn message_keys(ck: &[u8; 32]) -> ([u8; 32], [u8; 12]) {
    let key = kdf("msg-key", &[ck]);
    let mut nonce_full = kdf("msg-nonce", &[ck]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&nonce_full[..12]);
    nonce_full.zeroize();
    (key, nonce)
}

// ============================================================================
// Envelope parsing
// ============================================================================

struct Parsed<'a> {
    room_id: [u8; 32],
    epoch: u32,
    sender: [u8; 16],
    index: u32,
    header: &'a [u8],
    ct: &'a [u8],
    /// `header || ct_len || ct`: what the signature covers (after the domain).
    signing_bytes: &'a [u8],
    sig: Option<&'a [u8]>,
}

fn u32_at(b: &[u8], pos: usize) -> u32 {
    u32::from_le_bytes([b[pos], b[pos + 1], b[pos + 2], b[pos + 3]])
}

fn parse(bytes: &[u8]) -> Result<Parsed<'_>, CipherboxError> {
    if bytes.len() < HEADER_LEN + 4 {
        return Err(err("envelope too short"));
    }
    if &bytes[..4] != MAGIC {
        return Err(err("bad envelope magic"));
    }
    if bytes[4] != VERSION {
        return Err(err(format!("unsupported envelope version {}", bytes[4])));
    }
    let flags = bytes[5];
    if flags & !FLAG_SIGNED != 0 {
        return Err(err("unknown envelope flags"));
    }
    let mut room_id = [0u8; 32];
    room_id.copy_from_slice(&bytes[6..38]);
    let epoch = u32_at(bytes, 38);
    let mut sender = [0u8; 16];
    sender.copy_from_slice(&bytes[42..58]);
    let index = u32_at(bytes, 58);

    let ct_len = u32_at(bytes, HEADER_LEN) as usize;
    if !(PAD_BLOCK + TAG..=MAX_MESSAGE_BYTES + PAD_BLOCK + 4 + TAG).contains(&ct_len) {
        return Err(err("invalid ciphertext length"));
    }
    let ct_start = HEADER_LEN + 4;
    let ct_end = ct_start
        .checked_add(ct_len)
        .ok_or_else(|| err("invalid ciphertext length"))?;
    if bytes.len() < ct_end {
        return Err(err("envelope truncated"));
    }

    let sig = if flags & FLAG_SIGNED != 0 {
        if bytes.len() < ct_end + 2 {
            return Err(err("envelope truncated (signature length)"));
        }
        let sig_len = u16::from_le_bytes([bytes[ct_end], bytes[ct_end + 1]]) as usize;
        if sig_len == 0 || sig_len > MAX_SIG || bytes.len() != ct_end + 2 + sig_len {
            return Err(err("invalid signature length"));
        }
        Some(&bytes[ct_end + 2..])
    } else {
        if bytes.len() != ct_end {
            return Err(err("trailing bytes after envelope"));
        }
        None
    };

    Ok(Parsed {
        room_id,
        epoch,
        sender,
        index,
        header: &bytes[..HEADER_LEN],
        ct: &bytes[ct_start..ct_end],
        signing_bytes: &bytes[..ct_end],
        sig,
    })
}

fn signing_input(signing_bytes: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(SIG_DOMAIN.len() + signing_bytes.len());
    v.extend_from_slice(SIG_DOMAIN);
    v.extend_from_slice(signing_bytes);
    v
}

fn pad(data: &[u8]) -> Vec<u8> {
    let body = 4 + data.len();
    let total = body.div_ceil(PAD_BLOCK) * PAD_BLOCK;
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(&(data.len() as u32).to_le_bytes());
    out.extend_from_slice(data);
    out.resize(total, 0);
    out
}

fn unpad(padded: &[u8]) -> Result<Vec<u8>, CipherboxError> {
    if padded.len() < 4 || padded.len() % PAD_BLOCK != 0 {
        return Err(err("bad padding"));
    }
    let len = u32_at(padded, 0) as usize;
    if len > padded.len() - 4 || padded.len() - (4 + len) >= PAD_BLOCK {
        return Err(err("bad padding"));
    }
    if padded[4 + len..].iter().any(|&b| b != 0) {
        return Err(err("bad padding"));
    }
    Ok(padded[4..4 + len].to_vec())
}

// ============================================================================
// Receive chain
// ============================================================================

#[derive(Clone)]
struct RecvChain {
    next: u32,
    key: [u8; 32],
    /// index -> chain key at that index, for messages skipped over.
    skipped: BTreeMap<u32, [u8; 32]>,
}

impl Drop for RecvChain {
    fn drop(&mut self) {
        self.key.zeroize();
        for v in self.skipped.values_mut() {
            v.zeroize();
        }
    }
}

impl RecvChain {
    fn new(key: [u8; 32]) -> Self {
        Self {
            next: 0,
            key,
            skipped: BTreeMap::new(),
        }
    }

    /// Chain key for message `index`; advances/records this (cloned) chain.
    fn take(&mut self, index: u32) -> Result<[u8; 32], CipherboxError> {
        if index < self.next {
            return self
                .skipped
                .remove(&index)
                .ok_or_else(|| err("message already received or too old"));
        }
        let gap = index - self.next;
        if gap > MAX_SKIP || self.skipped.len() + gap as usize > MAX_SKIP as usize {
            return Err(err("too many skipped messages"));
        }
        let new_next = index
            .checked_add(1)
            .ok_or_else(|| err("message index exhausted"))?;
        while self.next < index {
            self.skipped.insert(self.next, self.key);
            self.key = chain_next(&self.key);
            self.next += 1;
        }
        let ck = self.key;
        self.key = chain_next(&ck);
        self.next = new_next;
        Ok(ck)
    }
}

// ============================================================================
// Rekey bundle
// ============================================================================

/// One member's copy of the fresh epoch seed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RekeyEntry {
    /// [`public_key_fingerprint`] of the recipient's public key.
    pub recipient_fingerprint: [u8; 32],
    /// `wrap_key(recipient_public_key, seed)` blob.
    pub wrapped: Vec<u8>,
}

/// A signed announcement of a new epoch, safe to relay through the server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RekeyBundle {
    pub room_id: [u8; 32],
    pub epoch: u32,
    pub entries: Vec<RekeyEntry>,
    pub signature: Vec<u8>,
}

impl RekeyBundle {
    fn check_shape(&self) -> Result<(), CipherboxError> {
        if self.entries.is_empty() || self.entries.len() > MAX_REKEY_MEMBERS {
            return Err(err("invalid rekey entry count"));
        }
        if self.signature.is_empty() || self.signature.len() > MAX_SIG {
            return Err(err("invalid rekey signature length"));
        }
        let mut recipients = BTreeSet::new();
        for entry in &self.entries {
            if !recipients.insert(entry.recipient_fingerprint) {
                return Err(err("duplicate rekey recipient"));
            }
            if !valid_wrapped_seed_len(entry.wrapped.len())
                || !entry.wrapped.starts_with(crate::WRAP_MAGIC)
                || entry.wrapped[4] != crate::WRAP_VERSION
            {
                return Err(err("invalid wrapped rekey seed"));
            }
        }
        Ok(())
    }

    /// The exact bytes that must be signed / verified.
    pub fn signing_input(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(REKEY_DOMAIN);
        v.extend_from_slice(&self.room_id);
        v.extend_from_slice(&self.epoch.to_le_bytes());
        v.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for e in &self.entries {
            v.extend_from_slice(&e.recipient_fingerprint);
            v.extend_from_slice(&(e.wrapped.len() as u32).to_le_bytes());
            v.extend_from_slice(&e.wrapped);
        }
        v
    }

    /// `"CBRK" | 0x01 | room_id | epoch | n | (fp | len | wrapped)* | sig_len u16 | sig`
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"CBRK");
        v.push(1);
        v.extend_from_slice(&self.room_id);
        v.extend_from_slice(&self.epoch.to_le_bytes());
        v.extend_from_slice(&(self.entries.len() as u32).to_le_bytes());
        for e in &self.entries {
            v.extend_from_slice(&e.recipient_fingerprint);
            v.extend_from_slice(&(e.wrapped.len() as u32).to_le_bytes());
            v.extend_from_slice(&e.wrapped);
        }
        v.extend_from_slice(&(self.signature.len() as u16).to_le_bytes());
        v.extend_from_slice(&self.signature);
        v
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CipherboxError> {
        let mut r = Reader::new(bytes);
        if r.take(4)? != b"CBRK" {
            return Err(err("bad rekey bundle magic"));
        }
        if r.u8()? != 1 {
            return Err(err("unsupported rekey bundle version"));
        }
        let room_id = r.arr32()?;
        let epoch = r.u32()?;
        let n = r.u32()? as usize;
        if !(1..=MAX_REKEY_MEMBERS).contains(&n) {
            return Err(err("invalid rekey entry count"));
        }
        let mut entries = Vec::with_capacity(n);
        for _ in 0..n {
            let recipient_fingerprint = r.arr32()?;
            let len = r.u32()? as usize;
            if !valid_wrapped_seed_len(len) {
                return Err(err("invalid wrapped rekey seed length"));
            }
            entries.push(RekeyEntry {
                recipient_fingerprint,
                wrapped: r.take(len)?.to_vec(),
            });
        }
        let sig_len = r.u16()? as usize;
        if !(1..=MAX_SIG).contains(&sig_len) {
            return Err(err("invalid rekey signature length"));
        }
        let signature = r.take(sig_len)?.to_vec();
        r.finish()?;
        let bundle = Self {
            room_id,
            epoch,
            entries,
            signature,
        };
        bundle.check_shape()?;
        Ok(bundle)
    }
}

fn valid_wrapped_seed_len(len: usize) -> bool {
    Suite::ALL
        .into_iter()
        .any(|suite| len == wrapped_seed_len(suite))
}

fn wrapped_seed_len(suite: Suite) -> usize {
    crate::WRAP_HEADER_BYTES + suite.ct_bytes() + 12 + 32 + TAG
}

// ============================================================================
// Byte reader for state / bundle parsing
// ============================================================================

struct Reader<'a> {
    b: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], CipherboxError> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or_else(|| err("truncated data"))?;
        if end > self.b.len() {
            return Err(err("truncated data"));
        }
        let s = &self.b[self.pos..end];
        self.pos = end;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, CipherboxError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, CipherboxError> {
        let s = self.take(2)?;
        Ok(u16::from_le_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32, CipherboxError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn arr32(&mut self) -> Result<[u8; 32], CipherboxError> {
        let mut a = [0u8; 32];
        a.copy_from_slice(self.take(32)?);
        Ok(a)
    }
    fn arr16(&mut self) -> Result<[u8; 16], CipherboxError> {
        let mut a = [0u8; 16];
        a.copy_from_slice(self.take(16)?);
        Ok(a)
    }
    fn finish(&self) -> Result<(), CipherboxError> {
        if self.pos != self.b.len() {
            return Err(err("trailing bytes"));
        }
        Ok(())
    }
}

// ============================================================================
// Room
// ============================================================================

/// Result of opening a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opened {
    pub plaintext: Vec<u8>,
    pub sender_id: [u8; 16],
    pub epoch: u32,
    pub index: u32,
    /// Whether the envelope carried a signature (it was verified only if a
    /// verifier was passed to [`Room::open`]).
    pub signed: bool,
    /// True only when the supplied signature verifier accepted the envelope.
    /// Trust in the verifying key is the caller's responsibility.
    pub signature_verified: bool,
}

/// One member's view of a room: epoch keys plus sending and receiving
/// ratchet state. Treat the state as secret.
pub struct Room {
    room_id: [u8; 32],
    sender_id: [u8; 16],
    current_epoch: u32,
    epoch_keys: BTreeMap<u32, [u8; 32]>,
    send_index: u32,
    send_key: [u8; 32],
    recv: BTreeMap<(u32, [u8; 16]), RecvChain>,
}

impl Drop for Room {
    fn drop(&mut self) {
        self.send_key.zeroize();
        for k in self.epoch_keys.values_mut() {
            k.zeroize();
        }
    }
}

type Signer<'a> = &'a dyn Fn(&[u8]) -> Vec<u8>;
type Verifier<'a> = &'a dyn Fn(&[u8], &[u8]) -> bool;

impl Room {
    /// Join with a fresh random sender id, starting at epoch 0.
    pub fn join(secret: &RoomSecret) -> Result<Self, CipherboxError> {
        let mut sender = [0u8; 16];
        fill_random(&mut sender)?;
        Ok(Self::join_with_sender_id(secret, sender))
    }

    /// Advanced: the caller must never reuse a sender id under the same
    /// epoch key. Prefer [`Self::join`] for normal operation.
    pub fn join_with_sender_id(secret: &RoomSecret, sender_id: [u8; 16]) -> Self {
        let mut k = secret.epoch0_key();
        let room = Self::from_keys(secret.room_id(), 0, k, sender_id);
        k.zeroize();
        room
    }

    /// Advanced / interoperability: build a room from raw values, starting at
    /// `epoch` with the given epoch key. Never reuse an (epoch key, epoch,
    /// sender id) tuple for sending.
    pub fn from_keys(
        room_id: [u8; 32],
        epoch: u32,
        epoch_key: [u8; 32],
        sender_id: [u8; 16],
    ) -> Self {
        let mut epoch_keys = BTreeMap::new();
        epoch_keys.insert(epoch, epoch_key);
        Self {
            room_id,
            sender_id,
            current_epoch: epoch,
            epoch_keys,
            send_index: 0,
            send_key: chain0(&epoch_key, &sender_id, epoch),
            recv: BTreeMap::new(),
        }
    }

    pub fn room_id(&self) -> &[u8; 32] {
        &self.room_id
    }
    pub fn sender_id(&self) -> &[u8; 16] {
        &self.sender_id
    }
    pub fn epoch(&self) -> u32 {
        self.current_epoch
    }

    // ---------------- sending ----------------

    /// Encrypt a message for the room (unsigned).
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, CipherboxError> {
        self.seal_inner(plaintext, None)
    }

    /// Encrypt and sign. `signer` receives the exact bytes to sign (domain
    /// prefix included) and returns the signature, e.g.
    /// `|m| ml_dsa_keypair.sign(m)`.
    pub fn seal_signed(
        &mut self,
        plaintext: &[u8],
        signer: Signer<'_>,
    ) -> Result<Vec<u8>, CipherboxError> {
        self.seal_inner(plaintext, Some(signer))
    }

    fn seal_inner(
        &mut self,
        plaintext: &[u8],
        signer: Option<Signer<'_>>,
    ) -> Result<Vec<u8>, CipherboxError> {
        if plaintext.len() > MAX_MESSAGE_BYTES {
            return Err(err("message too large for a room message"));
        }
        if self.send_index == u32::MAX {
            return Err(err("sending chain exhausted: rekey the room"));
        }
        let index = self.send_index;
        let mut ck = self.send_key;
        let (mut mk, nonce) = message_keys(&ck);

        let mut header = Vec::with_capacity(HEADER_LEN);
        header.extend_from_slice(MAGIC);
        header.push(VERSION);
        header.push(if signer.is_some() { FLAG_SIGNED } else { 0 });
        header.extend_from_slice(&self.room_id);
        header.extend_from_slice(&self.current_epoch.to_le_bytes());
        header.extend_from_slice(&self.sender_id);
        header.extend_from_slice(&index.to_le_bytes());
        debug_assert_eq!(header.len(), HEADER_LEN);

        let mut padded = pad(plaintext);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&mk));
        let ct = cipher.encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &padded,
                aad: &header,
            },
        );
        padded.zeroize();
        mk.zeroize();
        let ct = match ct {
            Ok(c) => c,
            Err(e) => {
                ck.zeroize();
                return Err(err(format!("encrypt: {e:?}")));
            }
        };

        // Advance the ratchet and drop the used chain key.
        self.send_key = chain_next(&ck);
        self.send_index = index + 1;
        ck.zeroize();

        let mut out = header;
        out.extend_from_slice(&(ct.len() as u32).to_le_bytes());
        out.extend_from_slice(&ct);

        if let Some(sign) = signer {
            let sig = sign(&signing_input(&out));
            if sig.is_empty() || sig.len() > MAX_SIG {
                return Err(err("signer returned an invalid signature"));
            }
            out.extend_from_slice(&(sig.len() as u16).to_le_bytes());
            out.extend_from_slice(&sig);
        }
        Ok(out)
    }

    // ---------------- receiving ----------------

    /// Decrypt an envelope. If `verify` is given, the envelope must be signed
    /// and `verify(signing_input, signature)` must return true; this is
    /// checked before any ratchet state is touched. State advances only after
    /// the message authenticates.
    pub fn open(
        &mut self,
        envelope: &[u8],
        verify: Option<Verifier<'_>>,
    ) -> Result<Opened, CipherboxError> {
        self.open_parsed(parse(envelope)?, verify)
    }

    /// Require both the expected sender id and its pinned ML-DSA-65/87 key.
    /// Obtain this binding from a trusted roster, not the relay or envelope.
    /// Do not fall back to [`Self::open`] without verification after failure.
    pub fn open_from(
        &mut self,
        envelope: &[u8],
        sender_id: &[u8; 16],
        verifying_key: &[u8],
    ) -> Result<Opened, CipherboxError> {
        let p = parse(envelope)?;
        if &p.sender != sender_id {
            return Err(err("unexpected sender id"));
        }
        self.open_parsed(
            p,
            Some(&|msg, sig| crate::ml_dsa_verify(verifying_key, msg, sig)),
        )
    }

    fn open_parsed(
        &mut self,
        p: Parsed<'_>,
        verify: Option<Verifier<'_>>,
    ) -> Result<Opened, CipherboxError> {
        if p.room_id != self.room_id {
            return Err(err("envelope belongs to a different room"));
        }
        if p.sender == self.sender_id {
            return Err(err("envelope was sent by this member"));
        }
        let signed = p.sig.is_some();
        if let Some(v) = verify {
            let sig = p.sig.ok_or_else(|| err("message is not signed"))?;
            if !v(&signing_input(p.signing_bytes), sig) {
                return Err(err("signature verification failed"));
            }
        }

        let epoch_key = *self.epoch_keys.get(&p.epoch).ok_or_else(|| {
            err(format!(
                "no key for epoch {} (unknown or forgotten)",
                p.epoch
            ))
        })?;

        let chain_id = (p.epoch, p.sender);
        let mut chain = match self.recv.get(&chain_id) {
            Some(c) => c.clone(),
            None => {
                if self.recv.len() >= MAX_CHAINS {
                    return Err(err("too many sender chains"));
                }
                RecvChain::new(chain0(&epoch_key, &p.sender, p.epoch))
            }
        };

        let mut ck = chain.take(p.index)?;
        let (mut mk, nonce) = message_keys(&ck);
        ck.zeroize();
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&mk));
        let dec = cipher.decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: p.ct,
                aad: p.header,
            },
        );
        mk.zeroize();
        let mut padded = dec.map_err(|_| err("message failed to authenticate"))?;
        let plaintext = unpad(&padded);
        padded.zeroize();
        let plaintext = plaintext?;

        // Commit only after successful authentication.
        self.recv.insert(chain_id, chain);
        Ok(Opened {
            plaintext,
            sender_id: p.sender,
            epoch: p.epoch,
            index: p.index,
            signed,
            signature_verified: verify.is_some(),
        })
    }

    // ---------------- epochs ----------------

    /// Start a new epoch with fresh randomness that is **not derivable from
    /// the room secret**: a random seed wrapped to each member's public key
    /// (plain ML-KEM or hybrid). `signer` signs the bundle (see
    /// [`RekeyBundle::signing_input`]); receivers verify it, which is what
    /// stops someone who merely knows the room secret from hijacking the room.
    ///
    /// Do not include your own key. After this call, `seal` uses the new epoch.
    /// Deliver bundles to members in order; concurrent rekeys must be
    /// serialized by whoever relays them (first wins).
    pub fn rekey(
        &mut self,
        member_public_keys: &[&[u8]],
        signer: Signer<'_>,
    ) -> Result<RekeyBundle, CipherboxError> {
        if member_public_keys.is_empty() || member_public_keys.len() > MAX_REKEY_MEMBERS {
            return Err(err("rekey needs between 1 and 1024 member keys"));
        }
        let new_epoch = self
            .current_epoch
            .checked_add(1)
            .ok_or_else(|| err("epoch counter exhausted"))?;
        if self.epoch_keys.len() >= MAX_EPOCHS {
            return Err(err("too many epochs retained: call forget_epochs_before"));
        }

        // Wrap first so a bad member key leaves the room state untouched.
        let mut seed = Zeroizing::new([0u8; 32]);
        fill_random(&mut seed[..])?;
        let mut entries = Vec::with_capacity(member_public_keys.len());
        let mut recipients = BTreeSet::new();
        for pk in member_public_keys {
            let fingerprint = public_key_fingerprint(pk);
            if !recipients.insert(fingerprint) {
                return Err(err("duplicate rekey recipient"));
            }
            entries.push(RekeyEntry {
                recipient_fingerprint: fingerprint,
                wrapped: crate::wrap_key(pk, &seed[..])?,
            });
        }

        let mut bundle = RekeyBundle {
            room_id: self.room_id,
            epoch: new_epoch,
            entries,
            signature: Vec::new(),
        };
        let sig = signer(&bundle.signing_input());
        if sig.is_empty() || sig.len() > MAX_SIG {
            return Err(err("signer returned an invalid signature"));
        }
        bundle.signature = sig;

        let new_key = next_epoch_key(&self.epoch_keys[&self.current_epoch], &seed, new_epoch);
        self.install_epoch(new_epoch, new_key);
        Ok(bundle)
    }

    /// Apply a rekey bundle announced by another member. `verify` must check
    /// `signature` over `bundle.signing_input()` against an authorized rekey
    /// signer. It is called before decapsulation or any state change. The bundle's epoch must be
    /// exactly one more than the newest epoch you know.
    pub fn apply_rekey<K: Decapsulator + ?Sized>(
        &mut self,
        bundle: &RekeyBundle,
        my_key: &K,
        verify: Verifier<'_>,
    ) -> Result<(), CipherboxError> {
        if bundle.room_id != self.room_id {
            return Err(err("rekey bundle belongs to a different room"));
        }
        let latest = self.current_epoch;
        if latest.checked_add(1) != Some(bundle.epoch) {
            return Err(err(format!(
                "rekey epoch {} is not the next epoch after {latest}",
                bundle.epoch
            )));
        }
        if self.epoch_keys.len() >= MAX_EPOCHS {
            return Err(err("too many epochs retained: call forget_epochs_before"));
        }
        bundle.check_shape()?;
        let fp = public_key_fingerprint(my_key.public_key_bytes());
        let entry = bundle
            .entries
            .iter()
            .find(|e| e.recipient_fingerprint == fp)
            .ok_or_else(|| err("rekey bundle has no entry for this key"))?;
        if entry.wrapped.len() != wrapped_seed_len(my_key.suite()) {
            return Err(err("wrapped rekey seed does not match recipient suite"));
        }
        if !verify(&bundle.signing_input(), &bundle.signature) {
            return Err(err("rekey signature verification failed"));
        }

        let seed_v = Zeroizing::new(crate::unwrap_key(my_key, &entry.wrapped)?);
        let seed: &[u8; 32] = seed_v
            .as_slice()
            .try_into()
            .map_err(|_| err("rekey seed has the wrong length"))?;
        let new_key = next_epoch_key(&self.epoch_keys[&latest], seed, bundle.epoch);
        self.install_epoch(bundle.epoch, new_key);
        Ok(())
    }

    fn install_epoch(&mut self, epoch: u32, mut key: [u8; 32]) {
        self.epoch_keys.insert(epoch, key);
        self.current_epoch = epoch;
        self.send_key = chain0(&key, &self.sender_id, epoch);
        self.send_index = 0;
        key.zeroize();
    }

    /// Delete keys and chains of epochs older than `epoch` (never the current
    /// one). This instance can no longer decrypt those epochs. Retaining the
    /// root, old snapshots, or recoverable rekey material can defeat erasure.
    pub fn forget_epochs_before(&mut self, epoch: u32) {
        let keep_from = epoch.min(self.current_epoch);
        let old: Vec<u32> = self
            .epoch_keys
            .keys()
            .copied()
            .filter(|e| *e < keep_from)
            .collect();
        for e in old {
            if let Some(mut k) = self.epoch_keys.remove(&e) {
                k.zeroize();
            }
        }
        self.recv.retain(|(e, _), _| *e >= keep_from);
    }

    // ---------------- persistence ----------------

    /// Encrypt the ratchet snapshot with a separately stored, random 32-byte
    /// device storage key. The snapshot is authenticated to this room id.
    pub fn export_encrypted_state(&self, device_key: &[u8; 32]) -> Result<Vec<u8>, CipherboxError> {
        let mut nonce = [0u8; STATE_NONCE_LEN];
        fill_random(&mut nonce)?;
        let state = Zeroizing::new(self.export_state());
        let cipher = XChaCha20Poly1305::new(Key::from_slice(device_key));
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &state,
                    aad: &state_aad(&self.room_id),
                },
            )
            .map_err(|_| err("could not encrypt room state"))?;
        let mut out = Vec::with_capacity(STATE_MAGIC.len() + nonce.len() + ct.len());
        out.extend_from_slice(STATE_MAGIC);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Restore authenticated state and rotate to a fresh sending id, so
    /// restoring the same snapshot repeatedly cannot restart the old send
    /// chain. Authenticate the new sender binding before sending to peers.
    /// The caller must also prevent storage rollback to protect replay history
    /// and reject snapshots from an obsolete epoch.
    pub fn restore_encrypted_state(
        bytes: &[u8],
        device_key: &[u8; 32],
        expected_room_id: &[u8; 32],
        minimum_epoch: u32,
    ) -> Result<Self, CipherboxError> {
        let header_len = STATE_MAGIC.len() + STATE_NONCE_LEN;
        if bytes.len() < header_len + TAG
            || bytes.len() > header_len + TAG + MAX_STATE_BYTES
            || !bytes.starts_with(STATE_MAGIC)
        {
            return Err(err("invalid encrypted room state framing"));
        }
        let cipher = XChaCha20Poly1305::new(Key::from_slice(device_key));
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&bytes[STATE_MAGIC.len()..header_len]),
                    Payload {
                        msg: &bytes[header_len..],
                        aad: &state_aad(expected_room_id),
                    },
                )
                .map_err(|_| err("room state failed to authenticate"))?,
        );
        let mut state = Self::import_state(&plain)?;
        if &state.room_id != expected_room_id || state.current_epoch < minimum_epoch {
            return Err(err("room state does not match the trusted room or epoch"));
        }
        let mut sender_id = [0u8; 16];
        loop {
            fill_random(&mut sender_id)?;
            if sender_id != state.sender_id
                && !state.recv.contains_key(&(state.current_epoch, sender_id))
            {
                break;
            }
        }
        state.sender_id = sender_id;
        state.send_index = 0;
        state.send_key = chain0(
            &state.epoch_keys[&state.current_epoch],
            &sender_id,
            state.current_epoch,
        );
        Ok(state)
    }

    /// Legacy raw secret snapshot. Prefer [`Self::export_encrypted_state`].
    /// This byte string must never be stored or transmitted in plaintext.
    pub fn export_state(&self) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(b"CBRS");
        v.push(1);
        v.extend_from_slice(&self.room_id);
        v.extend_from_slice(&self.sender_id);
        v.extend_from_slice(&self.current_epoch.to_le_bytes());
        v.extend_from_slice(&self.send_index.to_le_bytes());
        v.extend_from_slice(&self.send_key);
        v.extend_from_slice(&(self.epoch_keys.len() as u32).to_le_bytes());
        for (e, k) in &self.epoch_keys {
            v.extend_from_slice(&e.to_le_bytes());
            v.extend_from_slice(k);
        }
        v.extend_from_slice(&(self.recv.len() as u32).to_le_bytes());
        for ((e, sender), c) in &self.recv {
            v.extend_from_slice(&e.to_le_bytes());
            v.extend_from_slice(sender);
            v.extend_from_slice(&c.next.to_le_bytes());
            v.extend_from_slice(&c.key);
            v.extend_from_slice(&(c.skipped.len() as u32).to_le_bytes());
            for (i, k) in &c.skipped {
                v.extend_from_slice(&i.to_le_bytes());
                v.extend_from_slice(k);
            }
        }
        v
    }

    /// Legacy API for trusted, authenticated current snapshots only. Resuming
    /// a stale or concurrently used snapshot can reuse message keys/nonces.
    /// Prefer [`Self::restore_encrypted_state`].
    pub fn import_state(bytes: &[u8]) -> Result<Self, CipherboxError> {
        if bytes.len() > MAX_STATE_BYTES {
            return Err(err("room state too large"));
        }
        let mut r = Reader::new(bytes);
        if r.take(4)? != b"CBRS" {
            return Err(err("bad room state magic"));
        }
        if r.u8()? != 1 {
            return Err(err("unsupported room state version"));
        }
        let room_id = r.arr32()?;
        let sender_id = r.arr16()?;
        let current_epoch = r.u32()?;
        let send_index = r.u32()?;
        let send_key = Zeroizing::new(r.arr32()?);

        let n_epochs = r.u32()? as usize;
        if n_epochs == 0 || n_epochs > MAX_EPOCHS {
            return Err(err("invalid epoch count"));
        }
        let mut room = Self {
            room_id,
            sender_id,
            current_epoch,
            epoch_keys: BTreeMap::new(),
            send_index,
            send_key: *send_key,
            recv: BTreeMap::new(),
        };
        for _ in 0..n_epochs {
            let e = r.u32()?;
            if e > current_epoch || room.epoch_keys.contains_key(&e) {
                return Err(err("invalid or duplicate epoch in state"));
            }
            room.epoch_keys.insert(e, r.arr32()?);
        }
        if !room.epoch_keys.contains_key(&current_epoch) {
            return Err(err("current epoch key missing from state"));
        }

        let n_chains = r.u32()? as usize;
        if n_chains > MAX_CHAINS {
            return Err(err("too many chains in state"));
        }
        for _ in 0..n_chains {
            let e = r.u32()?;
            let sender = r.arr16()?;
            if sender == sender_id
                || !room.epoch_keys.contains_key(&e)
                || room.recv.contains_key(&(e, sender))
            {
                return Err(err("invalid or duplicate receive chain in state"));
            }
            let next = r.u32()?;
            let mut chain = RecvChain {
                next,
                key: r.arr32()?,
                skipped: BTreeMap::new(),
            };
            let n_skipped = r.u32()? as usize;
            if n_skipped > MAX_SKIP as usize {
                return Err(err("too many skipped keys in state"));
            }
            for _ in 0..n_skipped {
                let i = r.u32()?;
                if i >= next || chain.skipped.contains_key(&i) {
                    return Err(err("invalid or duplicate skipped key index"));
                }
                chain.skipped.insert(i, r.arr32()?);
            }
            room.recv.insert((e, sender), chain);
        }
        r.finish()?;

        Ok(room)
    }
}

fn state_aad(room_id: &[u8; 32]) -> [u8; 37] {
    let mut aad = [0u8; 37];
    aad[..STATE_MAGIC.len()].copy_from_slice(STATE_MAGIC);
    aad[STATE_MAGIC.len()..].copy_from_slice(room_id);
    aad
}
