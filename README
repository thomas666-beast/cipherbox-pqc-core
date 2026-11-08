================================================================================
                            CIPHERBOX PQC
================================================================================

           From-scratch ML-KEM-768 for servers, with streaming
                    large-file encryption and CLI tools.

                    Version 0.3.0  |  MIT License

================================================================================
  TABLE OF CONTENTS
================================================================================

  1.  What This Project Is
  2.  What This Project Is Not
  3.  The From-Scratch ML-KEM
  4.  Why "From Scratch" Matters
  5.  ACVP Validation
  6.  The Chunked File Format
  7.  CLI Tools
  8.  Library Usage
  9.  Testing and Fuzzing
 10.  Security Model and Honest Limitations
 11.  Relationship to Other PQC Projects
 12.  Building
 13.  License


================================================================================
  1.  WHAT THIS PROJECT IS
================================================================================

Cipherbox PQC is a Rust workspace with three crates:

  cipherbox-pqc-core
      A from-scratch implementation of ML-KEM-768 (FIPS 203),
      including Keccak-f[1600], the field arithmetic mod 3329, the
      NTT, CBD sampling, byte encoding, the IND-CPA PKE, and the
      Fujisaki-Okamoto IND-CCA transform. It also provides a
      streaming, chunked file-encryption format built on top of
      the KEM.

  cipherbox-pqc-native
      A thin re-export of the core crate plus five CLI binaries:
      keygen, file-encrypt, file-decrypt, verify (ML-DSA), and
      wrap (room-key wrapping).

  cipherbox-pqc-wasm
      WebAssembly bindings for the same core crate, so browser
      applications use the exact same ML-KEM implementation as
      server binaries.

The single sentence that describes the project:

  A transparent, ACVP-validated, from-scratch ML-KEM-768
  implementation for Rust, with a fully specified streaming file
  format and ready-to-use CLI tools.

If you want to know precisely what code is doing cryptography, read
cipherbox-pqc-core/src/. Everything is there. There is no hidden
layer, no proprietary entropy source, no undocumented exchange.


================================================================================
  2.  WHAT THIS PROJECT IS NOT
================================================================================

This is not a chat application, a VPN, a messaging product, or a
collaboration platform. It does not implement a network protocol.

This is not a drop-in replacement for OpenSSL or libsodium. It does
not attempt to solve key distribution, certificate management, or
protocol negotiation. Those are separate problems that require
separate engineering.

This is not an audited implementation. The code has been validated
against the official NIST ACVP test vectors and fuzzed, but it has
not been through an independent third-party security audit. If your
threat model requires an audit, use a library that has been audited
or wait for one that will be.

This is not a complete post-quantum stack. It provides ML-KEM-768.
It does not provide ML-DSA from scratch (that still comes from the
ml-dsa RustCrypto crate), ML-KEM-1024, FrodoKEM, or other PQC
primitives. Adding those is a future direction, not a current
feature.

What this project *is*: a building block. You can use it as the
KEM inside a larger system, as a reference implementation for
understanding ML-KEM, as a CLI for encrypting files at rest with a
post-quantum key, or as an ACVP-conformant code base to fork and
modify.


================================================================================
  3.  THE FROM-SCRATCH ML-KEM
================================================================================

The ML-KEM implementation in cipherbox-pqc-core is written against
FIPS 203 directly. No external KEM crate is used. The dependency
list is deliberately small:

  ml-dsa 0.1.2          ML-DSA (Dilithium) signatures. Not rewritten.
  chacha20poly1305 0.10 AEAD primitive for symmetric encryption.
  argon2 0.5            Passphrase KDF.
  base64 0.22           Encoding only.
  getrandom 0.2         OS entropy only.

Everything in the ML-KEM algorithm is our own code:

  keccak.rs  ~350 lines
      Keccak-f[1600] permutation. SHA3-256, SHA3-512, SHAKE-128,
      SHAKE-256. Implemented from the FIPS 202 specification.
      Tested against NIST's published KAT vectors for each function.

  field.rs  ~200 lines
      Field arithmetic modulo q = 3329. Montgomery multiplication
      with R = 2^16. Constant-time addition, subtraction,
      multiplication, negation, and equality. QINV (the Montgomery
      inverse constant) is derived by a compile-time brute-force
      search rather than a hand-written constant, removing any risk
      of transcription errors.

  ntt.rs  ~150 lines
      The 7-layer NTT and inverse NTT for Kyber-768. Zetas table
      is generated at compile time by computing ζ^bitrev7(k) and
      converting to Montgomery form, so the constants are provably
      correct.

  poly.rs  ~300 lines
      CBD sampling (η = 2), compress/decompress for d = 1, 4, 10,
      12, and byte encoding for 12-bit, 10-bit, 4-bit, and 1-bit
      polynomials. Every routine has round-trip tests including
      boundary values (all-zeros, all-ones, all-0xFFF, etc.).

  pke.rs  ~250 lines
      IND-CPA public-key encryption: K-PKE.KeyGen, K-PKE.Encrypt,
      K-PKE.Decrypt per Algorithms 13, 14, and 15. Uses all the
      above.

  kem.rs  ~130 lines
      IND-CCA key encapsulation: ML-KEM.KeyGen, ML-KEM.Encaps,
      ML-KEM.Decaps per Algorithms 16, 17, and 18. Implements the
      Fujisaki-Okamoto transform with implicit rejection: an
      invalid ciphertext produces a deterministic pseudorandom
      shared secret derived from J(z || c), never a decryption
      failure.

  file.rs  ~450 lines
      The chunked file encryption format. See section 6.

Total: approximately 1,830 lines of new cryptographic code in
cipherbox-pqc-core/src/. Everything below the "AEAD primitive" line
— ChaCha20-Poly1305, Argon2, and ML-DSA — is a dependency, and that
line is where we are honest about what is ours and what is not.


================================================================================
  4.  WHY "FROM SCRATCH" MATTERS
================================================================================

Every language ecosystem already has ML-KEM libraries. The RustCrypto
ml-kem crate is well-maintained, security-assessed, and used in
production. Why write another one?

Because the criticism of every wrapper library is the same: "I can
just use ml-kem directly; I do not need your wrapper." That
criticism is correct. A wrapper that adds nothing but an API is a
wrapper that adds nothing.

A from-scratch implementation is a different kind of artifact. It is
auditable at the algorithm level. If you want to understand how the
NTT works in ML-KEM-768, you can read ntt.rs. If you want to know
why the shared secret in decapsulation is derived the way it is, you
can read kem.rs. There is no opaque dependency between the spec and
the behavior. The code IS the spec, translated into Rust.

This matters for three concrete use cases:

  1. Teaching and reference. If you are writing a paper, teaching a
     course, or learning how ML-KEM works, a from-scratch
     implementation with ACVP validation is a better reference than
     a wrapper around an opaque library.

  2. Auditability. A reviewer who wants to verify that your system
     uses ML-KEM correctly can read the code that computes it. In a
     wrapper, they have to trust the wrapper AND the library. In a
     from-scratch implementation, they have to trust only the code
     in front of them, plus their own ability to verify it against
     the spec.

  3. Forkability. If you need to modify ML-KEM (for research, for
     a variant, for a constrained environment), you cannot modify
     a library you do not own. You can modify code you wrote.

What from-scratch does NOT buy you:

  - It does not buy you an audit. An implementation is audited by
    an independent third party, not by its author.
  - It does not buy you constant-time guarantees beyond what the
    code actually does. The field arithmetic is constant-time with
    respect to input values, but the compiler can optimize in ways
    that affect timing, and no formal verification has been done.
  - It does not buy you a performance improvement over the
    RustCrypto crate. Ours is probably slower.
  - It does not buy you production readiness. The RustCrypto ml-kem
    crate is production-ready. Ours is a reference implementation
    that happens to pass the ACVP vectors, which is the most
    important correctness milestone but not the only one.

Use this project when the value of transparency outweighs the cost
of writing and maintaining your own code. That is a real trade-off,
and it is not always the right one.


================================================================================
  5.  ACVP VALIDATION
================================================================================

The single most important validation of a from-scratch ML-KEM
implementation is conformance to the NIST ACVP test vectors. These
are the same vectors that every FIPS 203 implementation is validated
against by certification laboratories.

The project is validated against the ML-KEM-768 vectors from the
NIST ACVP-Server repository (v1.1.0.40):

  ML-KEM-keyGen-FIPS203/internalProjection.json
      25 test cases for parameter set ML-KEM-768.
      Each case provides (d, z) and expects (ek, dk).

  ML-KEM-encapDecap-FIPS203/internalProjection.json
      25 encapsulation cases and 10 decapsulation cases for
      parameter set ML-KEM-768.
      Encapsulation: given (ek, m), expects (c, k).
      Decapsulation: given (dk, c), expects k.
      The decapsulation cases include "modified ciphertext"
      inputs that exercise the implicit-rejection path.

Test file: cipherbox-pqc-core/tests/acvp_kat.rs.
Command:  cargo test acvp -- --nocapture.

Expected output:

  ACVP keyGen ML-KEM-768: 25 cases passed
  ACVP encapDecap ML-KEM-768: 25 encapsulation, 10 decapsulation cases passed

The test also skips the encapsulationKeyCheck and
decapsulationKeyCheck groups, which test FIPS 203 §7.2 and §7.3 key
validation. Those routines are not implemented (they are not part of
the KEM algorithms 16–18) and are a separate task for the future.

Passing these vectors is not the same as passing a certification
lab. A certification lab tests the implementation, the build process,
the documentation, and the operational environment. Passing the
vectors is the necessary and sufficient condition for "the math is
right." Everything else is process.


================================================================================
  6.  THE CHUNKED FILE FORMAT
================================================================================

The file format is designed for streaming encryption of arbitrarily
large files. The construction is the STREAM construction (Hoang,
Reyhanitabar, Rogaway, Vizár, 2015), which is the standard way to
apply an AEAD to a long message with chunked processing.

Header layout (all multi-byte integers are little-endian):

  +--------+---------+--------------+-------------+
  | magic  | version | chunk_size   | kem_ct      |
  | 4 B    | 1 B     | 4 B (u32)    | 1088 B      |
  +--------+---------+--------------+-------------+

  magic       b"CBOX"
  version     0x01
  chunk_size  plaintext bytes per chunk (must be in [64, 1048576])
  kem_ct      ML-KEM-768 ciphertext (1088 bytes)

The header is followed by one or more chunks. Each chunk is:

  ChaCha20-Poly1305(chunk_plaintext) with:
    key    = aead_key
    nonce  = counter (u64 LE) || 0x00 0x00 0x00 || last_flag (1 B)
    aad    = b"CBOX-v1-chunk"

  counter     chunk index, starting at 0
  last_flag   0x00 for non-final chunks, 0x01 for the final chunk

The final chunk is always present. If the plaintext length is an
exact multiple of chunk_size, the final chunk has zero-length
plaintext and consists only of the AEAD tag (16 bytes).

The AEAD key is derived as:

  aead_key = SHA3-256("cipherbox-file-v1" || header || shared_secret)

  header        = every byte from magic through the end of kem_ct
  shared_secret = ML-KEM shared secret from decapsulating kem_ct

This binding is important. It means that the AEAD key depends on the
header bytes. If an attacker flips any bit in the header — the
magic, the version, the chunk_size, or the KEM ciphertext — the
derived key will be different, and every chunk will fail
authentication. There is no way to modify the header without
invalidating the whole file.

Truncation detection:

  A ciphertext that has had its last chunk stripped produces a
  stream whose remaining chunks decrypt correctly but whose final
  chunk has last_flag = 0. The decryptor's finish() method always
  uses last_flag = 1 for the last chunk; the AEAD tag computed by
  the sender under last_flag = 0 will not verify. The decryptor
  returns an error. No partial plaintext is accepted.

  Similarly, a ciphertext that has had middle chunks stripped
  produces a stream where the chunk counter does not match the
  expected chunk index. The decryptor's update() checks this
  implicitly: the chunk at index N is decrypted with nonce derived
  from counter N, so removing a chunk shifts all subsequent counters
  and every chunk after the removal fails authentication.

Reorder detection:

  Swapping two chunks changes their counters. The AEAD tag for chunk
  N is computed under counter N; decrypting it as chunk M produces
  a tag mismatch. Reordering fails.

The format has no external length field. The decryptor learns the
plaintext length only by processing all chunks and reaching the final
one. This is standard for STREAM constructions and is what makes the
format work for streaming input of unknown length.

Limitations:

  The format does not compress. It does not hide the plaintext
  length (the ciphertext length is header + chunks + tags, which is
  a deterministic function of the plaintext length rounded up to
  chunk_size). It does not provide forward secrecy — the KEM
  ciphertext in the header is the only key material, and whoever
  holds the decapsulation key can decrypt the file at any time.

  If you need forward secrecy, you need a different construction
  where the KEM key is ephemeral and the decryption key is
  destroyed after use. That is a protocol-level decision, not a
  format-level one.


================================================================================
  7.  CLI TOOLS
================================================================================

Five binaries are provided. All use only the core crate, base64, and
the Rust standard library.

cipherbox-pqc-keygen
----------------------

  Generate a fresh ML-KEM-768 keypair.

  Usage:
      cipherbox-pqc-keygen                    # print to stdout
      cipherbox-pqc-keygen --out <dir>        # write ek.b64 and dk_seed.b64

  Output format:
      EK=<base64 1184-byte encapsulation key>
      DK_SEED=<base64 64-byte seed (d || z)>

  The seed is sufficient to reconstruct both halves of the keypair.
  Store it encrypted; anyone with the seed can decapsulate.

cipherbox-pqc-file-encrypt
----------------------------

  Encrypt a file using chunked streaming.

  Usage:
      cipherbox-pqc-file-encrypt <recipient_pk_b64> <input> <output> [chunk_size]

  chunk_size defaults to 65536 bytes. Range: [64, 1048576].

  The recipient's public key is 1184 bytes encoded as base64.

cipherbox-pqc-file-decrypt
----------------------------

  Decrypt a file produced by cipherbox-pqc-file-encrypt.

  Usage:
      cipherbox-pqc-file-decrypt <dk_seed_b64> <input> <output>

  Any tampering, truncation, or reordering of the ciphertext causes
  the command to exit non-zero with an error message. Partial
  plaintext is never written to the output.

cipherbox-pqc-verify
----------------------

  Verify an ML-DSA-65 signature (unchanged from previous versions).

  Usage:
      cipherbox-pqc-verify <public_key_b64> <message_b64> <signature_b64>

  Prints "true" and exits 0 on success; "false" and exits 1 on
  failure.

cipherbox-pqc-wrap
--------------------

  Wrap a plaintext room key to a user's ML-KEM public key, producing
  JSON suitable for transmitting a symmetric key to the recipient.
  (Unchanged from previous versions.)

  Usage:
      cipherbox-pqc-wrap <user_kyber_pk_b64> <plaintext_room_key>


================================================================================
  8.  LIBRARY USAGE
================================================================================

Basic key encapsulation:

  use cipherbox_pqc_core::MlKemKeyPair;

  let kp = MlKemKeyPair::new()?;
  let (ct, shared_secret_sender) = kp.encapsulate()?;
  let shared_secret_recipient = kp.decapsulate(&ct)?;
  assert_eq!(shared_secret_sender, shared_secret_recipient);

Reconstructing from the seed:

  let kp = MlKemKeyPair::new()?;
  let (seed, _ek) = kp.export_keys();
  let kp2 = MlKemKeyPair::from_seed(&seed)?;

Chunked file encryption:

  use cipherbox_pqc_core::file::{encrypt_file, decrypt_file};
  use cipherbox_pqc_core::MlKemKeyPair;

  let recipient = MlKemKeyPair::new()?;
  let ek = recipient.encapsulation_key();
  let dk = recipient.decapsulation_key();

  let plaintext = b"large file contents here";
  let ct = encrypt_file(plaintext, ek, 65536)?;
  let pt = decrypt_file(&ct, dk)?;
  assert_eq!(pt, plaintext);

Streaming encryption for files larger than memory:

  use cipherbox_pqc_core::file::{FileEncryptor, FileDecryptor};

  let mut enc = FileEncryptor::new(ek, 65536)?;
  let mut ct = Vec::new();
  for chunk in source_chunks {
      enc.update(chunk, &mut ct)?;
  }
  enc.finish(&mut ct)?;

  let mut dec = FileDecryptor::new(dk);
  let mut pt = Vec::new();
  for chunk in ciphertext_chunks {
      dec.update(chunk, &mut pt)?;
  }
  dec.finish(&mut pt)?;

Passphrase encryption (unchanged, uses Argon2 + ChaCha20-Poly1305):

  use cipherbox_pqc_core::{encrypt_private_key, decrypt_private_key};

  let encrypted = encrypt_private_key(seed_bytes, "passphrase")?;
  let recovered = decrypt_private_key(&encrypted, "passphrase")?;

ML-DSA signatures (via the ml-dsa crate, not from scratch):

  use cipherbox_pqc_core::MlDsaKeyPair;

  let kp = MlDsaKeyPair::new();
  let msg = b"hello, post-quantum world";
  let sig = kp.sign(msg);
  assert!(kp.verify(msg, &sig));


================================================================================
  9.  TESTING AND FUZZING
================================================================================

Test suite (all green, `cargo test --all-targets`):

  keccak_kat.rs    9   SHA3-256, SHA3-512, SHAKE-128, SHAKE-256 KATs
  field_kat.rs     12  Field arithmetic exhaustive property tests
  ntt_kat.rs       7   NTT / InvNTT / basemul / poly_mul correctness
  poly_kat.rs      16  CBD, compress/decompress, byte encoding
  pke_kat.rs       6   IND-CPA PKE roundtrip and determinism
  kem_kat.rs       7   IND-CCA KEM roundtrip and implicit rejection
  file_kat.rs      16  Chunked file format, truncation, reordering
  acvp_kat.rs      2   NIST ACVP keyGen and encapDecap vectors
  (native)
  native_crypto.rs 6   Existing verify, wrap, ML-KEM roundtrip tests
  file_decrypt.rs  8   CLI end-to-end for keygen, encrypt, decrypt

Total: 89 tests.

Fuzzing (libFuzzer, nightly):

  decrypt_file: 12,378,253 executions in 121 seconds.
                Reached 708 edges of the file decrypt path.
                Zero crashes. Corpus grew to 22 inputs.
                Dictionary hits included the magic "CBOX",
                the version byte, and the chunk_size field.

  kem_decaps:     87,847 executions in 121 seconds.
                Reached 214 edges of the KEM decapsulation path.
                Zero crashes. Slow per-execution (~1.4 ms) because
                each call does pke_decrypt + pke_encrypt + four
                SHA3-512 + one SHAKE-256.

The fuzzing was a bounded campaign, not an exhaustive one. The
numbers above are what actually ran. Do not read them as "no bugs
exist"; read them as "no crashes were found in these specific runs."
A production deployment would run these fuzzers for hours,
preferably overnight, with a seeded corpus. That is a maintenance
activity, not a one-time claim.

CI target:

  make ci
      cargo fmt --all -- --check
      cargo clippy --all-targets -- -D warnings
      cargo test --all-targets


================================================================================
 10.  SECURITY MODEL AND HONEST LIMITATIONS
================================================================================

What is verified:

  - ML-KEM-768 conformance to NIST ACVP vectors (60 cases).
  - Round-trip correctness of every cryptographic primitive in the
    algorithm (PKE, KEM, file format).
  - Constant-time behavior of field arithmetic with respect to
    input values (no data-dependent branches, no division, no table
    lookups).
  - Implicit rejection in the FO transform (invalid ciphertext
    produces a deterministic pseudorandom value, not an error).
  - Chunked file format detects truncation, reordering, and any
    header tampering.
  - No panics on adversarial input in the fuzzed paths.

What is NOT verified:

  - Independent third-party audit. There has been none.
  - Formal verification. No mechanized proof of correctness.
  - Side-channel resistance beyond what the code actually does.
    The field arithmetic is constant-time with respect to input
    values. But the compiler can optimize across function
    boundaries in ways that introduce data-dependent timing, and
    we have not analyzed the compiled output. WebAssembly and JIT
    environments are worse: their timing characteristics are not
    under our control.
  - Memory wiping. Keys are held in fixed-size arrays and are not
    explicitly zeroized after use. If you hold a MlKemKeyPair in
    memory, an attacker with process memory access can observe it
    while it is alive. This is a known limitation. Adding zeroize
    to all key types is a straightforward future improvement.
  - Performance. The implementation is not optimized. It is
    correct. If you need fast ML-KEM, use RustCrypto.

When to use this library:

  - You want to understand ML-KEM by reading its implementation.
  - You want a transparent, ACVP-validated building block that you
    can audit or fork.
  - You want a fully specified chunked file format that you can
    implement in another language if you need to.
  - You are learning or teaching.

When NOT to use this library:

  - You need a certified, audited, production-grade KEM. Use a
    library that has been certified or audited.
  - You need maximum performance. Use an optimized implementation.
  - You need features this library does not provide (ML-KEM-1024,
    hybrid KEX, protocol negotiation, certificate handling, etc.).


================================================================================
 11.  RELATIONSHIP TO OTHER PQC PROJECTS
================================================================================

RustCrypto ml-kem
-----------------

  This project's ML-KEM is not a wrapper around the ml-kem crate.
  The RustCrypto crate is what most Rust applications should use;
  it is security-assessed, maintained, and used in production. This
  project exists for a different purpose: transparency at the
  algorithm level. If you are building a product, use ml-kem. If
  you are building a reference implementation or an auditable
  system, use this.

Polynom (closed-source collaboration product)
---------------------------------------------

  Polynom is a collaboration platform that uses Kyber-1024 for key
  exchange and Dilithium5 for signatures, plus a proprietary
  "Social Encryption" layer that derives keys from shared entropy.
  It is a complete product (chat, rooms, file sharing, mobile
  apps). This project is a toolkit: a KEM, a file format, and CLI
  tools. Different users, different trust model. Neither is a
  substitute for the other.

  Where this project differs from Polynom:

    - Uses ML-KEM-768 (Level III) instead of Kyber-1024 (Level V).
      Both are FIPS 203 conformant. Level III is smaller and faster;
      Level V is more conservative.
    - Uses ChaCha20-Poly1305 instead of AES-256-GCM.
    - Publishes ACVP validation results. Polynom's whitepaper says
      it uses Kyber-1024 and Dilithium5; it does not publish test
      vectors.
    - Publishes the file encryption format. Polynom does not.
    - Is not a product. It is a building block.

  Where Polynom differs from this project:

    - Is a complete product with a UI, network protocols, mobile
      apps, and a user-facing feature set.
    - Uses a proprietary entropy-based key exchange layer that is
      not a NIST standard and is not independently auditable.
    - Uses Dilithium5 instead of ML-DSA-65 for signatures.

  These are different projects solving different problems. Do not
  compare them on features; compare them on whether the transparency
  of the cryptographic core matters to you.

liboqs
------

  liboqs is the reference C library for post-quantum cryptography.
  It implements many more algorithms than this project (ML-KEM,
  ML-DSA, FrodoKEM, BIKE, HQC, etc.) and is the library used by
  OpenSSL's PQC support. If you need breadth, use liboqs. This
  project is narrower: one KEM, from scratch, with ACVP
  validation and a file format.


================================================================================
 12.  BUILDING
================================================================================

Requirements:

  Rust 1.85 or later (edition 2024).
  For fuzzing: rustup with nightly toolchain.

Build the whole workspace:

  cargo build --release

Build only the native crate:

  cd cipherbox-pqc-native
  cargo build --release
  # Binaries in target/release/

Run tests:

  cargo test --all-targets

Run ACVP vectors with visible output:

  cd cipherbox-pqc-core
  cargo test acvp -- --nocapture

Fuzz (requires nightly):

  cd cipherbox-pqc-core/fuzz
  cargo +nightly fuzz run decrypt_file -- -max_total_time=120
  cargo +nightly fuzz run kem_decaps   -- -max_total_time=120


================================================================================
 13.  LICENSE
================================================================================

MIT. See LICENSE file for the full text.

Repository: https://github.com/thomas666-beast/cipherbox-pqc-native
Author:     Thomas <selfworker112@mailfence.com>

================================================================================
