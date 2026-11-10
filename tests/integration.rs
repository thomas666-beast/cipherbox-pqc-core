use cipherbox_pqc_core::file::{self, FileDecryptor, FileEncryptor};
use cipherbox_pqc_core::{
    KemLevel, MlDsa87KeyPair, MlDsaKeyPair, MlKemKeyPair, decrypt_private_key, encapsulate_to,
    encrypt_private_key, encrypt_private_key_with_params, kem, unwrap_key, unwrap_room_key,
    validate_encapsulation_key, wrap_key, wrap_room_key_for_user,
};

const LEVELS: [KemLevel; 2] = [KemLevel::MlKem768, KemLevel::MlKem1024];

fn kp(level: KemLevel, seed: u8) -> MlKemKeyPair {
    MlKemKeyPair::from_seed_with_level(&[seed; 64], level).unwrap()
}

fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 + 7) as u8).collect()
}

/// Corrupt the first coefficient of `t_hat` so it is >= q.
fn bad_ek(level: KemLevel) -> Vec<u8> {
    let mut ek = kp(level, 3).encapsulation_key().to_vec();
    ek[0] = 0xFF;
    ek[1] = 0xFF;
    ek
}

// ---------------- KEM ----------------

#[test]
fn kem_roundtrip_many_seeds() {
    for level in LEVELS {
        for s in 0..4u8 {
            let k = kp(level, s);
            assert_eq!(k.level(), level);
            let (ct, ss) = encapsulate_to(k.encapsulation_key()).unwrap();
            assert_eq!(ct.len(), level.ct_bytes());
            assert_eq!(k.decapsulate(&ct).unwrap(), ss, "{} seed {s}", level.name());
        }
    }
}

#[test]
fn kem_tampered_ct_gives_different_secret() {
    for level in LEVELS {
        let k = kp(level, 1);
        let (mut ct, ss) = encapsulate_to(k.encapsulation_key()).unwrap();
        ct[10] ^= 1;
        let ss2 = k.decapsulate(&ct).unwrap();
        assert_ne!(ss, ss2);
        assert_eq!(ss2, k.decapsulate(&ct).unwrap()); // deterministic rejection
    }
}

#[test]
fn kem_wrong_key_and_wrong_length() {
    for level in LEVELS {
        let (ct, ss) = encapsulate_to(kp(level, 1).encapsulation_key()).unwrap();
        assert_ne!(kp(level, 2).decapsulate(&ct).unwrap(), ss);
        assert!(kp(level, 1).decapsulate(&ct[..ct.len() - 1]).is_err());
    }
    // A 768 key cannot decapsulate a 1024 ciphertext and vice versa.
    let (ct1024, _) = encapsulate_to(kp(KemLevel::MlKem1024, 1).encapsulation_key()).unwrap();
    assert!(kp(KemLevel::MlKem768, 1).decapsulate(&ct1024).is_err());
}

#[test]
fn same_seed_different_levels_give_different_keys() {
    let a = kp(KemLevel::MlKem768, 5);
    let b = kp(KemLevel::MlKem1024, 5);
    assert_ne!(a.encapsulation_key().len(), b.encapsulation_key().len());
}

#[test]
fn ek_modulus_check_rejects_out_of_range() {
    for level in LEVELS {
        let good = kp(level, 3).encapsulation_key().to_vec();
        assert!(kem::check_ek_level(level, &good));
        assert!(validate_encapsulation_key(&good).is_ok());
        let bad = bad_ek(level);
        assert!(!kem::check_ek_level(level, &bad));
        assert!(validate_encapsulation_key(&bad).is_err());
        assert!(encapsulate_to(&bad).is_err());
        assert!(!kem::check_ek_level(level, &good[..good.len() - 1]));
    }
    assert!(validate_encapsulation_key(&[0u8; 100]).is_err());
}

#[test]
fn dk_check_detects_corrupt_hash() {
    for level in LEVELS {
        let k = kp(level, 4);
        let mut dk = k.decapsulation_key().to_vec();
        assert!(kem::check_dk_level(level, &dk));
        let n = dk.len();
        dk[n - 40] ^= 1; // inside the stored H(ek)
        assert!(!kem::check_dk_level(level, &dk));
        assert!(FileDecryptor::new(&dk).is_err());
    }
}

#[test]
fn import_export_roundtrip() {
    for level in LEVELS {
        let k = kp(level, 5);
        let (seed, ek) = k.export_keys();
        let k2 = MlKemKeyPair::import_keys(&seed, &ek).unwrap();
        assert_eq!(k2.level(), level);
        assert_eq!(k.encapsulation_key(), k2.encapsulation_key());
        let mut bad = ek.clone();
        bad[100] ^= 1;
        assert!(MlKemKeyPair::import_keys(&seed, &bad).is_err());
        assert!(MlKemKeyPair::from_seed_with_level(&seed[..63], level).is_err());
    }
}

#[test]
fn new_keypair_levels() {
    assert_eq!(MlKemKeyPair::new().unwrap().level(), KemLevel::MlKem768);
    let k = MlKemKeyPair::new_with_level(KemLevel::MlKem1024).unwrap();
    assert_eq!(k.encapsulation_key().len(), 1568);
    assert_eq!(k.decapsulation_key().len(), 3168);
}

// ---------------- file encryption ----------------

const CS: usize = 64;

fn enc(k: &MlKemKeyPair, pt: &[u8]) -> Vec<u8> {
    file::encrypt_file(pt, k.encapsulation_key(), CS).unwrap()
}

#[test]
fn file_header_formats() {
    let k768 = kp(KemLevel::MlKem768, 7);
    let c = enc(&k768, b"x");
    assert_eq!(&c[..5], b"CBOX\x01", "768 files stay in the v1 format");
    assert_eq!(file::header_len(KemLevel::MlKem768), file::HEADER_BYTES);

    let k1024 = kp(KemLevel::MlKem1024, 7);
    let c = enc(&k1024, b"x");
    assert_eq!(&c[..6], b"CBOX\x02\x05");
    assert_eq!(file::header_len(KemLevel::MlKem1024), 4 + 1 + 1 + 4 + 1568);
}

#[test]
fn file_roundtrip_various_sizes() {
    for level in LEVELS {
        let k = kp(level, 7);
        for n in [0, 1, 63, 64, 65, 127, 128, 129, 1000] {
            let pt = data(n);
            let ct = enc(&k, &pt);
            assert_eq!(
                file::decrypt_file(&ct, k.decapsulation_key()).unwrap(),
                pt,
                "{} n = {n}",
                level.name()
            );
            assert_eq!(
                file::decrypt_file_with_seed(&ct, &k.export_keys().0).unwrap(),
                pt
            );
        }
    }
}

#[test]
fn file_streaming_odd_slices() {
    for level in LEVELS {
        let k = kp(level, 7);
        let pt = data(5000);
        let mut e = FileEncryptor::new(k.encapsulation_key(), CS).unwrap();
        let mut ct = Vec::new();
        for piece in pt.chunks(37) {
            e.update(piece, &mut ct).unwrap();
        }
        e.finish(&mut ct).unwrap();

        // Seed-based decryptor works across arbitrary slicing, including
        // slices that split the header.
        let mut d = FileDecryptor::from_seed(&k.export_keys().0).unwrap();
        let mut out = Vec::new();
        for piece in ct.chunks(101) {
            d.update(piece, &mut out).unwrap();
        }
        d.finish(&mut out).unwrap();
        assert_eq!(out, pt);
    }
}

#[test]
fn file_wrong_key_and_wrong_level_fail() {
    for level in LEVELS {
        let ct = enc(&kp(level, 7), &data(300));
        assert!(file::decrypt_file(&ct, kp(level, 8).decapsulation_key()).is_err());
        assert!(file::decrypt_file_with_seed(&ct, &[8u8; 64]).is_err());
    }
    // Key of the other level is rejected by the header check.
    let ct768 = enc(&kp(KemLevel::MlKem768, 7), &data(300));
    let ct1024 = enc(&kp(KemLevel::MlKem1024, 7), &data(300));
    assert!(file::decrypt_file(&ct768, kp(KemLevel::MlKem1024, 7).decapsulation_key()).is_err());
    assert!(file::decrypt_file(&ct1024, kp(KemLevel::MlKem768, 7).decapsulation_key()).is_err());
    // The seed variant derives the right level from the header.
    assert!(file::decrypt_file_with_seed(&ct768, &[7u8; 64]).is_ok());
    assert!(file::decrypt_file_with_seed(&ct1024, &[7u8; 64]).is_ok());
}

#[test]
fn file_any_header_bit_flip_fails() {
    for level in LEVELS {
        let k = kp(level, 7);
        let ct = enc(&k, &data(300));
        let hl = file::header_len(level);
        for pos in [0usize, 4, 5, 6, 7, 9, 10, 500, hl - 1] {
            let mut bad = ct.clone();
            bad[pos] ^= 0x01;
            assert!(
                file::decrypt_file(&bad, k.decapsulation_key()).is_err(),
                "{}: flip at byte {pos} was accepted",
                level.name()
            );
        }
    }
}

#[test]
fn file_body_bit_flip_fails() {
    for level in LEVELS {
        let k = kp(level, 7);
        let ct = enc(&k, &data(300));
        let hl = file::header_len(level);
        for pos in [hl, hl + 100, ct.len() - 1] {
            let mut bad = ct.clone();
            bad[pos] ^= 0x80;
            assert!(file::decrypt_file(&bad, k.decapsulation_key()).is_err());
        }
    }
}

#[test]
fn file_truncation_fails() {
    for level in LEVELS {
        let k = kp(level, 7);
        let pt = data(300); // 4 full chunks + partial
        let ct = enc(&k, &pt);
        let hl = file::header_len(level);
        assert!(file::decrypt_file(&ct[..ct.len() - 5], k.decapsulation_key()).is_err());
        let last = (pt.len() % CS) + file::TAG_BYTES;
        assert!(file::decrypt_file(&ct[..ct.len() - last], k.decapsulation_key()).is_err());
        assert!(file::decrypt_file(&ct[..hl], k.decapsulation_key()).is_err());
        assert!(file::decrypt_file(&ct[..100], k.decapsulation_key()).is_err());
        assert!(file::decrypt_file(&ct[..3], k.decapsulation_key()).is_err());
        assert!(file::decrypt_file(&[], k.decapsulation_key()).is_err());
    }
}

#[test]
fn file_extension_and_reorder_fail() {
    for level in LEVELS {
        let k = kp(level, 7);
        let ct = enc(&k, &data(300));

        let mut longer = ct.clone();
        longer.extend_from_slice(&[0u8; 16]);
        assert!(file::decrypt_file(&longer, k.decapsulation_key()).is_err());

        let full = CS + file::TAG_BYTES;
        let mut swapped = ct.clone();
        let a = file::header_len(level);
        let (c0, c1) = (a..a + full, a + full..a + 2 * full);
        let tmp = swapped[c0.clone()].to_vec();
        swapped.copy_within(c1.clone(), c0.start);
        swapped[c1].copy_from_slice(&tmp);
        assert!(file::decrypt_file(&swapped, k.decapsulation_key()).is_err());
    }
}

#[test]
fn file_rejects_bad_chunk_size_and_key() {
    for level in LEVELS {
        let k = kp(level, 7);
        assert!(FileEncryptor::new(k.encapsulation_key(), file::CHUNK_SIZE_MIN - 1).is_err());
        assert!(FileEncryptor::new(k.encapsulation_key(), file::CHUNK_SIZE_MAX + 1).is_err());
        assert!(FileEncryptor::new(&bad_ek(level), CS).is_err());
    }
    assert!(FileEncryptor::new(&[0u8; 50], CS).is_err());
    assert!(FileDecryptor::new(&[0u8; 50]).is_err());
    assert!(FileDecryptor::from_seed(&[0u8; 10]).is_err());
}

// ---------------- key wrapping ----------------

#[test]
fn binary_wrap_roundtrip_and_tamper() {
    for level in LEVELS {
        let k = kp(level, 9);
        let blob = wrap_key(k.encapsulation_key(), b"room-key-123").unwrap();
        assert_eq!(unwrap_key(&k, &blob).unwrap(), b"room-key-123");
        assert!(unwrap_key(&kp(level, 10), &blob).is_err());
        for pos in [0usize, 4, 20, blob.len() - 1] {
            let mut bad = blob.clone();
            bad[pos] ^= 1;
            assert!(unwrap_key(&k, &bad).is_err(), "pos {pos}");
        }
    }
}

fn field(json: &str, key: &str) -> String {
    let pat = format!("\"{key}\":\"");
    let s = json.find(&pat).unwrap() + pat.len();
    json[s..s + json[s..].find('"').unwrap()].to_string()
}

#[test]
fn json_room_key_roundtrip() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    for level in LEVELS {
        let k = kp(level, 11);
        let pk = STANDARD.encode(k.encapsulation_key());
        let json = wrap_room_key_for_user(&pk, "my room key").unwrap();
        assert!(json.contains("\"v\":2"));
        let (ct, iv, enc) = (
            field(&json, "ct"),
            field(&json, "iv"),
            field(&json, "enc_aes"),
        );
        assert_eq!(
            unwrap_room_key(&k, 2, &ct, &iv, &enc).unwrap(),
            "my room key"
        );
        // A v2 blob must not open as legacy v1.
        assert!(unwrap_room_key(&k, 1, &ct, &iv, &enc).is_err());
    }
}

// ---------------- ML-DSA ----------------

#[test]
fn ml_dsa_65_roundtrip() {
    let k = MlDsaKeyPair::new();
    let sig = k.sign(b"hello");
    assert_eq!(sig.len(), 3309);
    assert!(k.verify(b"hello", &sig));
    assert!(!k.verify(b"hellp", &sig));
    assert!(!k.verify(b"hello", &sig[..sig.len() - 1]));
    let (seed, vk) = k.export_keys();
    assert_eq!(vk.len(), 1952);
    let k2 = MlDsaKeyPair::import_keys(&seed, &vk).unwrap();
    assert!(k2.verify(b"hello", &sig));
    assert!(MlDsaKeyPair::import_keys(&seed, &vk[..10]).is_err());
}

#[test]
fn ml_dsa_87_roundtrip() {
    let k = MlDsa87KeyPair::new();
    let sig = k.sign(b"hello");
    assert_eq!(sig.len(), 4627);
    assert!(k.verify(b"hello", &sig));
    assert!(!k.verify(b"hellp", &sig));
    let (seed, vk) = k.export_keys();
    assert_eq!(vk.len(), 2592);
    let k2 = MlDsa87KeyPair::import_keys(&seed, &vk).unwrap();
    assert!(k2.verify(b"hello", &sig));
    // A 65 key must be rejected by the 87 importer (length differs).
    let k65 = MlDsaKeyPair::new();
    let (s65, v65) = k65.export_keys();
    assert!(MlDsa87KeyPair::import_keys(&s65, &v65).is_err());
}

// ---------------- passphrase encryption ----------------
// Small Argon2 parameters keep these fast.

#[test]
fn passphrase_roundtrip_and_failures() {
    let blob = encrypt_private_key_with_params(b"secret seed", "pw", 64, 1, 1).unwrap();
    assert_eq!(&blob[..4], b"CBPK");
    assert_eq!(decrypt_private_key(&blob, "pw").unwrap(), b"secret seed");
    assert!(decrypt_private_key(&blob, "other").is_err());
    let mut bad = blob.clone();
    bad[5] ^= 1; // KDF parameters are authenticated
    assert!(decrypt_private_key(&blob[..10], "pw").is_err());
    assert!(decrypt_private_key(&bad, "pw").is_err());
    let mut huge = blob.clone();
    huge[5..9].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(decrypt_private_key(&huge, "pw").is_err());
}

#[test]
fn passphrase_default_params_and_legacy_blob() {
    use argon2::Argon2;
    use chacha20poly1305::{
        ChaCha20Poly1305, Key, Nonce,
        aead::{Aead, KeyInit},
    };
    let blob = encrypt_private_key(b"abc", "pw").unwrap();
    assert_eq!(decrypt_private_key(&blob, "pw").unwrap(), b"abc");

    // Legacy format (what 0.3.x produced).
    let salt = [3u8; 16];
    let nonce = [5u8; 12];
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(b"pw", &salt, &mut key)
        .unwrap();
    let ct = ChaCha20Poly1305::new(Key::from_slice(&key))
        .encrypt(Nonce::from_slice(&nonce), b"old data".as_slice())
        .unwrap();
    let mut legacy = salt.to_vec();
    legacy.extend_from_slice(&nonce);
    legacy.extend_from_slice(&ct);
    assert_eq!(decrypt_private_key(&legacy, "pw").unwrap(), b"old data");
}
