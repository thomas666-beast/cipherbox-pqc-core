//! Tests for the X25519 + ML-KEM hybrid KEM and its use in files and key
//! wrapping. `data/hybrid_kat.txt` comes from an independent Python model
//! built on OpenSSL-validated ML-KEM and RFC 7748 X25519.

use cipherbox_pqc_core::hybrid::{self, SECRET_BYTES};
use cipherbox_pqc_core::{
    Decapsulator, HybridKeyPair, KemLevel, MlKemKeyPair, Suite, encapsulate_hybrid_to, file,
    unwrap_key, unwrap_room_key, validate_public_key, wrap_key, wrap_room_key_for_user,
};

const LEVELS: [KemLevel; 2] = [KemLevel::MlKem768, KemLevel::MlKem1024];
const KAT: &str = include_str!("data/hybrid_kat.txt");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn level(s: &str) -> KemLevel {
    KemLevel::from_param(s.parse().unwrap()).expect("level")
}

fn hk(level: KemLevel, seed: u8) -> HybridKeyPair {
    HybridKeyPair::from_seed(&[seed; 32], level).unwrap()
}

fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| ((i * 31 + 7) % 256) as u8).collect()
}

// ---------------- known answers ----------------

#[test]
fn hybrid_known_answers() {
    let (mut kg, mut en, mut dc, mut fl) = (0, 0, 0, 0);
    for line in KAT
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        let f: Vec<&str> = line.split_whitespace().collect();
        let lvl = level(f[1]);
        let seed = unhex(f[2]);
        let kp = HybridKeyPair::from_seed(&seed, lvl).unwrap();
        match f[0] {
            "HKEYGEN" => {
                assert_eq!(
                    kp.public_key(),
                    unhex(f[3]).as_slice(),
                    "{} keygen",
                    lvl.name()
                );
                kg += 1;
            }
            "HENCAPS" => {
                let (mut m, mut eph) = ([0u8; 32], [0u8; 32]);
                m.copy_from_slice(&unhex(f[3]));
                eph.copy_from_slice(&unhex(f[4]));
                let (ct, ss) = hybrid::encaps_deterministic(kp.public_key(), &m, &eph).unwrap();
                assert_eq!(ct, unhex(f[5]), "{} encaps ct", lvl.name());
                assert_eq!(ss.to_vec(), unhex(f[6]), "{} encaps ss", lvl.name());
                en += 1;
            }
            "HDECAPS" => {
                let ss = kp.decapsulate(&unhex(f[3])).unwrap();
                assert_eq!(ss, unhex(f[4]), "{} decaps", lvl.name());
                dc += 1;
            }
            "HFILE" => {
                let len: usize = f[4].parse().unwrap();
                let ct = unhex(f[5]);
                let got = file::decrypt_file_with_hybrid_secret(&ct, &kp.export_secret()).unwrap();
                assert_eq!(got, data(len), "{} file len {len}", lvl.name());
                fl += 1;
            }
            other => panic!("unknown record {other}"),
        }
    }
    assert_eq!(
        (kg, en, dc, fl),
        (4, 4, 12, 4),
        "expected the full vector set"
    );
}

// ---------------- KEM behaviour ----------------

#[test]
fn sizes() {
    for level in LEVELS {
        let kp = hk(level, 1);
        let suite = Suite::Hybrid(level);
        assert_eq!(kp.public_key().len(), suite.ek_bytes());
        let (ct, ss) = encapsulate_hybrid_to(kp.public_key()).unwrap();
        assert_eq!(ct.len(), suite.ct_bytes());
        assert_eq!(ss.len(), 32);
    }
    assert_eq!(hk(KemLevel::MlKem768, 1).public_key().len(), 1216);
    assert_eq!(hk(KemLevel::MlKem1024, 1).public_key().len(), 1600);
}

#[test]
fn roundtrip_and_independent_encapsulations() {
    for level in LEVELS {
        let kp = hk(level, 2);
        let (ct1, ss1) = encapsulate_hybrid_to(kp.public_key()).unwrap();
        let (ct2, ss2) = encapsulate_hybrid_to(kp.public_key()).unwrap();
        assert_eq!(kp.decapsulate(&ct1).unwrap(), ss1);
        assert_eq!(kp.decapsulate(&ct2).unwrap(), ss2);
        assert_ne!(ct1, ct2);
        assert_ne!(ss1, ss2);
    }
}

#[test]
fn tampering_either_half_changes_the_secret() {
    for level in LEVELS {
        let kp = hk(level, 3);
        let (ct, ss) = encapsulate_hybrid_to(kp.public_key()).unwrap();
        let cut = level.ct_bytes();

        let mut bad_m = ct.clone();
        bad_m[10] ^= 1; // ML-KEM half
        let s_m = kp.decapsulate(&bad_m).unwrap();
        assert_ne!(s_m, ss);

        let mut bad_x = ct.clone();
        bad_x[cut + 4] ^= 1; // X25519 half
        let s_x = kp.decapsulate(&bad_x).unwrap();
        assert_ne!(s_x, ss);
        assert_ne!(s_x, s_m);

        // Deterministic for the same bad input.
        assert_eq!(s_m, kp.decapsulate(&bad_m).unwrap());
    }
}

#[test]
fn wrong_key_and_wrong_length() {
    for level in LEVELS {
        let (ct, ss) = encapsulate_hybrid_to(hk(level, 1).public_key()).unwrap();
        assert_ne!(hk(level, 2).decapsulate(&ct).unwrap(), ss);
        assert!(hk(level, 1).decapsulate(&ct[..ct.len() - 1]).is_err());
    }
}

#[test]
fn same_seed_different_levels_are_unrelated() {
    let a = hk(KemLevel::MlKem768, 7);
    let b = hk(KemLevel::MlKem1024, 7);
    // The X25519 halves differ because the seed expansion is level-separated.
    assert_ne!(
        &a.public_key()[a.public_key().len() - 32..],
        &b.public_key()[b.public_key().len() - 32..]
    );
}

#[test]
fn public_key_validation() {
    for level in LEVELS {
        let kp = hk(level, 4);
        assert_eq!(
            validate_public_key(kp.public_key()).unwrap(),
            Suite::Hybrid(level)
        );
        assert_eq!(
            hybrid::validate_hybrid_public_key(kp.public_key()).unwrap(),
            level
        );

        // ML-KEM half out of range -> rejected.
        let mut bad = kp.public_key().to_vec();
        bad[0] = 0xFF;
        bad[1] = 0xFF;
        assert!(validate_public_key(&bad).is_err());
        assert!(encapsulate_hybrid_to(&bad).is_err());

        // Wrong length.
        assert!(validate_public_key(&kp.public_key()[..100]).is_err());
    }
    // A plain ML-KEM key is not a hybrid key.
    let plain = MlKemKeyPair::from_seed(&[1u8; 64]).unwrap();
    assert_eq!(
        validate_public_key(plain.encapsulation_key()).unwrap(),
        Suite::Kem(KemLevel::MlKem768)
    );
    assert!(hybrid::validate_hybrid_public_key(plain.encapsulation_key()).is_err());
    assert!(encapsulate_hybrid_to(plain.encapsulation_key()).is_err());
}

#[test]
fn low_order_x25519_public_key_is_rejected_by_sender() {
    for level in LEVELS {
        let kp = hk(level, 5);
        for point in [[0u8; 32], {
            let mut p = [0u8; 32];
            p[0] = 1; // u = 1, a low-order point
            p
        }] {
            let mut pk = kp.public_key().to_vec();
            let n = pk.len();
            pk[n - 32..].copy_from_slice(&point);
            assert!(
                encapsulate_hybrid_to(&pk).is_err(),
                "{} {:?}",
                level.name(),
                &point[..2]
            );
        }
    }
}

#[test]
fn receiver_never_errors_on_odd_x25519_ciphertext() {
    for level in LEVELS {
        let kp = hk(level, 6);
        let (mut ct, ss) = encapsulate_hybrid_to(kp.public_key()).unwrap();
        let n = ct.len();
        ct[n - 32..].fill(0); // low-order point as ct_x
        let out = kp.decapsulate(&ct).unwrap();
        assert_ne!(out, ss);
    }
}

#[test]
fn secret_export_import() {
    for level in LEVELS {
        let kp = hk(level, 8);
        let secret = kp.export_secret();
        assert_eq!(secret.len(), SECRET_BYTES);
        assert_eq!(secret[0], 1);
        assert_eq!(secret[1], level.id());
        let kp2 = HybridKeyPair::from_secret(&secret).unwrap();
        assert_eq!(kp2.level(), level);
        assert_eq!(kp.public_key(), kp2.public_key());
        let (ct, ss) = encapsulate_hybrid_to(kp.public_key()).unwrap();
        assert_eq!(kp2.decapsulate(&ct).unwrap(), ss);

        let mut bad = secret.clone();
        bad[0] = 9;
        assert!(HybridKeyPair::from_secret(&bad).is_err());
        let mut bad = secret.clone();
        bad[1] = 77;
        assert!(HybridKeyPair::from_secret(&bad).is_err());
        assert!(HybridKeyPair::from_secret(&secret[..33]).is_err());
    }
    assert!(HybridKeyPair::from_seed(&[0u8; 31], KemLevel::MlKem768).is_err());
    assert_eq!(
        HybridKeyPair::new(KemLevel::MlKem768)
            .unwrap()
            .public_key()
            .len(),
        1216
    );
}

// ---------------- files ----------------

const CS: usize = 64;

fn enc(kp: &HybridKeyPair, pt: &[u8]) -> Vec<u8> {
    file::encrypt_file(pt, kp.public_key(), CS).unwrap()
}

#[test]
fn hybrid_file_roundtrip_and_header() {
    for level in LEVELS {
        let kp = hk(level, 9);
        for n in [0, 1, 63, 64, 65, 300, 1000] {
            let pt = data(n);
            let ct = enc(&kp, &pt);
            assert_eq!(
                file::decrypt_file_with_hybrid_secret(&ct, &kp.export_secret()).unwrap(),
                pt,
                "{} n={n}",
                level.name()
            );
        }
        let ct = enc(&kp, b"x");
        assert_eq!(&ct[..5], b"CBOX\x02");
        assert_eq!(ct[5], Suite::Hybrid(level).id());
        assert_eq!(
            ct.len(),
            file::header_len_suite(Suite::Hybrid(level)) + 1 + file::TAG_BYTES
        );
    }
}

#[test]
fn hybrid_file_streaming_odd_slices() {
    for level in LEVELS {
        let kp = hk(level, 9);
        let pt = data(5000);
        let mut e = file::FileEncryptor::new(kp.public_key(), CS).unwrap();
        let mut ct = Vec::new();
        for piece in pt.chunks(37) {
            e.update(piece, &mut ct).unwrap();
        }
        e.finish(&mut ct).unwrap();

        let mut d = file::FileDecryptor::from_hybrid_secret(&kp.export_secret()).unwrap();
        let mut out = Vec::new();
        for piece in ct.chunks(101) {
            d.update(piece, &mut out).unwrap();
        }
        d.finish(&mut out).unwrap();
        assert_eq!(out, pt);
    }
}

#[test]
fn hybrid_file_wrong_keys_fail() {
    for level in LEVELS {
        let kp = hk(level, 9);
        let ct = enc(&kp, &data(300));
        // other hybrid key of the same level
        assert!(
            file::decrypt_file_with_hybrid_secret(&ct, &hk(level, 10).export_secret()).is_err()
        );
        // hybrid key of the other level
        let other = if level == KemLevel::MlKem768 {
            KemLevel::MlKem1024
        } else {
            KemLevel::MlKem768
        };
        assert!(file::decrypt_file_with_hybrid_secret(&ct, &hk(other, 9).export_secret()).is_err());
        // plain seed / plain dk cannot open a hybrid file
        assert!(file::decrypt_file_with_seed(&ct, &[9u8; 64]).is_err());
        let plain = MlKemKeyPair::from_seed_with_level(&[9u8; 64], level).unwrap();
        assert!(file::decrypt_file(&ct, plain.decapsulation_key()).is_err());
    }
    // a hybrid key cannot open a plain-ML-KEM file
    let plain = MlKemKeyPair::from_seed(&[9u8; 64]).unwrap();
    let ct = file::encrypt_file(&data(100), plain.encapsulation_key(), CS).unwrap();
    assert!(
        file::decrypt_file_with_hybrid_secret(&ct, &hk(KemLevel::MlKem768, 9).export_secret())
            .is_err()
    );
}

#[test]
fn hybrid_file_tamper_and_truncation_fail() {
    for level in LEVELS {
        let kp = hk(level, 9);
        let secret = kp.export_secret();
        let pt = data(300);
        let ct = enc(&kp, &pt);
        let hl = file::header_len_suite(Suite::Hybrid(level));

        for pos in [
            0usize,
            4,
            5,
            6,
            9,
            10,
            500,
            hl - 1,
            hl,
            hl + 100,
            ct.len() - 1,
        ] {
            let mut bad = ct.clone();
            bad[pos] ^= 0x01;
            assert!(
                file::decrypt_file_with_hybrid_secret(&bad, &secret).is_err(),
                "{}: flip at {pos} accepted",
                level.name()
            );
        }
        let last = (pt.len() % CS) + file::TAG_BYTES;
        assert!(file::decrypt_file_with_hybrid_secret(&ct[..ct.len() - 5], &secret).is_err());
        assert!(file::decrypt_file_with_hybrid_secret(&ct[..ct.len() - last], &secret).is_err());
        assert!(file::decrypt_file_with_hybrid_secret(&ct[..hl], &secret).is_err());
        let mut longer = ct.clone();
        longer.extend_from_slice(&[0u8; 16]);
        assert!(file::decrypt_file_with_hybrid_secret(&longer, &secret).is_err());
    }
}

// ---------------- key wrapping ----------------

#[test]
fn hybrid_binary_wrap_roundtrip() {
    for level in LEVELS {
        let kp = hk(level, 11);
        let blob = wrap_key(kp.public_key(), b"room-key-123").unwrap();
        assert_eq!(unwrap_key(&kp, &blob).unwrap(), b"room-key-123");
        assert!(unwrap_key(&hk(level, 12), &blob).is_err());
        for pos in [0usize, 4, 20, blob.len() - 1] {
            let mut bad = blob.clone();
            bad[pos] ^= 1;
            assert!(unwrap_key(&kp, &bad).is_err(), "pos {pos}");
        }
        // A plain key of the same level cannot open it (different ct length).
        let plain = MlKemKeyPair::from_seed_with_level(&[11u8; 64], level).unwrap();
        assert!(unwrap_key(&plain, &blob).is_err());
    }
}

fn field(json: &str, key: &str) -> String {
    let pat = format!("\"{key}\":\"");
    let s = json.find(&pat).unwrap() + pat.len();
    json[s..s + json[s..].find('"').unwrap()].to_string()
}

#[test]
fn hybrid_json_room_key_roundtrip() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    for level in LEVELS {
        let kp = hk(level, 13);
        let pk = STANDARD.encode(kp.public_key());
        let json = wrap_room_key_for_user(&pk, "my room key").unwrap();
        let (ct, iv, enc) = (
            field(&json, "ct"),
            field(&json, "iv"),
            field(&json, "enc_aes"),
        );
        assert_eq!(
            unwrap_room_key(&kp, 2, &ct, &iv, &enc).unwrap(),
            "my room key"
        );
        assert!(unwrap_room_key(&hk(level, 14), 2, &ct, &iv, &enc).is_err());
    }
}

#[test]
fn decapsulator_trait_is_usable_generically() {
    fn roundtrip<K: Decapsulator>(kp: &K) {
        let (_s, ct, ss) = cipherbox_pqc_core::encapsulate_any(kp.public_key_bytes()).unwrap();
        assert_eq!(kp.decapsulate_raw(&ct).unwrap(), ss);
        assert_eq!(ct.len(), kp.suite().ct_bytes());
    }
    roundtrip(&hk(KemLevel::MlKem768, 1));
    roundtrip(&hk(KemLevel::MlKem1024, 1));
    roundtrip(&MlKemKeyPair::from_seed(&[1u8; 64]).unwrap());
}
