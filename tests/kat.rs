//! ML-KEM known-answer tests. `data/ml_kem_kat.txt` was generated with
//! OpenSSL's ML-KEM (through python-cryptography), an independent
//! implementation, for both ML-KEM-768 and ML-KEM-1024:
//!
//!   KEYGEN level seed ek           key generation from seed d||z
//!   DECAPS level seed ct ss        incl. corrupted ciphertexts (implicit rejection)
//!   ENCAPS level seed m ct ss      deterministic encapsulation with message m
//!
//! If this test fails, the implementation does NOT match FIPS 203.

use cipherbox_pqc_core::{KemLevel, kem};

const KAT: &str = include_str!("data/ml_kem_kat.txt");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn level(s: &str) -> KemLevel {
    KemLevel::from_param(s.parse().unwrap()).expect("level")
}

#[test]
fn ml_kem_known_answers() {
    let (mut kg, mut dc, mut en) = (0, 0, 0);
    for line in KAT
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        let f: Vec<&str> = line.split_whitespace().collect();
        let lvl = level(f[1]);
        let seed = unhex(f[2]);
        let (mut d, mut z) = ([0u8; 32], [0u8; 32]);
        d.copy_from_slice(&seed[..32]);
        z.copy_from_slice(&seed[32..]);
        let (ek, dk) = kem::keygen_level(lvl, &d, &z);
        assert_eq!(ek.len(), lvl.ek_bytes());
        assert_eq!(dk.len(), lvl.dk_bytes());
        assert!(kem::check_ek_level(lvl, &ek));
        assert!(kem::check_dk_level(lvl, &dk));
        match f[0] {
            "KEYGEN" => {
                assert_eq!(ek, unhex(f[3]), "{} keygen", lvl.name());
                kg += 1;
            }
            "DECAPS" => {
                let ss = kem::decaps_level(lvl, &dk, &unhex(f[3])).unwrap();
                assert_eq!(ss.to_vec(), unhex(f[4]), "{} decaps", lvl.name());
                dc += 1;
            }
            "ENCAPS" => {
                let mut m = [0u8; 32];
                m.copy_from_slice(&unhex(f[3]));
                let (ct, ss) = kem::encaps_level(lvl, &ek, &m).unwrap();
                assert_eq!(ct, unhex(f[4]), "{} encaps ct", lvl.name());
                assert_eq!(ss.to_vec(), unhex(f[5]), "{} encaps ss", lvl.name());
                en += 1;
            }
            other => panic!("unknown record {other}"),
        }
    }
    assert_eq!((kg, dc, en), (6, 12, 6), "expected the full vector set");
}

#[test]
fn legacy_fixed_size_api_matches_generic() {
    let (d, z) = ([7u8; 32], [9u8; 32]);
    let (ek, dk) = kem::keygen(&d, &z);
    let (ek_v, dk_v) = kem::keygen_level(KemLevel::MlKem768, &d, &z);
    assert_eq!(ek.to_vec(), ek_v);
    assert_eq!(dk.to_vec(), dk_v);
    let m = [3u8; 32];
    let (ct, ss) = kem::encaps(&ek, &m);
    assert_eq!(kem::decaps(&dk, &ct), ss);
}

// ---------------------------------------------------------------------------
// File-format known answers. `data/file_kat.txt` holds .cbox files built by an
// independent implementation of the documented format (v1 for ML-KEM-768,
// v2 for ML-KEM-1024). They pin the on-disk format: files written by older
// versions must keep decrypting.
// ---------------------------------------------------------------------------

use cipherbox_pqc_core::file;

const FILE_KAT: &str = include_str!("data/file_kat.txt");

#[test]
fn file_format_known_answers() {
    let mut n = 0;
    for line in FILE_KAT
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        let f: Vec<&str> = line.split_whitespace().collect();
        assert_eq!(f[0], "FILE");
        let lvl = level(f[1]);
        let seed = unhex(f[2]);
        let len: usize = f[4].parse().unwrap();
        let ct = unhex(f[5]);
        let want: Vec<u8> = (0..len).map(|i| ((i * 31 + 7) % 256) as u8).collect();

        // Via the seed (level read from the header)...
        assert_eq!(
            file::decrypt_file_with_seed(&ct, &seed).unwrap(),
            want,
            "{} len {len}",
            lvl.name()
        );

        // ...and via a full decapsulation key of the right level.
        let (mut d, mut z) = ([0u8; 32], [0u8; 32]);
        d.copy_from_slice(&seed[..32]);
        z.copy_from_slice(&seed[32..]);
        let (_ek, dk) = kem::keygen_level(lvl, &d, &z);
        assert_eq!(file::decrypt_file(&ct, &dk).unwrap(), want);

        // Header sanity: v1 for 768, v2 + level id for 1024.
        match lvl {
            KemLevel::MlKem768 => assert_eq!(&ct[..5], b"CBOX\x01"),
            KemLevel::MlKem1024 => assert_eq!(&ct[..6], b"CBOX\x02\x05"),
        }
        n += 1;
    }
    assert_eq!(n, 8);
}
