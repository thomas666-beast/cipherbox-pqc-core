//! Tests for the IND-CPA PKE (K-PKE).

use cipherbox_pqc_core::pke::{pke_decrypt, pke_encrypt, pke_keygen};

#[test]
fn pke_roundtrip() {
    let d = [0x42u8; 32];
    let m = [0x55u8; 32];
    let r = [0x77u8; 32];

    let (ek, dk) = pke_keygen(&d);
    let c = pke_encrypt(&ek, &m, &r);
    let m_recovered = pke_decrypt(&dk, &c);

    assert_eq!(m_recovered, m);
}

#[test]
fn pke_roundtrip_multi() {
    let d = [0xA5u8; 32];
    let (ek, dk) = pke_keygen(&d);

    for trial in 0..10u8 {
        let mut m = [0u8; 32];
        let mut r = [0u8; 32];
        for k in 0..32 {
            m[k] = (trial.wrapping_mul(31).wrapping_add(k as u8)) ^ 0x5A;
            r[k] = (trial.wrapping_mul(17).wrapping_add(k as u8)).wrapping_add(0x80);
        }
        let c = pke_encrypt(&ek, &m, &r);
        let recovered = pke_decrypt(&dk, &c);
        assert_eq!(recovered, m, "failed at trial {trial}");
    }
}

#[test]
fn pke_deterministic() {
    let d = [0x42u8; 32];
    let m = [0x55u8; 32];
    let r = [0x77u8; 32];

    let (ek1, dk1) = pke_keygen(&d);
    let (ek2, dk2) = pke_keygen(&d);
    assert_eq!(ek1, ek2, "keygen not deterministic");
    assert_eq!(dk1, dk2, "keygen not deterministic");

    let c1 = pke_encrypt(&ek1, &m, &r);
    let c2 = pke_encrypt(&ek2, &m, &r);
    assert_eq!(c1, c2, "encrypt not deterministic");
}

#[test]
fn pke_all_zero_message() {
    let d = [0x11u8; 32];
    let m = [0u8; 32];
    let r = [0x22u8; 32];

    let (ek, dk) = pke_keygen(&d);
    let c = pke_encrypt(&ek, &m, &r);
    let recovered = pke_decrypt(&dk, &c);
    assert_eq!(recovered, m);
}

#[test]
fn pke_all_ones_message() {
    let d = [0x33u8; 32];
    let m = [0xFFu8; 32];
    let r = [0x44u8; 32];

    let (ek, dk) = pke_keygen(&d);
    let c = pke_encrypt(&ek, &m, &r);
    let recovered = pke_decrypt(&dk, &c);
    assert_eq!(recovered, m);
}

#[test]
fn pke_ciphertext_wrong_key_different_message() {
    // Encrypting two different messages under the same key produces
    // different ciphertexts.
    let d = [0x99u8; 32];
    let r = [0xAAu8; 32];
    let (ek, _) = pke_keygen(&d);

    let m1 = [0x00u8; 32];
    let m2 = [0xFFu8; 32];
    let c1 = pke_encrypt(&ek, &m1, &r);
    let c2 = pke_encrypt(&ek, &m2, &r);
    assert_ne!(c1, c2, "different messages gave same ciphertext");
}
