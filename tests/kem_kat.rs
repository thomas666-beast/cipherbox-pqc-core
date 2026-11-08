//! Tests for ML-KEM-768 KEM.

use cipherbox_pqc_core::kem::{CT_BYTES, DK_BYTES, EK_BYTES, SS_BYTES, decaps, encaps, keygen};

#[test]
fn kem_roundtrip() {
    let d = [0x42u8; 32];
    let z = [0x24u8; 32];
    let m = [0x55u8; 32];

    let (ek, dk) = keygen(&d, &z);
    let (ct, ss_sender) = encaps(&ek, &m);
    let ss_recipient = decaps(&dk, &ct);

    assert_eq!(ss_sender, ss_recipient);
    assert_eq!(ss_sender.len(), SS_BYTES);
}

#[test]
fn kem_sizes() {
    assert_eq!(EK_BYTES, 1184);
    assert_eq!(DK_BYTES, 2400);
    assert_eq!(CT_BYTES, 1088);
    assert_eq!(SS_BYTES, 32);
}

#[test]
fn kem_roundtrip_multi() {
    let d = [0xA5u8; 32];
    let z = [0x5Au8; 32];
    let (ek, dk) = keygen(&d, &z);

    for trial in 0..5u8 {
        let mut m = [0u8; 32];
        for (k, byte) in m.iter_mut().enumerate() {
            *byte = (trial.wrapping_mul(37)).wrapping_add(k as u8);
        }
        let (ct, ss1) = encaps(&ek, &m);
        let ss2 = decaps(&dk, &ct);
        assert_eq!(ss1, ss2, "failed at trial {trial}");
    }
}

#[test]
fn kem_deterministic() {
    let d = [0x11u8; 32];
    let z = [0x22u8; 32];
    let m = [0x33u8; 32];

    let (ek1, dk1) = keygen(&d, &z);
    let (ek2, dk2) = keygen(&d, &z);
    assert_eq!(ek1, ek2);
    assert_eq!(dk1, dk2);

    let (ct1, ss1) = encaps(&ek1, &m);
    let (ct2, ss2) = encaps(&ek2, &m);
    assert_eq!(ct1, ct2);
    assert_eq!(ss1, ss2);
}

#[test]
fn kem_implicit_rejection() {
    // Corrupting the ciphertext must produce a shared secret that is
    // different from the sender's, but the function must not panic and
    // must return a 32-byte value (implicit rejection).
    let d = [0x99u8; 32];
    let z = [0x77u8; 32];
    let m = [0xAAu8; 32];

    let (ek, dk) = keygen(&d, &z);
    let (ct, ss_sender) = encaps(&ek, &m);

    let mut tampered = ct;
    tampered[0] ^= 0x01;

    let ss_recipient = decaps(&dk, &tampered);
    assert_ne!(
        ss_recipient, ss_sender,
        "tampered ciphertext must not decrypt"
    );
    assert_eq!(ss_recipient.len(), SS_BYTES);
}

#[test]
fn kem_different_messages_different_secrets() {
    let d = [0x01u8; 32];
    let z = [0x02u8; 32];
    let (ek, _) = keygen(&d, &z);

    let m1 = [0u8; 32];
    let m2 = [0xFFu8; 32];
    let (_, ss1) = encaps(&ek, &m1);
    let (_, ss2) = encaps(&ek, &m2);
    assert_ne!(ss1, ss2);
}

#[test]
fn kem_wrong_key_implicit_rejection() {
    // Encapsulate under one key, decapsulate under a different key.
    // Must produce a mismatch, not a panic.
    let d1 = [0x10u8; 32];
    let z1 = [0x11u8; 32];
    let d2 = [0x20u8; 32];
    let z2 = [0x21u8; 32];
    let m = [0x55u8; 32];

    let (ek1, _dk1) = keygen(&d1, &z1);
    let (_ek2, dk2) = keygen(&d2, &z2);

    let (ct, ss_sender) = encaps(&ek1, &m);
    let ss_recipient = decaps(&dk2, &ct);
    assert_ne!(ss_recipient, ss_sender);
}
