//! Tests for chunked file encryption.

use cipherbox_pqc_core::file::{
    CHUNK_SIZE_MAX, CHUNK_SIZE_MIN, FileDecryptor, FileEncryptor, HEADER_BYTES, MAGIC, TAG_BYTES,
    VERSION, decrypt_file, encrypt_file,
};
use cipherbox_pqc_core::kem;
use getrandom::getrandom;

fn fresh_keypair() -> ([u8; kem::EK_BYTES], [u8; kem::DK_BYTES]) {
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    getrandom(&mut d).unwrap();
    getrandom(&mut z).unwrap();
    kem::keygen(&d, &z)
}

#[test]
fn roundtrip_empty() {
    let (ek, dk) = fresh_keypair();
    let ct = encrypt_file(b"", &ek, CHUNK_SIZE_MIN).unwrap();
    let pt = decrypt_file(&ct, &dk).unwrap();
    assert_eq!(pt, b"");
}

#[test]
fn roundtrip_short() {
    let (ek, dk) = fresh_keypair();
    let msg = b"hello, chunked file world!";
    let ct = encrypt_file(msg, &ek, CHUNK_SIZE_MIN).unwrap();
    let pt = decrypt_file(&ct, &dk).unwrap();
    assert_eq!(pt, msg);
}

#[test]
fn roundtrip_exact_chunk_size() {
    let (ek, dk) = fresh_keypair();
    let chunk_size = CHUNK_SIZE_MIN;
    let msg = vec![0x42u8; chunk_size];
    let ct = encrypt_file(&msg, &ek, chunk_size).unwrap();
    let pt = decrypt_file(&ct, &dk).unwrap();
    assert_eq!(pt, msg);
}

#[test]
fn roundtrip_one_byte_over_chunk() {
    let (ek, dk) = fresh_keypair();
    let chunk_size = CHUNK_SIZE_MIN;
    let msg = vec![0x37u8; chunk_size + 1];
    let ct = encrypt_file(&msg, &ek, chunk_size).unwrap();
    let pt = decrypt_file(&ct, &dk).unwrap();
    assert_eq!(pt, msg);
}

#[test]
fn roundtrip_multi_chunk() {
    let (ek, dk) = fresh_keypair();
    let chunk_size = CHUNK_SIZE_MIN;
    let msg: Vec<u8> = (0..(3 * chunk_size + 500))
        .map(|i| (i % 256) as u8)
        .collect();
    let ct = encrypt_file(&msg, &ek, chunk_size).unwrap();
    let pt = decrypt_file(&ct, &dk).unwrap();
    assert_eq!(pt, msg);
}

#[test]
fn streaming_matches_oneshot() {
    let (ek, dk) = fresh_keypair();
    let chunk_size = CHUNK_SIZE_MIN;
    let msg: Vec<u8> = (0..1000).map(|i| (i % 256) as u8).collect();

    let oneshot_ct = encrypt_file(&msg, &ek, chunk_size).unwrap();

    let mut enc = FileEncryptor::new(&ek, chunk_size).unwrap();
    let mut streaming_ct = Vec::new();
    enc.update(&msg[..7], &mut streaming_ct).unwrap();
    enc.update(&msg[7..300], &mut streaming_ct).unwrap();
    enc.update(&msg[300..], &mut streaming_ct).unwrap();
    enc.finish(&mut streaming_ct).unwrap();

    assert_eq!(decrypt_file(&oneshot_ct, &dk).unwrap(), msg);
    assert_eq!(decrypt_file(&streaming_ct, &dk).unwrap(), msg);
}

#[test]
fn streaming_all_split_points() {
    let (ek, dk) = fresh_keypair();
    let chunk_size = CHUNK_SIZE_MIN;
    let msg: Vec<u8> = (0..200).map(|i| (i % 256) as u8).collect();

    for split_at in 0..=msg.len() {
        let mut enc = FileEncryptor::new(&ek, chunk_size).unwrap();
        let mut ct = Vec::new();
        enc.update(&msg[..split_at], &mut ct).unwrap();
        enc.update(&msg[split_at..], &mut ct).unwrap();
        enc.finish(&mut ct).unwrap();
        let pt = decrypt_file(&ct, &dk).unwrap();
        assert_eq!(pt, msg, "split_at={split_at}");
    }
}

#[test]
fn wrong_key_fails() {
    let (ek1, _) = fresh_keypair();
    let (_, dk2) = fresh_keypair();
    let ct = encrypt_file(b"secret", &ek1, CHUNK_SIZE_MIN).unwrap();
    assert!(decrypt_file(&ct, &dk2).is_err());
}

#[test]
fn tampered_header_fails() {
    let (ek, dk) = fresh_keypair();
    let ct = encrypt_file(b"payload", &ek, CHUNK_SIZE_MIN).unwrap();
    let mut bad = ct.clone();
    bad[5] ^= 0x01;
    assert!(decrypt_file(&bad, &dk).is_err());
}

#[test]
fn tampered_chunk_fails() {
    let (ek, dk) = fresh_keypair();
    let ct = encrypt_file(
        b"payload that spans at least one chunk",
        &ek,
        CHUNK_SIZE_MIN,
    )
    .unwrap();
    let mut bad = ct.clone();
    bad[HEADER_BYTES + 5] ^= 0x01;
    assert!(decrypt_file(&bad, &dk).is_err());
}

#[test]
fn truncated_ciphertext_fails() {
    let (ek, dk) = fresh_keypair();
    let ct = encrypt_file(b"truncate me please", &ek, CHUNK_SIZE_MIN).unwrap();
    let bad = &ct[..ct.len() - TAG_BYTES];
    assert!(decrypt_file(bad, &dk).is_err());
}

#[test]
fn reordered_chunks_fails() {
    let (ek, dk) = fresh_keypair();
    let chunk_size = CHUNK_SIZE_MIN;
    let msg = vec![0xABu8; 3 * chunk_size];
    let ct = encrypt_file(&msg, &ek, chunk_size).unwrap();
    let ct_full = chunk_size + TAG_BYTES;
    let mut bad = ct.clone();
    let (start, mid, end) = (
        HEADER_BYTES,
        HEADER_BYTES + ct_full,
        HEADER_BYTES + 2 * ct_full,
    );
    let chunk0: Vec<u8> = bad[start..mid].to_vec();
    let chunk1: Vec<u8> = bad[mid..end].to_vec();
    bad[start..mid].copy_from_slice(&chunk1);
    bad[mid..end].copy_from_slice(&chunk0);
    assert!(decrypt_file(&bad, &dk).is_err());
}

#[test]
fn invalid_chunk_size_rejected() {
    let (ek, _) = fresh_keypair();
    assert!(encrypt_file(b"x", &ek, CHUNK_SIZE_MIN - 1).is_err());
    assert!(encrypt_file(b"x", &ek, CHUNK_SIZE_MAX + 1).is_err());
}

#[test]
fn header_magic_and_version() {
    let (ek, _) = fresh_keypair();
    let ct = encrypt_file(b"", &ek, CHUNK_SIZE_MIN).unwrap();
    assert_eq!(&ct[..4], MAGIC);
    assert_eq!(ct[4], VERSION);
    assert!(ct.len() >= HEADER_BYTES + TAG_BYTES);
}

#[test]
fn decryptor_finish_without_data_fails() {
    let (_, dk) = fresh_keypair();
    let dec = FileDecryptor::new(&dk);
    let mut out = Vec::new();
    assert!(dec.finish(&mut out).is_err());
}

#[test]
fn chunk_size_from_header_is_validated() {
    let (ek, dk) = fresh_keypair();
    let ct = encrypt_file(b"x", &ek, CHUNK_SIZE_MIN).unwrap();
    let mut bad = ct.clone();
    let huge = u32::MAX;
    bad[5..9].copy_from_slice(&huge.to_le_bytes());
    assert!(decrypt_file(&bad, &dk).is_err());
}
