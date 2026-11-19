use cipherbox_pqc_core::file::{
    FileDecryptor, FileEncryptor, HEADER_BYTES, TAG_BYTES, decrypt_file, encrypt_file,
};
use cipherbox_pqc_core::room::{RekeyBundle, Room, RoomSecret};
use cipherbox_pqc_core::{MlDsa87KeyPair, MlDsaKeyPair, MlKemKeyPair, ml_dsa_verify};

#[test]
fn verifies_pinned_sender_and_key_without_consuming_failed_messages() {
    let secret = RoomSecret::generate().unwrap();
    let (mut sender, mut receiver) = (Room::join(&secret).unwrap(), Room::join(&secret).unwrap());
    assert_ne!(secret.room_id(), RoomSecret::generate().unwrap().room_id());
    let dsa = MlDsa87KeyPair::new();
    let (_, vk) = dsa.export_keys();
    let (_, other_vk) = MlDsa87KeyPair::new().export_keys();
    let sender_id = *sender.sender_id();
    let signed = sender.seal_signed(b"hello", &|m| dsa.sign(m)).unwrap();
    let unsigned = sender.seal(b"unsigned").unwrap();
    assert!(receiver.open_from(&signed, &[0; 16], &vk).is_err());
    assert!(receiver.open_from(&signed, &sender_id, &other_vk).is_err());
    assert!(receiver.open_from(&unsigned, &sender_id, &vk).is_err());
    let opened = receiver.open_from(&signed, &sender_id, &vk).unwrap();
    assert!(opened.signed && opened.signature_verified);
    assert_eq!(opened.plaintext, b"hello");
    assert!(receiver.open_from(&signed, &sender_id, &vk).is_err());
    let another = sender.seal_signed(b"unchecked", &|m| dsa.sign(m)).unwrap();
    let opened = receiver.open(&another, None).unwrap();
    assert!(opened.signed && !opened.signature_verified);
}

#[test]
fn authenticated_snapshots_are_room_bound_and_restore_distinct_send_chains() {
    let secret = RoomSecret::generate().unwrap();
    let (mut room, mut peer) = (Room::join(&secret).unwrap(), Room::join(&secret).unwrap());
    let e0 = peer.seal(b"skipped").unwrap();
    let e1 = peer.seal(b"seen").unwrap();
    room.open(&e1, None).unwrap();
    let key = [42; 32];
    let id = *room.room_id();
    let state = room.export_encrypted_state(&key).unwrap();
    assert_ne!(state, room.export_encrypted_state(&key).unwrap());
    let mut a = Room::restore_encrypted_state(&state, &key, &id, 0).unwrap();
    let mut b = Room::restore_encrypted_state(&state, &key, &id, 0).unwrap();
    assert_ne!(a.sender_id(), room.sender_id());
    assert_ne!(a.sender_id(), b.sender_id());
    assert_eq!(a.open(&e0, None).unwrap().plaintext, b"skipped");
    assert!(a.open(&e1, None).is_err());
    let first = a.seal(b"a").unwrap();
    let second = b.seal(b"b").unwrap();
    let first = peer.open(&first, None).unwrap();
    let second = peer.open(&second, None).unwrap();
    assert_eq!((first.index, second.index), (0, 0));
    assert_ne!(first.sender_id, second.sender_id);
    assert!(Room::restore_encrypted_state(&state, &[0; 32], &id, 0).is_err());
    assert!(Room::restore_encrypted_state(&state, &key, &[0; 32], 0).is_err());
    assert!(Room::restore_encrypted_state(&state, &key, &id, 1).is_err());
    let mut tampered = state.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(Room::restore_encrypted_state(&tampered, &key, &id, 0).is_err());
    assert!(Room::restore_encrypted_state(&state[..state.len() - 1], &key, &id, 0).is_err());
}

#[test]
fn malformed_rekeys_are_rejected_without_changing_epoch() {
    let secret = RoomSecret::generate().unwrap();
    let (mut a, mut b) = (Room::join(&secret).unwrap(), Room::join(&secret).unwrap());
    let recipient = MlKemKeyPair::new().unwrap();
    let pk = recipient.encapsulation_key();
    let signer = MlDsaKeyPair::new();
    let (_, vk) = signer.export_keys();
    assert!(a.rekey(&[pk, pk], &|m| signer.sign(m)).is_err());
    assert_eq!(a.epoch(), 0);
    let bundle = a.rekey(&[pk], &|m| signer.sign(m)).unwrap();
    let mut duplicate = bundle.clone();
    duplicate.entries.push(duplicate.entries[0].clone());
    let mut malformed = bundle.clone();
    malformed.entries[0].wrapped.clear();
    let mut empty = bundle.clone();
    empty.signature.clear();
    for invalid in [duplicate, malformed, empty] {
        assert!(RekeyBundle::from_bytes(&invalid.to_bytes()).is_err());
        assert!(
            b.apply_rekey(&invalid, &recipient, &|_, _| panic!(
                "malformed shape must be rejected first"
            ))
            .is_err()
        );
    }
    assert_eq!(b.epoch(), 0);
    b.apply_rekey(&bundle, &recipient, &|m, sig| ml_dsa_verify(&vk, m, sig))
        .unwrap();
    assert_eq!(b.epoch(), 1);
}

#[test]
fn mldsa_import_rejects_mismatched_verifying_keys() {
    let (seed, mut vk) = MlDsaKeyPair::new().export_keys();
    assert!(MlDsaKeyPair::import_keys(&seed, &vk).is_ok());
    vk[0] ^= 1;
    assert!(MlDsaKeyPair::import_keys(&seed, &vk).is_err());
    let (seed, mut vk) = MlDsa87KeyPair::new().export_keys();
    assert!(MlDsa87KeyPair::import_keys(&seed, &vk).is_ok());
    vk[0] ^= 1;
    assert!(MlDsa87KeyPair::import_keys(&seed, &vk).is_err());
}

#[test]
fn file_stream_handles_large_and_mixed_updates_at_both_chunk_limits() {
    let k = MlKemKeyPair::new().unwrap();
    let plaintext: Vec<u8> = (0..(2 * 1024 * 1024 + 123))
        .map(|i| (i % 251) as u8)
        .collect();
    for chunk_size in [64, 1024 * 1024] {
        let mut encrypt = FileEncryptor::new(k.encapsulation_key(), chunk_size).unwrap();
        let mut ciphertext = Vec::new();
        encrypt.update(&plaintext[..7], &mut ciphertext).unwrap();
        encrypt.update(&plaintext[7..], &mut ciphertext).unwrap();
        encrypt.finish(&mut ciphertext).unwrap();
        assert_eq!(
            decrypt_file(&ciphertext, k.decapsulation_key()).unwrap(),
            plaintext
        );

        let mut decrypt = FileDecryptor::new(k.decapsulation_key()).unwrap();
        let mut output = Vec::new();
        for input in [
            &ciphertext[..5],
            &ciphertext[5..HEADER_BYTES + 13],
            &ciphertext[HEADER_BYTES + 13..],
        ] {
            decrypt.update(input, &mut output).unwrap();
        }
        decrypt.finish(&mut output).unwrap();
        assert_eq!(output, plaintext);
    }
}

#[test]
fn failed_file_update_discards_this_calls_output_and_cannot_continue() {
    let k = MlKemKeyPair::new().unwrap();
    let mut ciphertext = encrypt_file(&[7; 256], k.encapsulation_key(), 64).unwrap();
    ciphertext[HEADER_BYTES + (64 + TAG_BYTES) + 3] ^= 1;
    let mut decrypt = FileDecryptor::new(k.decapsulation_key()).unwrap();
    let mut output = b"unchanged".to_vec();
    assert!(decrypt.update(&ciphertext, &mut output).is_err());
    assert_eq!(output, b"unchanged");
    assert!(decrypt.update(&[], &mut output).is_err());
    assert!(decrypt.finish(&mut output).is_err());
    assert_eq!(output, b"unchanged");
}
