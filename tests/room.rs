//! Tests for secret-derived rooms: derivation, ratchet, signatures, rekey,
//! state persistence. `data/room_kat.txt` comes from an independent Python
//! model (Argon2id checked against RFC 9106, SHA3 and ChaCha20-Poly1305 from
//! standard libraries). Run with `--release`: the KAT includes the 64 MiB
//! default Argon2 parameters.

use cipherbox_pqc_core::room::{
    self, MAX_SKIP, PAD_BLOCK, RekeyBundle, Room, RoomKdfParams, RoomSecret, auth_verifier,
    next_epoch_key,
};
use cipherbox_pqc_core::{
    HybridKeyPair, KemLevel, MlDsa87KeyPair, MlDsaKeyPair, MlKemKeyPair, ml_dsa_verify,
};

const KAT: &str = include_str!("data/room_kat.txt");
const FAST: RoomKdfParams = RoomKdfParams::new(32, 1, 1);

fn unhex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn arr32(s: &str) -> [u8; 32] {
    let mut a = [0u8; 32];
    a.copy_from_slice(&unhex(s));
    a
}

#[allow(dead_code)]
fn arr16(s: &str) -> [u8; 16] {
    let mut a = [0u8; 16];
    a.copy_from_slice(&unhex(s));
    a
}

fn secret(tag: &str) -> RoomSecret {
    RoomSecret::derive("test-room", &[tag.as_bytes(), b"second source"], FAST).unwrap()
}

fn member(s: &RoomSecret, id: u8) -> Room {
    Room::join_with_sender_id(s, [id; 16])
}

// ---------------- known answers ----------------

#[test]
fn room_known_answers() {
    let (mut rooms, mut epochs, mut msgs) = (0, 0, 0);
    let mut receiver: Option<Room> = None;
    for line in KAT
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        let f: Vec<&str> = line.split_whitespace().collect();
        match f[0] {
            "ROOM" => {
                let ctx = if f[1] == "-" { "" } else { f[1] };
                let params = RoomKdfParams::new(
                    f[2].parse().unwrap(),
                    f[3].parse().unwrap(),
                    f[4].parse().unwrap(),
                );
                let n: usize = f[5].parse().unwrap();
                let sources: Vec<Vec<u8>> = f[6..6 + n].iter().map(|h| unhex(h)).collect();
                let refs: Vec<&[u8]> = sources.iter().map(|v| v.as_slice()).collect();
                assert_eq!(f[6 + n], "=>");
                let s = RoomSecret::derive(ctx, &refs, params).unwrap();
                assert_eq!(s.room_id(), arr32(f[7 + n]), "room_id ({ctx})");
                assert_eq!(s.auth_token(), arr32(f[8 + n]), "auth ({ctx})");
                assert_eq!(
                    auth_verifier(&s.auth_token()),
                    arr32(f[9 + n]),
                    "verifier ({ctx})"
                );
                assert_eq!(s.epoch0_key(), arr32(f[10 + n]), "epoch0 ({ctx})");
                // The order of sources must not matter.
                let mut rev = refs.clone();
                rev.reverse();
                let s2 = RoomSecret::derive(ctx, &rev, params).unwrap();
                assert_eq!(s.root_bytes(), s2.root_bytes());
                rooms += 1;
            }
            "EPOCHNEXT" => {
                let got = next_epoch_key(&arr32(f[1]), &arr32(f[2]), f[3].parse().unwrap());
                assert_eq!(got, arr32(f[5]));
                epochs += 1;
            }
            "CTX" => {
                receiver = Some(Room::from_keys(
                    arr32(f[1]),
                    f[3].parse().unwrap(),
                    arr32(f[2]),
                    [0xEE; 16],
                ));
            }
            "MSG" => {
                let signed = f[2] == "1";
                let want = unhex(f[3]);
                let env = unhex(f[5]);
                let o = receiver.as_mut().unwrap().open(&env, None).unwrap();
                assert_eq!(o.plaintext, want, "message index {}", f[1]);
                assert_eq!(o.index, f[1].parse::<u32>().unwrap());
                assert_eq!(o.signed, signed);
                msgs += 1;
            }
            other => panic!("unknown record {other}"),
        }
    }
    assert_eq!(
        (rooms, epochs, msgs),
        (4, 2, 8),
        "expected the full vector set"
    );
}

// ---------------- derivation ----------------

#[test]
fn derivation_properties() {
    let a = RoomSecret::derive("c", &[b"one", b"two"], FAST).unwrap();
    let b = RoomSecret::derive("c", &[b"two", b"one"], FAST).unwrap();
    assert_eq!(a.room_id(), b.room_id());

    assert_ne!(
        a.room_id(),
        RoomSecret::derive("c2", &[b"one", b"two"], FAST)
            .unwrap()
            .room_id()
    );
    assert_ne!(
        a.room_id(),
        RoomSecret::derive("c", &[b"one", b"twp"], FAST)
            .unwrap()
            .room_id()
    );
    assert_ne!(
        a.room_id(),
        RoomSecret::derive("c", &[b"one"], FAST).unwrap().room_id()
    );
    assert_ne!(
        a.room_id(),
        RoomSecret::derive("c", &[b"one", b"two"], RoomKdfParams::new(32, 2, 1))
            .unwrap()
            .room_id()
    );

    // room id, auth token and epoch key are unrelated values
    let ids = [a.room_id(), a.auth_token(), a.epoch0_key()];
    assert!(ids[0] != ids[1] && ids[1] != ids[2] && ids[0] != ids[2]);
    assert_ne!(&ids[0], a.root_bytes());
    assert_ne!(auth_verifier(&a.auth_token()), a.auth_token());

    let r = RoomSecret::from_root(*a.root_bytes());
    assert_eq!(r.room_id(), a.room_id());
}

#[test]
fn derivation_input_validation() {
    assert!(RoomSecret::derive("c", &[], FAST).is_err());
    assert!(RoomSecret::derive("c", &[b""], FAST).is_err());
    let many: Vec<&[u8]> = vec![b"x".as_slice(); 17];
    assert!(RoomSecret::derive("c", &many, FAST).is_err());
    assert!(RoomSecret::derive("c", &[b"x"], RoomKdfParams::new(32, 0, 1)).is_err());
    assert!(RoomSecret::derive("c", &[b"x"], RoomKdfParams::new(u32::MAX, 1, 1)).is_err());
}

// ---------------- messaging ----------------

#[test]
fn two_members_exchange_messages() {
    let s = secret("a");
    let (mut alice, mut bob) = (member(&s, 1), member(&s, 2));
    for i in 0..5u8 {
        let env = alice.seal(&[i; 10]).unwrap();
        let o = bob.open(&env, None).unwrap();
        assert_eq!(o.plaintext, vec![i; 10]);
        assert_eq!(o.sender_id, [1; 16]);
        assert_eq!(o.index, i as u32);
        assert!(!o.signed);
        let back = bob.seal(b"pong").unwrap();
        assert_eq!(alice.open(&back, None).unwrap().plaintext, b"pong");
    }
}

#[test]
fn random_sender_ids_differ() {
    let s = secret("a");
    let (a, b) = (Room::join(&s).unwrap(), Room::join(&s).unwrap());
    assert_ne!(a.sender_id(), b.sender_id());
    assert_eq!(a.room_id(), b.room_id());
    assert_eq!(a.room_id(), &s.room_id());
}

#[test]
fn other_secret_cannot_read_or_join() {
    let (mut alice, mut eve) = (member(&secret("a"), 1), member(&secret("b"), 3));
    let env = alice.seal(b"secret").unwrap();
    assert!(eve.open(&env, None).is_err()); // different room id
    // Even forcing the same room id, the keys differ.
    let mut eve2 = Room::from_keys(*alice.room_id(), 0, [9u8; 32], [3; 16]);
    assert!(eve2.open(&env, None).is_err());
}

#[test]
fn replay_and_reordering() {
    let s = secret("a");
    let (mut alice, mut bob) = (member(&s, 1), member(&s, 2));
    let envs: Vec<Vec<u8>> = (0..6u8).map(|i| alice.seal(&[i]).unwrap()).collect();
    // deliver out of order: 0, 3, 1, 5, 2, 4
    for &i in &[0usize, 3, 1, 5, 2, 4] {
        assert_eq!(bob.open(&envs[i], None).unwrap().plaintext, vec![i as u8]);
    }
    // every replay is rejected
    for e in &envs {
        assert!(bob.open(e, None).is_err());
    }
}

#[test]
fn skip_limit_and_failed_auth_does_not_burn_keys() {
    let s = secret("a");
    let (mut alice, mut bob) = (member(&s, 1), member(&s, 2));
    let first = alice.seal(b"first").unwrap();

    // A forged envelope with a huge index (valid framing, bad tag) must not
    // advance bob's chain.
    let mut forged = first.clone();
    forged[58..62].copy_from_slice(&500u32.to_le_bytes());
    assert!(bob.open(&forged, None).is_err());
    assert_eq!(bob.open(&first, None).unwrap().plaintext, b"first");

    // Real messages beyond the skip window are refused.
    let mut last = Vec::new();
    for _ in 0..(MAX_SKIP + 2) {
        last = alice.seal(b"x").unwrap();
    }
    assert!(bob.open(&last, None).is_err());
}

#[test]
fn tampering_is_detected() {
    let s = secret("a");
    let (mut alice, mut bob) = (member(&s, 1), member(&s, 2));
    let env = alice.seal(b"integrity").unwrap();
    // flip one bit at representative positions: magic, version, flags, room id,
    // epoch, sender, index, ct_len, ciphertext, tag
    for pos in [0usize, 4, 5, 6, 38, 42, 58, 62, 70, 100, env.len() - 1] {
        let mut bad = env.clone();
        bad[pos] ^= 0x01;
        assert!(
            bob.open(&bad, None).is_err(),
            "flip at byte {pos} was accepted"
        );
    }
    assert!(bob.open(&env[..env.len() - 1], None).is_err());
    let mut longer = env.clone();
    longer.push(0);
    assert!(bob.open(&longer, None).is_err());
    assert!(bob.open(&[], None).is_err());
    // none of the above consumed the real message
    assert_eq!(bob.open(&env, None).unwrap().plaintext, b"integrity");
}

#[test]
fn own_messages_are_not_reopened() {
    let s = secret("a");
    let mut alice = member(&s, 1);
    let env = alice.seal(b"hi").unwrap();
    assert!(alice.open(&env, None).is_err());
}

#[test]
fn padding_hides_length() {
    let s = secret("a");
    let mut alice = member(&s, 1);
    let l = |n: usize, r: &mut Room| r.seal(&vec![7u8; n]).unwrap().len();
    let (a, b) = (l(0, &mut alice), l(100, &mut alice));
    assert_eq!(a, b);
    assert_eq!(l(252, &mut alice), a); // 4 + 252 == 256
    assert_eq!(l(253, &mut alice), a + PAD_BLOCK);
    assert_eq!(l(600, &mut alice), a + 2 * PAD_BLOCK);
    assert!(alice.seal(&vec![0u8; room::MAX_MESSAGE_BYTES + 1]).is_err());
}

// ---------------- signatures ----------------

#[test]
fn signed_messages_ml_dsa_65_and_87() {
    let s = secret("a");
    let (mut alice, mut bob) = (member(&s, 1), member(&s, 2));
    let dsa65 = MlDsaKeyPair::new();
    let (_, vk65) = dsa65.export_keys();

    let env = alice
        .seal_signed(b"signed", &|m: &[u8]| dsa65.sign(m))
        .unwrap();
    let ok = |m: &[u8], sig: &[u8]| ml_dsa_verify(&vk65, m, sig);
    let o = bob.open(&env, Some(&ok)).unwrap();
    assert_eq!(o.plaintext, b"signed");
    assert!(o.signed);

    // wrong key rejected; unsigned message rejected when a verifier is required
    let other = MlDsaKeyPair::new();
    let (_, vk_other) = other.export_keys();
    let env2 = alice
        .seal_signed(b"two", &|m: &[u8]| dsa65.sign(m))
        .unwrap();
    let bad = |m: &[u8], sig: &[u8]| ml_dsa_verify(&vk_other, m, sig);
    assert!(bob.open(&env2, Some(&bad)).is_err());
    let plain = alice.seal(b"unsigned").unwrap();
    assert!(bob.open(&plain, Some(&ok)).is_err());

    // those failures left the state intact
    assert_eq!(bob.open(&env2, Some(&ok)).unwrap().plaintext, b"two");
    assert_eq!(bob.open(&plain, None).unwrap().plaintext, b"unsigned");

    // flipping a signature byte or a ciphertext byte breaks verification
    let env3 = alice
        .seal_signed(b"three", &|m: &[u8]| dsa65.sign(m))
        .unwrap();
    let mut t1 = env3.clone();
    let n = t1.len();
    t1[n - 5] ^= 1;
    assert!(bob.open(&t1, Some(&ok)).is_err());
    let mut t2 = env3.clone();
    t2[100] ^= 1;
    assert!(bob.open(&t2, Some(&ok)).is_err());
    assert_eq!(bob.open(&env3, Some(&ok)).unwrap().plaintext, b"three");

    // ML-DSA-87 works the same way
    let dsa87 = MlDsa87KeyPair::new();
    let (_, vk87) = dsa87.export_keys();
    let env4 = alice.seal_signed(b"87", &|m: &[u8]| dsa87.sign(m)).unwrap();
    let ok87 = |m: &[u8], sig: &[u8]| ml_dsa_verify(&vk87, m, sig);
    assert_eq!(bob.open(&env4, Some(&ok87)).unwrap().plaintext, b"87");
    assert!(!ml_dsa_verify(&[0u8; 10], b"m", b"s"));
}

// ---------------- epochs and rekey ----------------

fn sign_with(dsa: &MlDsaKeyPair) -> impl Fn(&[u8]) -> Vec<u8> + '_ {
    move |m| dsa.sign(m)
}

#[test]
fn rekey_gives_post_compromise_security() {
    let s = secret("leaky passphrase");
    let (mut alice, mut bob, mut carol) = (member(&s, 1), member(&s, 2), member(&s, 3));
    // Attacker who learned the root secret (e.g. stolen passphrase) and records traffic.
    let mut eve = member(&RoomSecret::from_root(*s.root_bytes()), 9);

    let bob_k = HybridKeyPair::new(KemLevel::MlKem768).unwrap();
    let carol_k = MlKemKeyPair::new_with_level(KemLevel::MlKem1024).unwrap(); // mixed key types
    let alice_dsa = MlDsaKeyPair::new();
    let (_, alice_vk) = alice_dsa.export_keys();

    let e0 = alice.seal(b"epoch zero").unwrap();
    assert_eq!(eve.open(&e0, None).unwrap().plaintext, b"epoch zero"); // root alone suffices at epoch 0
    assert_eq!(bob.open(&e0, None).unwrap().plaintext, b"epoch zero");
    carol.open(&e0, None).unwrap();

    let bundle = alice
        .rekey(
            &[bob_k.public_key(), carol_k.encapsulation_key()],
            &sign_with(&alice_dsa),
        )
        .unwrap();
    assert_eq!(bundle.epoch, 1);
    assert_eq!(alice.epoch(), 1);

    let trusted = |m: &[u8], sig: &[u8]| ml_dsa_verify(&alice_vk, m, sig);
    bob.apply_rekey(&bundle, &bob_k, &trusted).unwrap();
    carol.apply_rekey(&bundle, &carol_k, &trusted).unwrap();
    assert_eq!((bob.epoch(), carol.epoch()), (1, 1));

    let e1 = alice.seal(b"epoch one").unwrap();
    assert_eq!(bob.open(&e1, None).unwrap().plaintext, b"epoch one");
    assert_eq!(carol.open(&e1, None).unwrap().plaintext, b"epoch one");
    let b1 = bob.seal(b"from bob").unwrap();
    assert_eq!(carol.open(&b1, None).unwrap().plaintext, b"from bob");
    assert_eq!(alice.open(&b1, None).unwrap().plaintext, b"from bob");

    // Eve knows the root but not the members' KEM keys: epoch 1 stays closed.
    assert!(eve.open(&e1, None).is_err());
    assert!(eve.open(&b1, None).is_err());
}

#[test]
fn rekey_requires_a_trusted_signature_and_correct_order() {
    let s = secret("a");
    let (mut alice, mut bob) = (member(&s, 1), member(&s, 2));
    let bob_k = HybridKeyPair::new(KemLevel::MlKem768).unwrap();
    let alice_dsa = MlDsaKeyPair::new();
    let (_, alice_vk) = alice_dsa.export_keys();
    let mallory_dsa = MlDsaKeyPair::new();
    let (_, mallory_vk) = mallory_dsa.export_keys();

    // Anyone holding the room secret can build a bundle, but not a trusted signature.
    let mut mallory = member(&s, 4);
    let evil = mallory
        .rekey(&[bob_k.public_key()], &sign_with(&mallory_dsa))
        .unwrap();
    let trusted = |m: &[u8], sig: &[u8]| ml_dsa_verify(&alice_vk, m, sig);
    assert!(bob.apply_rekey(&evil, &bob_k, &trusted).is_err());
    assert_eq!(bob.epoch(), 0);
    // ...whereas a verifier that trusts Mallory would accept it (policy is the caller's).
    let trusts_mallory = |m: &[u8], sig: &[u8]| ml_dsa_verify(&mallory_vk, m, sig);
    assert!(bob.apply_rekey(&evil, &bob_k, &trusts_mallory).is_ok());

    let mut bob2 = member(&s, 5);
    let good = alice
        .rekey(&[bob_k.public_key()], &sign_with(&alice_dsa))
        .unwrap();
    // tampering with the bundle invalidates the signature
    let mut forged = good.clone();
    forged.entries[0].wrapped[10] ^= 1;
    assert!(bob2.apply_rekey(&forged, &bob_k, &trusted).is_err());
    let mut wrong_room = good.clone();
    wrong_room.room_id[0] ^= 1;
    assert!(bob2.apply_rekey(&wrong_room, &bob_k, &trusted).is_err());

    // no entry for a stranger's key
    let stranger = HybridKeyPair::new(KemLevel::MlKem768).unwrap();
    assert!(bob2.apply_rekey(&good, &stranger, &trusted).is_err());

    bob2.apply_rekey(&good, &bob_k, &trusted).unwrap();
    // replaying / skipping epochs is refused
    assert!(bob2.apply_rekey(&good, &bob_k, &trusted).is_err());
    let mut skip = good.clone();
    skip.epoch = 5;
    assert!(bob2.apply_rekey(&skip, &bob_k, &trusted).is_err());
}

#[test]
fn rekey_input_validation_leaves_state_untouched() {
    let s = secret("a");
    let mut alice = member(&s, 1);
    let dsa = MlDsaKeyPair::new();
    assert!(alice.rekey(&[], &sign_with(&dsa)).is_err());
    assert!(alice.rekey(&[&[0u8; 7][..]], &sign_with(&dsa)).is_err());
    assert!(
        alice
            .rekey(
                &[HybridKeyPair::new(KemLevel::MlKem768).unwrap().public_key()],
                &|_m: &[u8]| Vec::new()
            )
            .is_err()
    );
    assert_eq!(alice.epoch(), 0);
}

#[test]
fn bundle_serialization_roundtrip() {
    let s = secret("a");
    let mut alice = member(&s, 1);
    let dsa = MlDsaKeyPair::new();
    let k = MlKemKeyPair::new().unwrap();
    let bundle = alice
        .rekey(&[k.encapsulation_key()], &sign_with(&dsa))
        .unwrap();
    let bytes = bundle.to_bytes();
    assert_eq!(RekeyBundle::from_bytes(&bytes).unwrap(), bundle);
    assert!(RekeyBundle::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    let mut more = bytes.clone();
    more.push(0);
    assert!(RekeyBundle::from_bytes(&more).is_err());
    assert!(RekeyBundle::from_bytes(b"nope").is_err());
}

#[test]
fn forgetting_old_epochs_gives_forward_secrecy() {
    let s = secret("a");
    let (mut alice, mut bob) = (member(&s, 1), member(&s, 2));
    let bob_k = MlKemKeyPair::new().unwrap();
    let dsa = MlDsaKeyPair::new();
    let (_, vk) = dsa.export_keys();
    let trusted = |m: &[u8], sig: &[u8]| ml_dsa_verify(&vk, m, sig);

    let old = alice.seal(b"old epoch").unwrap(); // not yet delivered to bob
    let bundle = alice
        .rekey(&[bob_k.encapsulation_key()], &sign_with(&dsa))
        .unwrap();
    bob.apply_rekey(&bundle, &bob_k, &trusted).unwrap();

    // in-flight messages of the previous epoch still open until it is forgotten
    let mut bob_copy = Room::import_state(&bob.export_state()).unwrap();
    assert_eq!(bob.open(&old, None).unwrap().plaintext, b"old epoch");

    bob_copy.forget_epochs_before(1);
    assert!(bob_copy.open(&old, None).is_err());
    // the current epoch cannot be forgotten
    bob_copy.forget_epochs_before(99);
    assert_eq!(bob_copy.epoch(), 1);
    let fresh = alice.seal(b"new").unwrap();
    assert_eq!(bob_copy.open(&fresh, None).unwrap().plaintext, b"new");
}

// ---------------- persistence ----------------

#[test]
fn state_export_import_preserves_ratchets_and_skipped_keys() {
    let s = secret("a");
    let (mut alice, mut bob) = (member(&s, 1), member(&s, 2));
    let envs: Vec<Vec<u8>> = (0..4u8).map(|i| alice.seal(&[i]).unwrap()).collect();
    bob.open(&envs[3], None).unwrap(); // skips 0, 1, 2

    let mut bob2 = Room::import_state(&bob.export_state()).unwrap();
    assert_eq!(bob2.sender_id(), bob.sender_id());
    for i in [1usize, 0, 2] {
        assert_eq!(bob2.open(&envs[i], None).unwrap().plaintext, vec![i as u8]);
    }
    assert!(bob2.open(&envs[3], None).is_err()); // already received

    // the sending chain continues where it left off
    let m1 = bob.seal(b"before").unwrap();
    let mut bob3 = Room::import_state(&bob.export_state()).unwrap();
    let m2 = bob3.seal(b"after").unwrap();
    assert_eq!(alice.open(&m1, None).unwrap().index, 0);
    assert_eq!(alice.open(&m2, None).unwrap().index, 1);
}

#[test]
fn state_import_rejects_garbage() {
    let s = secret("a");
    let bytes = member(&s, 1).export_state();
    assert!(Room::import_state(&bytes[..bytes.len() - 1]).is_err());
    let mut more = bytes.clone();
    more.push(0);
    assert!(Room::import_state(&more).is_err());
    let mut bad = bytes.clone();
    bad[0] = b'X';
    assert!(Room::import_state(&bad).is_err());
    assert!(Room::import_state(&[]).is_err());
    // current epoch must be present among the epoch keys
    let mut bad_epoch = bytes.clone();
    bad_epoch[4 + 1 + 32 + 16..4 + 1 + 32 + 16 + 4].copy_from_slice(&7u32.to_le_bytes());
    assert!(Room::import_state(&bad_epoch).is_err());
}
