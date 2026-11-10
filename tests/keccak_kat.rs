//! Keccak known-answer tests. Vectors in `data/keccak_kat.txt` were produced
//! with Python's `hashlib` (an independent implementation); inputs are
//! `bytes[(i * 7 + 3) % 256 for i in 0..len]`, which exercises every
//! rate-boundary case for absorb and multi-block squeeze.

use cipherbox_pqc_core::keccak::{sha3_256, sha3_512, shake_128, shake_256};
use hex_literal::hex;

const KAT: &str = include_str!("data/keccak_kat.txt");

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

#[test]
fn sha3_256_abc() {
    assert_eq!(
        sha3_256(b"abc"),
        hex!("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
    );
}

#[test]
fn sha3_512_abc() {
    assert_eq!(
        sha3_512(b"abc"),
        hex!(
            "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
             10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
        )
    );
}

#[test]
fn keccak_vectors_from_hashlib() {
    let mut n = 0;
    for line in KAT
        .lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
    {
        let f: Vec<&str> = line.split_whitespace().collect();
        let len: usize = f[1].parse().unwrap();
        let out_len: usize = f[2].parse().unwrap();
        let want = unhex(f[3]);
        let input: Vec<u8> = (0..len).map(|i| ((i * 7 + 3) % 256) as u8).collect();
        let got = match f[0] {
            "sha3_256" => sha3_256(&input).to_vec(),
            "sha3_512" => sha3_512(&input).to_vec(),
            "shake128" => shake_128(&input, out_len),
            "shake256" => shake_256(&input, out_len),
            other => panic!("unknown function {other}"),
        };
        assert_eq!(got, want, "{} len={len} out={out_len}", f[0]);
        n += 1;
    }
    assert!(n > 100, "expected the full vector set, ran {n}");
}
