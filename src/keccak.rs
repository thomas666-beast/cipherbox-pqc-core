//! Keccak-f[1600] permutation and the FIPS 202 hash/XOF functions
//! required by ML-KEM (FIPS 203):
//!
//!   - SHA3-256, SHA3-512
//!   - SHAKE-128, SHAKE-256
//!
//! Implemented from scratch per FIPS 202. Tested against the official
//! NIST known-answer tests in `tests/keccak_kat.rs`.

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808A,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808B,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008A,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000A,
    0x0000_0000_8000_808B,
    0x8000_0000_0000_008B,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800A,
    0x8000_0000_8000_000A,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

const ROTATION_OFFSETS: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

const ROUNDS: usize = 24;

type State = [u64; 25];

#[inline]
fn round(state: &mut State, rc: u64) {
    // Theta
    let mut c = [0u64; 5];
    for x in 0..5 {
        c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
    }
    let mut d = [0u64; 5];
    for x in 0..5 {
        d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
    }
    for x in 0..5 {
        for y in 0..5 {
            state[x + 5 * y] ^= d[x];
        }
    }

    // Rho + Pi
    let mut b = [0u64; 25];
    for x in 0..5 {
        for y in 0..5 {
            let src = x + 5 * y;
            let rot = ROTATION_OFFSETS[src];
            let dst = y + 5 * ((2 * x + 3 * y) % 5);
            b[dst] = state[src].rotate_left(rot);
        }
    }

    // Chi
    for y in 0..5 {
        for x in 0..5 {
            let idx = x + 5 * y;
            let next1 = ((x + 1) % 5) + 5 * y;
            let next2 = ((x + 2) % 5) + 5 * y;
            state[idx] = b[idx] ^ ((!b[next1]) & b[next2]);
        }
    }

    // Iota
    state[0] ^= rc;
}

pub fn keccak_f1600(state: &mut State) {
    for &rc in ROUND_CONSTANTS.iter().take(ROUNDS) {
        round(state, rc);
    }
}

fn absorb(state: &mut State, input: &[u8], rate: usize, domain: u8) {
    debug_assert!(rate.is_multiple_of(8));
    debug_assert!(rate < 200);

    let mut block = [0u8; 200];
    let mut offset = 0;

    while offset + rate <= input.len() {
        xor_block_into_state(state, &input[offset..offset + rate], rate);
        keccak_f1600(state);
        offset += rate;
    }

    let remaining = input.len() - offset;
    block[..remaining].copy_from_slice(&input[offset..]);
    block[remaining] ^= domain;
    block[rate - 1] ^= 0x80;

    xor_block_into_state(state, &block[..rate], rate);
    keccak_f1600(state);
}

fn xor_block_into_state(state: &mut State, block: &[u8], rate: usize) {
    debug_assert_eq!(block.len(), rate);
    debug_assert!(rate.is_multiple_of(8));
    for i in 0..(rate / 8) {
        let lane = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
        state[i] ^= lane;
    }
}

fn squeeze(state: &mut State, output: &mut [u8], rate: usize) {
    debug_assert!(rate.is_multiple_of(8));

    let mut offset = 0;
    loop {
        let take = core::cmp::min(rate, output.len() - offset);
        for (i, lane) in state.iter().enumerate().take(take.div_ceil(8)) {
            let lane_bytes = lane.to_le_bytes();
            let start = i * 8;
            let end = core::cmp::min(start + 8, take);
            output[offset + start..offset + end].copy_from_slice(&lane_bytes[..end - start]);
        }
        offset += take;
        if offset == output.len() {
            return;
        }
        keccak_f1600(state);
    }
}

pub fn sha3_256(input: &[u8]) -> [u8; 32] {
    let mut state = [0u64; 25];
    absorb(&mut state, input, 136, 0x06);
    let mut out = [0u8; 32];
    squeeze(&mut state, &mut out, 136);
    out
}

pub fn sha3_512(input: &[u8]) -> [u8; 64] {
    let mut state = [0u64; 25];
    absorb(&mut state, input, 72, 0x06);
    let mut out = [0u8; 64];
    squeeze(&mut state, &mut out, 72);
    out
}

pub fn shake_128(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut state = [0u64; 25];
    absorb(&mut state, input, 168, 0x1F);
    let mut out = vec![0u8; output_len];
    squeeze(&mut state, &mut out, 168);
    out
}

pub fn shake_256(input: &[u8], output_len: usize) -> Vec<u8> {
    let mut state = [0u64; 25];
    absorb(&mut state, input, 136, 0x1F);
    let mut out = vec![0u8; output_len];
    squeeze(&mut state, &mut out, 136);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha3_256_empty() {
        let expected =
            hex_literal::hex!("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
        assert_eq!(sha3_256(b""), expected);
    }

    #[test]
    fn sha3_512_empty() {
        let expected = hex_literal::hex!(
            "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a6\
             15b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26"
        );
        assert_eq!(sha3_512(b""), expected);
    }

    #[test]
    fn shake_128_empty_32() {
        let expected =
            hex_literal::hex!("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
        assert_eq!(shake_128(b"", 32), expected);
    }

    #[test]
    fn shake_256_empty_64() {
        let expected = hex_literal::hex!(
            "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f\
             d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be"
        );
        assert_eq!(shake_256(b"", 64), expected);
    }
}
