#![no_main]

use cipherbox_pqc_core::file::decrypt_file;
use cipherbox_pqc_core::kem;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

// A fixed decapsulation key is enough: the fuzz target is checking that
// arbitrary ciphertext bytes never panic, not that they decrypt.
static DK: OnceLock<[u8; kem::DK_BYTES]> = OnceLock::new();

fn get_dk() -> &'static [u8; kem::DK_BYTES] {
    DK.get_or_init(|| {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        getrandom::getrandom(&mut d).unwrap();
        getrandom::getrandom(&mut z).unwrap();
        let (_ek, dk) = kem::keygen(&d, &z);
        dk
    })
}

fuzz_target!(|data: &[u8]| {
    let _ = decrypt_file(data, get_dk());
});
