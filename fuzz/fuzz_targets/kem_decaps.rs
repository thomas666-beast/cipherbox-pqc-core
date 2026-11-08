#![no_main]

use cipherbox_pqc_core::kem;
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static DK: OnceLock<[u8; kem::DK_BYTES]> = OnceLock::new();
static EK: OnceLock<[u8; kem::EK_BYTES]> = OnceLock::new();

fn get_keys() -> (&'static [u8; kem::EK_BYTES], &'static [u8; kem::DK_BYTES]) {
    EK.get_or_init(|| {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        getrandom::getrandom(&mut d).unwrap();
        getrandom::getrandom(&mut z).unwrap();
        let (ek, _) = kem::keygen(&d, &z);
        ek
    });
    DK.get_or_init(|| {
        let mut d = [0u8; 32];
        let mut z = [0u8; 32];
        getrandom::getrandom(&mut d).unwrap();
        getrandom::getrandom(&mut z).unwrap();
        let (_, dk) = kem::keygen(&d, &z);
        dk
    });
    (EK.get().unwrap(), DK.get().unwrap())
}

fuzz_target!(|data: &[u8]| {
    let (_, dk) = get_keys();
    let mut ct = [0u8; kem::CT_BYTES];
    let copy_len = data.len().min(kem::CT_BYTES);
    ct[..copy_len].copy_from_slice(&data[..copy_len]);
    let _ = kem::decaps(dk, &ct);
});
