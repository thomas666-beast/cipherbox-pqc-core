//! NIST ACVP known-answer tests for ML-KEM-768.
//!
//! Uses the official ACVP-Server vectors (v1.1.0.40):
//!   - ML-KEM-keyGen-FIPS203/internalProjection.json
//!   - ML-KEM-encapDecap-FIPS203/internalProjection.json
//!
//! Only the `ML-KEM-768` parameter set is exercised. The
//! `encapsulationKeyCheck` and `decapsulationKeyCheck` groups are
//! skipped: they test FIPS 203 §7.2/§7.3 key validation, which is
//! separate from the KEM algorithms 16–18.

use cipherbox_pqc_core::kem;
use serde_json::Value;
use std::fs;

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2),
        "odd-length hex string: len={}",
        s.len()
    );
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_val(bytes[i]);
        let lo = hex_val(bytes[i + 1]);
        out.push((hi << 4) | lo);
    }
    out
}

fn hex_val(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("invalid hex byte: {}", b),
    }
}

fn load(name: &str) -> Value {
    let path = format!("tests/vectors/{name}");
    let text = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("cannot read {path}: {e}. Run the curl commands in the task description.")
    });
    serde_json::from_str(&text).expect("invalid JSON")
}

fn as_fixed<const N: usize>(bytes: &[u8], what: &str, tc_id: u64) -> [u8; N] {
    bytes.try_into().unwrap_or_else(|_| {
        panic!(
            "{what} length mismatch at tcId={tc_id}: got {}, expected {N}",
            bytes.len()
        )
    })
}

// ==========================================
// keyGen
// ==========================================

#[test]
fn acvp_keygen_ml_kem_768() {
    let doc = load("ml-kem-keygen.json");
    let groups = doc["testGroups"].as_array().expect("testGroups");
    let mut cases_run = 0;

    for group in groups {
        if group["parameterSet"].as_str() != Some("ML-KEM-768") {
            continue;
        }
        let tests = group["tests"].as_array().expect("tests");
        for case in tests {
            let tc_id = case["tcId"].as_u64().expect("tcId");
            let d_bytes = hex_decode(case["d"].as_str().expect("d"));
            let z_bytes = hex_decode(case["z"].as_str().expect("z"));
            let expected_ek = hex_decode(case["ek"].as_str().expect("ek"));
            let expected_dk = hex_decode(case["dk"].as_str().expect("dk"));

            let d: [u8; 32] = as_fixed(&d_bytes, "d", tc_id);
            let z: [u8; 32] = as_fixed(&z_bytes, "z", tc_id);

            let (ek, dk) = kem::keygen(&d, &z);

            assert_eq!(
                ek.as_slice(),
                expected_ek.as_slice(),
                "tcId={tc_id}: ek mismatch"
            );
            assert_eq!(
                dk.as_slice(),
                expected_dk.as_slice(),
                "tcId={tc_id}: dk mismatch"
            );

            cases_run += 1;
        }
    }

    assert!(cases_run > 0, "no ML-KEM-768 keyGen cases found");
    eprintln!("ACVP keyGen ML-KEM-768: {cases_run} cases passed");
}

// ==========================================
// Encapsulation and decapsulation
// ==========================================

#[test]
fn acvp_encapdecap_ml_kem_768() {
    let doc = load("ml-kem-encapdecap.json");
    let groups = doc["testGroups"].as_array().expect("testGroups");
    let mut encap_count = 0;
    let mut decap_count = 0;

    for group in groups {
        if group["parameterSet"].as_str() != Some("ML-KEM-768") {
            continue;
        }
        let function = match group["function"].as_str() {
            Some("encapsulation") => "encapsulation",
            Some("decapsulation") => "decapsulation",
            _ => continue,
        };
        let tests = group["tests"].as_array().expect("tests");
        for case in tests {
            let tc_id = case["tcId"].as_u64().expect("tcId");

            match function {
                "encapsulation" => {
                    let ek_bytes = hex_decode(case["ek"].as_str().expect("ek"));
                    let m_bytes = hex_decode(case["m"].as_str().expect("m"));
                    let expected_c = hex_decode(case["c"].as_str().expect("c"));
                    let expected_k = hex_decode(case["k"].as_str().expect("k"));

                    let ek: [u8; kem::EK_BYTES] = as_fixed(&ek_bytes, "ek", tc_id);
                    let m: [u8; 32] = as_fixed(&m_bytes, "m", tc_id);

                    let (c, k) = kem::encaps(&ek, &m);

                    assert_eq!(
                        c.as_slice(),
                        expected_c.as_slice(),
                        "tcId={tc_id}: encapsulation c mismatch"
                    );
                    assert_eq!(
                        k.as_slice(),
                        expected_k.as_slice(),
                        "tcId={tc_id}: encapsulation k mismatch"
                    );

                    encap_count += 1;
                }
                "decapsulation" => {
                    let dk_bytes = hex_decode(case["dk"].as_str().expect("dk"));
                    let c_bytes = hex_decode(case["c"].as_str().expect("c"));
                    let expected_k = hex_decode(case["k"].as_str().expect("k"));
                    let reason = case["reason"].as_str().unwrap_or("");

                    let dk: [u8; kem::DK_BYTES] = as_fixed(&dk_bytes, "dk", tc_id);
                    let c: [u8; kem::CT_BYTES] = as_fixed(&c_bytes, "c", tc_id);

                    let k = kem::decaps(&dk, &c);

                    assert_eq!(
                        k.as_slice(),
                        expected_k.as_slice(),
                        "tcId={tc_id}: decapsulation k mismatch (reason: {reason})"
                    );

                    decap_count += 1;
                }
                _ => unreachable!(),
            }
        }
    }

    assert!(encap_count > 0, "no ML-KEM-768 encapsulation cases found");
    assert!(decap_count > 0, "no ML-KEM-768 decapsulation cases found");
    eprintln!(
        "ACVP encapDecap ML-KEM-768: {encap_count} encapsulation, {decap_count} decapsulation cases passed"
    );
}
