//! Property tests for the field arithmetic mod 3329.
//!
//! Uses the `core::ops::Add`, `Sub`, `Mul`, `Neg` trait impls, which
//! exercise the same code as the inherent `add_mod`/`sub_mod`/`mul_mod`/
//! `neg_mod` methods. Reference implementations use u32/u64/i64 so they
//! are obviously correct, and the field ops are compared against them.

use cipherbox_pqc_core::field::{FieldElement, Q};

fn ref_add(a: u16, b: u16) -> u16 {
    ((a as u32 + b as u32) % Q as u32) as u16
}

fn ref_sub(a: u16, b: u16) -> u16 {
    ((a as i64 - b as i64).rem_euclid(Q as i64)) as u16
}

fn ref_mul(a: u16, b: u16) -> u16 {
    ((a as u64 * b as u64) % Q as u64) as u16
}

#[test]
fn add_matches_reference() {
    for a in 0..Q {
        for b in 0..Q {
            let got = (FieldElement::from_u16(a) + FieldElement::from_u16(b)).to_u16();
            assert_eq!(got, ref_add(a, b), "add({a}, {b})");
        }
    }
}

#[test]
fn sub_matches_reference() {
    for a in 0..Q {
        for b in 0..Q {
            let got = (FieldElement::from_u16(a) - FieldElement::from_u16(b)).to_u16();
            assert_eq!(got, ref_sub(a, b), "sub({a}, {b})");
        }
    }
}

#[test]
fn mul_matches_reference() {
    for a in 0..Q {
        for b in 0..Q {
            let got = (FieldElement::from_u16(a) * FieldElement::from_u16(b)).to_u16();
            assert_eq!(got, ref_mul(a, b), "mul({a}, {b})");
        }
    }
}

#[test]
fn mul_commutative() {
    for a in 0..Q {
        for b in 0..Q {
            let ab = (FieldElement::from_u16(a) * FieldElement::from_u16(b)).to_u16();
            let ba = (FieldElement::from_u16(b) * FieldElement::from_u16(a)).to_u16();
            assert_eq!(ab, ba, "mul not commutative at ({a}, {b})");
        }
    }
}

#[test]
fn add_sub_inverses() {
    for a in 0..Q {
        for b in 0..Q {
            let got = ((FieldElement::from_u16(a) + FieldElement::from_u16(b))
                - FieldElement::from_u16(b))
            .to_u16();
            assert_eq!(got, a, "a + b - b != a at ({a}, {b})");
        }
    }
}

#[test]
fn multiplicative_identity() {
    let one = FieldElement::ONE;
    for a in 0..Q {
        let fe = FieldElement::from_u16(a);
        assert_eq!((fe * one).to_u16(), a);
    }
}

#[test]
fn inverse_correct() {
    let one = FieldElement::ONE;
    for a in 1..Q {
        let fe = FieldElement::from_u16(a);
        let inv = fe.inverse();
        assert_eq!(
            (fe * inv).to_u16(),
            one.to_u16(),
            "a * a^-1 != 1 at a = {a}"
        );
    }
}

#[test]
fn neg_correct() {
    for a in 0..Q {
        let fe = FieldElement::from_u16(a);
        let sum = (fe + (-fe)).to_u16();
        assert_eq!(sum, 0, "a + (-a) != 0 at a = {a}");
    }
}

#[test]
fn zero_annihilates() {
    let zero = FieldElement::from_u16(0);
    for a in 0..Q {
        let fe = FieldElement::from_u16(a);
        assert_eq!((fe * zero).to_u16(), 0);
    }
}

#[test]
fn boundary_values() {
    let vals = [0u16, 1, Q - 1];
    for &a in &vals {
        for &b in &vals {
            let got = (FieldElement::from_u16(a) * FieldElement::from_u16(b)).to_u16();
            assert_eq!(got, ref_mul(a, b));
        }
    }
}

#[test]
fn ct_eq_returns_ffff_on_equal() {
    for a in [0u16, 1, 100, Q - 1] {
        let fe = FieldElement::from_u16(a);
        assert_eq!(fe.ct_eq(fe), 0xFFFF, "ct_eq(x, x) should be 0xFFFF");
    }
}

#[test]
fn ct_eq_returns_zero_on_unequal() {
    assert_eq!(
        FieldElement::from_u16(0).ct_eq(FieldElement::from_u16(1)),
        0
    );
    assert_eq!(
        FieldElement::from_u16(1).ct_eq(FieldElement::from_u16(3328)),
        0
    );
}
