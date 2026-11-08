//! Tests for the NTT, InvNTT, basemul, and ring multiplication.

use cipherbox_pqc_core::field::FieldElement;
use cipherbox_pqc_core::ntt::{inv_ntt, ntt, poly_mul};

#[test]
fn ntt_of_constant_one() {
    let mut f = [FieldElement::ZERO; 256];
    f[0] = FieldElement::from_u16(1);
    ntt(&mut f);
    for (i, coeff) in f.iter().enumerate() {
        let expected = if i % 2 == 0 { 1 } else { 0 };
        assert_eq!(coeff.to_u16(), expected, "NTT of [1,0,...] at index {i}");
    }
}

#[test]
fn ntt_roundtrip() {
    let mut f = [FieldElement::ZERO; 256];
    for (i, coeff) in f.iter_mut().enumerate() {
        *coeff = FieldElement::from_u16(((i * 37 + 11) % 3329) as u16);
    }
    let orig = f;
    ntt(&mut f);
    inv_ntt(&mut f);
    for (i, coeff) in f.iter().enumerate() {
        assert_eq!(coeff.to_u16(), orig[i].to_u16(), "roundtrip at index {i}");
    }
}

#[test]
fn ntt_roundtrip_zero() {
    let mut f = [FieldElement::ZERO; 256];
    ntt(&mut f);
    inv_ntt(&mut f);
    for coeff in f.iter() {
        assert_eq!(coeff.to_u16(), 0);
    }
}

#[test]
fn ntt_constant_polynomial() {
    let mut f = [FieldElement::ZERO; 256];
    f[0] = FieldElement::from_u16(7);
    ntt(&mut f);
    for (i, coeff) in f.iter().enumerate() {
        let expected = if i % 2 == 0 { 7 } else { 0 };
        assert_eq!(coeff.to_u16(), expected, "NTT of [7,0,...] at index {i}");
    }
    inv_ntt(&mut f);
    for (i, coeff) in f.iter().enumerate() {
        let expected = if i == 0 { 7 } else { 0 };
        assert_eq!(coeff.to_u16(), expected, "roundtrip at index {i}");
    }
}

fn schoolbook_mul(a: &[FieldElement; 256], b: &[FieldElement; 256]) -> [FieldElement; 256] {
    let mut result = [FieldElement::ZERO; 256];
    for (i, ai) in a.iter().enumerate() {
        for (j, bj) in b.iter().enumerate() {
            let idx = i + j;
            let val = *ai * *bj;
            if idx < 256 {
                result[idx] = result[idx] + val;
            } else {
                result[idx - 256] = result[idx - 256] - val;
            }
        }
    }
    result
}

#[test]
fn poly_mul_matches_schoolbook_small() {
    let mut a = [FieldElement::ZERO; 256];
    let mut b = [FieldElement::ZERO; 256];
    for (i, coeff) in a.iter_mut().enumerate() {
        *coeff = FieldElement::from_u16(((i * 13 + 7) % 3329) as u16);
    }
    for (i, coeff) in b.iter_mut().enumerate() {
        *coeff = FieldElement::from_u16(((i * 29 + 3) % 3329) as u16);
    }
    let expected = schoolbook_mul(&a, &b);
    let got = poly_mul(&a, &b);
    for (i, coeff) in got.iter().enumerate() {
        assert_eq!(
            coeff.to_u16(),
            expected[i].to_u16(),
            "poly_mul vs schoolbook at index {i}"
        );
    }
}

#[test]
fn poly_mul_identity() {
    let mut a = [FieldElement::ZERO; 256];
    let mut one = [FieldElement::ZERO; 256];
    one[0] = FieldElement::from_u16(1);
    for (i, coeff) in a.iter_mut().enumerate() {
        *coeff = FieldElement::from_u16(((i * 41 + 5) % 3329) as u16);
    }
    let product = poly_mul(&a, &one);
    for (i, coeff) in product.iter().enumerate() {
        assert_eq!(coeff.to_u16(), a[i].to_u16(), "a * 1 != a at index {i}");
    }
}

#[test]
fn poly_mul_neg_x() {
    let mut x = [FieldElement::ZERO; 256];
    x[1] = FieldElement::from_u16(1);
    let mut x_255 = [FieldElement::ZERO; 256];
    x_255[255] = FieldElement::from_u16(1);
    let product = poly_mul(&x, &x_255);
    assert_eq!(product[0].to_u16(), 3328, "x * x^255 at index 0");
    for (i, coeff) in product.iter().enumerate().skip(1) {
        assert_eq!(coeff.to_u16(), 0, "x * x^255 at index {i}");
    }
}
