//! Field arithmetic modulo q = 3329, the ML-KEM prime.

pub const Q: u16 = 3329;
pub const R: u16 = 2285;
pub const R2: u16 = 1353;
pub const MONT_ONE: u16 = R;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldElement {
    pub(crate) mont: u16,
}

impl FieldElement {
    pub fn from_u16(x: u16) -> Self {
        let x = x % Q;
        let mont = montgomery_reduce((x as u32) * (R2 as u32));
        debug_assert!(mont < Q);
        FieldElement { mont }
    }

    pub fn to_u16(self) -> u16 {
        montgomery_reduce(self.mont as u32)
    }

    pub fn to_mont(self) -> u16 {
        self.mont
    }

    pub fn from_mont(mont: u16) -> Self {
        debug_assert!(mont < Q);
        FieldElement { mont }
    }

    pub const ZERO: Self = FieldElement { mont: 0 };
    pub const ONE: Self = FieldElement { mont: MONT_ONE };

    pub fn add_mod(self, rhs: Self) -> Self {
        let sum = self.mont as u32 + rhs.mont as u32;
        let sum = sum.wrapping_sub(Q as u32);
        let mask = ((sum >> 31) as u16).wrapping_neg();
        let mont = (sum as u16).wrapping_add(mask & Q);
        FieldElement { mont }
    }

    pub fn sub_mod(self, rhs: Self) -> Self {
        let diff = (self.mont as u32).wrapping_sub(rhs.mont as u32);
        let mask = ((diff >> 31) as u16).wrapping_neg();
        let mont = (diff as u16).wrapping_add(mask & Q);
        FieldElement { mont }
    }

    pub fn neg_mod(self) -> Self {
        if self.mont == 0 {
            self
        } else {
            FieldElement {
                mont: Q - self.mont,
            }
        }
    }

    pub fn mul_mod(self, rhs: Self) -> Self {
        let prod = (self.mont as u32) * (rhs.mont as u32);
        let mont = montgomery_reduce(prod);
        FieldElement { mont }
    }

    pub fn inverse(self) -> Self {
        let mut acc = Self::ONE;
        let mut sq = self;
        let bits = 0b1100_1111_1111u16;
        for i in 0..12 {
            if bits & (1 << i) != 0 {
                acc = acc.mul_mod(sq);
            }
            sq = sq.mul_mod(sq);
        }
        acc
    }

    pub fn ct_eq(self, other: Self) -> u16 {
        let diff = self.mont ^ other.mont;
        let d = diff as u32;
        let mask = d.wrapping_sub(1) >> 31;
        ((mask as u16) ^ 1).wrapping_sub(1)
    }

    pub fn ct_select(a: Self, b: Self, mask: u16) -> Self {
        FieldElement {
            mont: (a.mont & !mask) | (b.mont & mask),
        }
    }
}

impl core::ops::Add for FieldElement {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        self.add_mod(rhs)
    }
}

impl core::ops::Sub for FieldElement {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        self.sub_mod(rhs)
    }
}

impl core::ops::Mul for FieldElement {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        self.mul_mod(rhs)
    }
}

impl core::ops::Neg for FieldElement {
    type Output = Self;
    fn neg(self) -> Self {
        self.neg_mod()
    }
}

// ============================================================================
// QINV = Q^{-1} mod 2^16, as i16. Computed by brute force at compile time.
//
// Search condition: candidate * Q ≡ 1 (mod 2^16). The unique solution in
// [1, 65536) is 62209, which as i16 is -3327, matching the reference C
// `QINV` constant in Kyber. The reference `montgomery_reduce` formula
// (a - t*Q) >> 16 requires t ≡ a * Q^{-1} (mod 2^16), not a * (-Q^{-1}),
// so the correct search target is 1, not 0xFFFF.
// ============================================================================

pub const QINV: i16 = {
    let mut candidate: u32 = 1;
    let mut found: u32 = 0;
    while candidate < 65536 {
        if (candidate * (Q as u32)) & 0xFFFF == 1 {
            found = candidate;
            break;
        }
        candidate += 1;
    }
    found as i16
};

/// Montgomery reduction: given `a < Q * 2^16`, return `a * R^{-1} mod Q`
/// in `[0, Q)`. Matches the FIPS 203 MontgomeryReduce.
#[inline]
pub fn montgomery_reduce(a: u32) -> u16 {
    debug_assert!(a < (Q as u32) * (1u32 << 16));
    let a_i32 = a as i32;

    let t = (a_i32 as i16).wrapping_mul(QINV) as i32;

    let u = (a_i32 - t * (Q as i32)) >> 16;

    let u = u + ((u >> 31) & (Q as i32));

    debug_assert!((0..Q as i32).contains(&u));
    u as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverse_of_qinv() {
        let prod = (QINV as u32).wrapping_mul(Q as u32) & 0xFFFF;
        assert_eq!(prod, 1);
    }

    #[test]
    fn roundtrip_u16() {
        for x in 0u16..Q {
            let fe = FieldElement::from_u16(x);
            assert_eq!(fe.to_u16(), x, "roundtrip failed for x = {x}");
        }
    }

    #[test]
    fn montgomery_reduce_boundary() {
        assert_eq!(montgomery_reduce(0), 0);
        assert_eq!(montgomery_reduce(R2 as u32), R);
        assert_eq!(montgomery_reduce(R as u32), 1);
        assert_eq!(montgomery_reduce((Q as u32) * (R as u32)), 0);
    }
}
