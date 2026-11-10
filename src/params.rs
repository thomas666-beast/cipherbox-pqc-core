//! ML-KEM parameter sets (FIPS 203 Table 2). Both supported sets use
//! eta1 = eta2 = 2, so only the eta = 2 sampler is needed.

/// Supported ML-KEM security levels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KemLevel {
    /// ML-KEM-768 (NIST category 3).
    MlKem768,
    /// ML-KEM-1024 (NIST category 5, required by CNSA 2.0).
    MlKem1024,
}

pub const ETA1: u32 = 2;
pub const ETA2: u32 = 2;

impl KemLevel {
    pub const ALL: [KemLevel; 2] = [KemLevel::MlKem768, KemLevel::MlKem1024];

    /// Module rank k.
    pub const fn k(self) -> usize {
        match self {
            Self::MlKem768 => 3,
            Self::MlKem1024 => 4,
        }
    }
    pub const fn du(self) -> u32 {
        match self {
            Self::MlKem768 => 10,
            Self::MlKem1024 => 11,
        }
    }
    pub const fn dv(self) -> u32 {
        match self {
            Self::MlKem768 => 4,
            Self::MlKem1024 => 5,
        }
    }
    /// Encapsulation key size in bytes (384k + 32).
    pub const fn ek_bytes(self) -> usize {
        384 * self.k() + 32
    }
    /// K-PKE secret key size in bytes (384k).
    pub const fn pke_dk_bytes(self) -> usize {
        384 * self.k()
    }
    /// Decapsulation key size in bytes (768k + 96).
    pub const fn dk_bytes(self) -> usize {
        768 * self.k() + 96
    }
    /// Ciphertext size in bytes (32 (du k + dv)).
    pub const fn ct_bytes(self) -> usize {
        32 * (self.du() as usize * self.k() + self.dv() as usize)
    }
    /// Shared secret size (always 32).
    pub const fn ss_bytes(self) -> usize {
        32
    }
    /// Parameter number: 768 or 1024.
    pub const fn param(self) -> u16 {
        match self {
            Self::MlKem768 => 768,
            Self::MlKem1024 => 1024,
        }
    }
    /// One-byte identifier stored in file headers (NIST category).
    pub const fn id(self) -> u8 {
        match self {
            Self::MlKem768 => 3,
            Self::MlKem1024 => 5,
        }
    }
    pub const fn name(self) -> &'static str {
        match self {
            Self::MlKem768 => "ML-KEM-768",
            Self::MlKem1024 => "ML-KEM-1024",
        }
    }

    pub fn from_param(p: u16) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.param() == p)
    }
    pub fn from_id(id: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.id() == id)
    }
    pub fn from_ek_len(n: usize) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.ek_bytes() == n)
    }
    pub fn from_dk_len(n: usize) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.dk_bytes() == n)
    }
    pub fn from_ct_len(n: usize) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.ct_bytes() == n)
    }
}

/// Size of an X25519 public key / ciphertext component.
pub const X25519_BYTES: usize = 32;

/// A key-encapsulation suite: plain ML-KEM, or X25519 + ML-KEM hybrid.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Suite {
    /// Plain ML-KEM at the given level.
    Kem(KemLevel),
    /// X25519 + ML-KEM hybrid at the given level (see `hybrid`).
    Hybrid(KemLevel),
}

impl Suite {
    pub const ALL: [Suite; 4] = [
        Suite::Kem(KemLevel::MlKem768),
        Suite::Kem(KemLevel::MlKem1024),
        Suite::Hybrid(KemLevel::MlKem768),
        Suite::Hybrid(KemLevel::MlKem1024),
    ];

    pub const fn level(self) -> KemLevel {
        match self {
            Self::Kem(l) | Self::Hybrid(l) => l,
        }
    }
    pub const fn is_hybrid(self) -> bool {
        matches!(self, Self::Hybrid(_))
    }
    /// Public key size: ML-KEM key, plus 32 bytes of X25519 for hybrids.
    pub const fn ek_bytes(self) -> usize {
        match self {
            Self::Kem(l) => l.ek_bytes(),
            Self::Hybrid(l) => l.ek_bytes() + X25519_BYTES,
        }
    }
    /// Ciphertext size: ML-KEM ciphertext, plus 32 bytes of X25519 for hybrids.
    pub const fn ct_bytes(self) -> usize {
        match self {
            Self::Kem(l) => l.ct_bytes(),
            Self::Hybrid(l) => l.ct_bytes() + X25519_BYTES,
        }
    }
    /// One-byte identifier used in file headers: 3 / 5 for plain ML-KEM,
    /// 0x13 / 0x15 for hybrids.
    pub const fn id(self) -> u8 {
        match self {
            Self::Kem(l) => l.id(),
            Self::Hybrid(l) => 0x10 | l.id(),
        }
    }
    pub const fn name(self) -> &'static str {
        match self {
            Self::Kem(KemLevel::MlKem768) => "ML-KEM-768",
            Self::Kem(KemLevel::MlKem1024) => "ML-KEM-1024",
            Self::Hybrid(KemLevel::MlKem768) => "X25519+ML-KEM-768",
            Self::Hybrid(KemLevel::MlKem1024) => "X25519+ML-KEM-1024",
        }
    }

    pub fn from_id(id: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.id() == id)
    }
    pub fn from_ek_len(n: usize) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.ek_bytes() == n)
    }
    pub fn from_ct_len(n: usize) -> Option<Self> {
        Self::ALL.into_iter().find(|s| s.ct_bytes() == n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_fips_203() {
        let l = KemLevel::MlKem768;
        assert_eq!(
            (l.ek_bytes(), l.dk_bytes(), l.ct_bytes()),
            (1184, 2400, 1088)
        );
        let l = KemLevel::MlKem1024;
        assert_eq!(
            (l.ek_bytes(), l.dk_bytes(), l.ct_bytes()),
            (1568, 3168, 1568)
        );
    }

    #[test]
    fn suite_sizes_and_lookups() {
        assert_eq!(Suite::Hybrid(KemLevel::MlKem768).ek_bytes(), 1216);
        assert_eq!(Suite::Hybrid(KemLevel::MlKem768).ct_bytes(), 1120);
        assert_eq!(Suite::Hybrid(KemLevel::MlKem1024).ek_bytes(), 1600);
        assert_eq!(Suite::Hybrid(KemLevel::MlKem1024).ct_bytes(), 1600);
        assert_eq!(Suite::Hybrid(KemLevel::MlKem768).id(), 0x13);
        assert_eq!(Suite::Hybrid(KemLevel::MlKem1024).id(), 0x15);
        for s in Suite::ALL {
            assert_eq!(Suite::from_id(s.id()), Some(s));
            assert_eq!(Suite::from_ek_len(s.ek_bytes()), Some(s), "{}", s.name());
        }
        // Public-key lengths must be unambiguous across all four suites.
        let mut lens: Vec<usize> = Suite::ALL.iter().map(|s| s.ek_bytes()).collect();
        lens.sort();
        lens.dedup();
        assert_eq!(lens.len(), 4);
        assert_eq!(Suite::from_ek_len(1000), None);
    }

    #[test]
    fn lookups_roundtrip() {
        for l in KemLevel::ALL {
            assert_eq!(KemLevel::from_param(l.param()), Some(l));
            assert_eq!(KemLevel::from_id(l.id()), Some(l));
            assert_eq!(KemLevel::from_ek_len(l.ek_bytes()), Some(l));
            assert_eq!(KemLevel::from_dk_len(l.dk_bytes()), Some(l));
            assert_eq!(KemLevel::from_ct_len(l.ct_bytes()), Some(l));
        }
        assert_eq!(KemLevel::from_param(512), None);
        assert_eq!(KemLevel::from_ek_len(1000), None);
    }
}
