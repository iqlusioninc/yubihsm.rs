use super::{Algorithm, AlgorithmError, AlgorithmErrorKind::TagInvalid};

/// Asymmetric algorithms (RSA or ECC)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum AsymmetricAlg {
    /// 2048-bit RSA
    RSA_2048 = 0x09,

    /// 3072-bit RSA
    RSA_3072 = 0x0a,

    /// 4096-bit RSA
    RSA_4096 = 0x0b,

    /// Ed25519
    Ed25519 = 0x2e,

    /// NIST P-224 (secp224r1)
    EC_P224 = 0x2f,

    /// NIST P-256 (secp256r1, prime256v1)
    EC_P256 = 0x0c,

    /// NIST P-384 (secp384r1)
    EC_P384 = 0x0d,

    /// P-521 (secp521r1)
    EC_P521 = 0x0e,

    /// secp256k1
    EC_K256 = 0x0f,

    /// brainpool256r1
    EC_BP256 = 0x10,

    /// brainpool384r1
    EC_BP384 = 0x11,

    /// brainpool512r1
    EC_BP512 = 0x12,
}

impl AsymmetricAlg {
    /// Convert an unsigned byte tag into an `AsymmetricAlgorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, AlgorithmError> {
        Ok(match tag {
            0x09 => AsymmetricAlg::RSA_2048,
            0x0a => AsymmetricAlg::RSA_3072,
            0x0b => AsymmetricAlg::RSA_4096,
            0x0c => AsymmetricAlg::EC_P256,
            0x0d => AsymmetricAlg::EC_P384,
            0x0e => AsymmetricAlg::EC_P521,
            0x0f => AsymmetricAlg::EC_K256,
            0x10 => AsymmetricAlg::EC_BP256,
            0x11 => AsymmetricAlg::EC_BP384,
            0x12 => AsymmetricAlg::EC_BP512,
            0x2e => AsymmetricAlg::Ed25519,
            0x2f => AsymmetricAlg::EC_P224,
            _ => fail!(TagInvalid, "unknown asymmetric algorithm ID: 0x{:02x}", tag),
        })
    }

    /// Serialize algorithm ID as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Return the size of the given key (as expected by the `YubiHSM2`) in bytes
    pub fn key_len(self) -> usize {
        match self {
            AsymmetricAlg::RSA_2048 => 256,
            AsymmetricAlg::RSA_3072 => 384,
            AsymmetricAlg::RSA_4096 => 512,
            AsymmetricAlg::Ed25519 => 32,
            AsymmetricAlg::EC_P224 => 28,
            AsymmetricAlg::EC_P256 => 32,
            AsymmetricAlg::EC_K256 => 32,
            AsymmetricAlg::EC_P384 => 48,
            AsymmetricAlg::EC_P521 => 66,
            AsymmetricAlg::EC_BP256 => 32,
            AsymmetricAlg::EC_BP384 => 48,
            AsymmetricAlg::EC_BP512 => 64,
        }
    }
}

impl From<AsymmetricAlg> for Algorithm {
    fn from(alg: AsymmetricAlg) -> Algorithm {
        Algorithm::Asymmetric(alg)
    }
}

impl_algorithm_serializers!(AsymmetricAlg);
