//! Asymmetric algorithm support

use crate::algorithm;

/// Asymmetric algorithms (RSA or ECC)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum Algorithm {
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

impl Algorithm {
    /// Convert an unsigned byte tag into an `Algorithmorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, algorithm::Error> {
        Ok(match tag {
            0x09 => Algorithm::RSA_2048,
            0x0a => Algorithm::RSA_3072,
            0x0b => Algorithm::RSA_4096,
            0x0c => Algorithm::EC_P256,
            0x0d => Algorithm::EC_P384,
            0x0e => Algorithm::EC_P521,
            0x0f => Algorithm::EC_K256,
            0x10 => Algorithm::EC_BP256,
            0x11 => Algorithm::EC_BP384,
            0x12 => Algorithm::EC_BP512,
            0x2e => Algorithm::Ed25519,
            0x2f => Algorithm::EC_P224,
            _ => fail!(
                algorithm::ErrorKind::TagInvalid,
                "unknown asymmetric algorithm ID: 0x{:02x}",
                tag
            ),
        })
    }

    /// Serialize algorithm ID as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Return the size of the given key (as expected by the `YubiHSM 2`) in bytes
    pub fn key_len(self) -> usize {
        match self {
            Algorithm::RSA_2048 => 256,
            Algorithm::RSA_3072 => 384,
            Algorithm::RSA_4096 => 512,
            Algorithm::Ed25519 => 32,
            Algorithm::EC_P224 => 28,
            Algorithm::EC_P256 => 32,
            Algorithm::EC_K256 => 32,
            Algorithm::EC_P384 => 48,
            Algorithm::EC_P521 => 66,
            Algorithm::EC_BP256 => 32,
            Algorithm::EC_BP384 => 48,
            Algorithm::EC_BP512 => 64,
        }
    }
}

impl_algorithm_serializers!(Algorithm);
