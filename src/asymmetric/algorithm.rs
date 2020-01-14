//! Asymmetric algorithm support

use crate::algorithm;
use anomaly::fail;

/// Asymmetric algorithms (RSA or ECC)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Algorithm {
    /// 2048-bit RSA
    Rsa2048 = 0x09,

    /// 3072-bit RSA
    Rsa3072 = 0x0a,

    /// 4096-bit RSA
    Rsa4096 = 0x0b,

    /// Ed25519
    Ed25519 = 0x2e,

    /// NIST P-224 (secp224r1)
    EcP224 = 0x2f,

    /// NIST P-256 (secp256r1, prime256v1)
    EcP256 = 0x0c,

    /// NIST P-384 (secp384r1)
    EcP384 = 0x0d,

    /// P-521 (secp521r1)
    EcP521 = 0x0e,

    /// secp256k1
    EcK256 = 0x0f,

    /// brainpool256r1
    EcBp256 = 0x10,

    /// brainpool384r1
    EcBp384 = 0x11,

    /// brainpool512r1
    EcBp512 = 0x12,
}

impl Algorithm {
    /// Convert an unsigned byte tag into an `Algorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, algorithm::Error> {
        Ok(match tag {
            0x09 => Algorithm::Rsa2048,
            0x0a => Algorithm::Rsa3072,
            0x0b => Algorithm::Rsa4096,
            0x0c => Algorithm::EcP256,
            0x0d => Algorithm::EcP384,
            0x0e => Algorithm::EcP521,
            0x0f => Algorithm::EcK256,
            0x10 => Algorithm::EcBp256,
            0x11 => Algorithm::EcBp384,
            0x12 => Algorithm::EcBp512,
            0x2e => Algorithm::Ed25519,
            0x2f => Algorithm::EcP224,
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
            Algorithm::Rsa2048 => 256,
            Algorithm::Rsa3072 => 384,
            Algorithm::Rsa4096 => 512,
            Algorithm::Ed25519 => 32,
            Algorithm::EcP224 => 28,
            Algorithm::EcP256 => 32,
            Algorithm::EcK256 => 32,
            Algorithm::EcP384 => 48,
            Algorithm::EcP521 => 66,
            Algorithm::EcBp256 => 32,
            Algorithm::EcBp384 => 48,
            Algorithm::EcBp512 => 64,
        }
    }
}

impl_algorithm_serializers!(Algorithm);
