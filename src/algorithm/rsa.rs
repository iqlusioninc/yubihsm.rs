use super::{Algorithm, AlgorithmError, AlgorithmErrorKind::TagInvalid};

/// RSA algorithms (signing and encryption)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum RsaAlg {
    /// rsa-pkcs1-sha1
    PKCS1_SHA1 = 0x01,

    /// rsa-pkcs1-sha256
    PKCS1_SHA256 = 0x02,

    /// rsa-pkcs1-sha384
    PKCS1_SHA384 = 0x03,

    /// rsa-pkcs1-sha512
    PKCS1_SHA512 = 0x04,

    /// rsa-pss-sha1
    PSS_SHA1 = 0x05,

    /// rsa-pss-sha256
    PSS_SHA256 = 0x06,

    /// rsa-pss-sha384
    PSS_SHA384 = 0x07,

    /// rsa-pss-sha512
    PSS_SHA512 = 0x08,

    /// rsa-oaep-sha1
    OAEP_SHA1 = 0x19,

    /// rsa-oaep-sha256
    OAEP_SHA256 = 0x1a,

    /// rsa-oaep-sha384
    OAEP_SHA384 = 0x1b,

    /// rsa-oaep-sha512
    OAEP_SHA512 = 0x1c,
}

impl RsaAlg {
    /// Convert an unsigned byte tag into an `RsaAlgorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, AlgorithmError> {
        Ok(match tag {
            0x01 => RsaAlg::PKCS1_SHA1,
            0x02 => RsaAlg::PKCS1_SHA256,
            0x03 => RsaAlg::PKCS1_SHA384,
            0x04 => RsaAlg::PKCS1_SHA512,
            0x05 => RsaAlg::PSS_SHA1,
            0x06 => RsaAlg::PSS_SHA256,
            0x07 => RsaAlg::PSS_SHA384,
            0x08 => RsaAlg::PSS_SHA512,
            0x19 => RsaAlg::OAEP_SHA1,
            0x1a => RsaAlg::OAEP_SHA256,
            0x1b => RsaAlg::OAEP_SHA384,
            0x1c => RsaAlg::OAEP_SHA512,
            _ => fail!(TagInvalid, "unknown RSA algorithm ID: 0x{:02x}", tag),
        })
    }

    /// Serialize algorithm ID as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl From<RsaAlg> for Algorithm {
    fn from(alg: RsaAlg) -> Algorithm {
        Algorithm::Rsa(alg)
    }
}

impl_algorithm_serializers!(RsaAlg);
