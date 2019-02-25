use super::{Algorithm, AlgorithmError, AlgorithmErrorKind::TagInvalid};

/// Valid algorithms for HMAC keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum HmacAlg {
    /// hmac-sha1
    SHA1 = 0x13,

    /// hmac-sha256
    SHA256 = 0x14,

    /// hmac-sha384
    SHA384 = 0x15,

    /// hmac-sha512
    SHA512 = 0x16,
}

impl HmacAlg {
    /// Convert an unsigned byte tag into an `HmacAlgorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, AlgorithmError> {
        Ok(match tag {
            0x13 => HmacAlg::SHA1,
            0x14 => HmacAlg::SHA256,
            0x15 => HmacAlg::SHA384,
            0x16 => HmacAlg::SHA512,
            _ => fail!(TagInvalid, "unknown HMAC algorithm ID: 0x{:02x}", tag),
        })
    }

    /// Serialize algorithm ID as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Recommended key length (identical to output size)
    pub fn key_len(self) -> usize {
        match self {
            HmacAlg::SHA1 => 20,
            HmacAlg::SHA256 => 32,
            HmacAlg::SHA384 => 48,
            HmacAlg::SHA512 => 64,
        }
    }

    /// Return the size of the given key (as expected by the `YubiHSM 2`) in bytes
    pub fn max_key_len(self) -> usize {
        match self {
            HmacAlg::SHA1 => 64,
            HmacAlg::SHA256 => 64,
            HmacAlg::SHA384 => 128,
            HmacAlg::SHA512 => 128,
        }
    }
}

impl From<HmacAlg> for Algorithm {
    fn from(alg: HmacAlg) -> Algorithm {
        Algorithm::Hmac(alg)
    }
}

impl_algorithm_serializers!(HmacAlg);
