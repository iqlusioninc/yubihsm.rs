use super::{Algorithm, AlgorithmError, AlgorithmErrorKind::TagInvalid};

/// Valid algorithms for Yubico OTP (AES-based one time password) keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum OtpAlg {
    /// Yubico OTP using AES-128
    AES128 = 0x25,

    /// Yubico OTP using AES-192
    AES192 = 0x27,

    /// Yubico OTP using AES-256
    AES256 = 0x28,
}

impl OtpAlg {
    /// Convert an unsigned byte tag into an `OtpAlgorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, AlgorithmError> {
        Ok(match tag {
            0x25 => OtpAlg::AES128,
            0x27 => OtpAlg::AES192,
            0x28 => OtpAlg::AES256,
            _ => fail!(TagInvalid, "unknown OTP algorithm ID: 0x{:02x}", tag),
        })
    }

    /// Serialize algorithm ID as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }

    /// Return the size of the given key (as expected by the `YubiHSM2`) in bytes
    pub fn key_len(self) -> usize {
        match self {
            OtpAlg::AES128 => 16,
            OtpAlg::AES192 => 24,
            OtpAlg::AES256 => 32,
        }
    }
}

impl From<OtpAlg> for Algorithm {
    fn from(alg: OtpAlg) -> Algorithm {
        Algorithm::Otp(alg)
    }
}

impl_algorithm_serializers!(OtpAlg);
