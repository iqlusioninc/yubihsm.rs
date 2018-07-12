use failure::Error;

use super::Algorithm;

/// Valid algorithms for Yubico OTP (AES-based one time password) keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum OTPAlgorithm {
    /// Yubico OTP using AES-128
    YUBICO_OTP_AES128 = Algorithm::YUBICO_OTP_AES128 as u8,

    /// Yubico OTP using AES-192
    YUBICO_OTP_AES192 = Algorithm::YUBICO_OTP_AES192 as u8,

    /// Yubico OTP using AES-1256
    YUBICO_OTP_AES256 = Algorithm::YUBICO_OTP_AES256 as u8,
}

impl OTPAlgorithm {
    /// Convert from an `Algorithm` into an `OTPAlgorithm`
    pub fn from_algorithm(algorithm: Algorithm) -> Result<Self, Error> {
        Ok(match algorithm {
            Algorithm::YUBICO_OTP_AES128 => OTPAlgorithm::YUBICO_OTP_AES128,
            Algorithm::YUBICO_OTP_AES192 => OTPAlgorithm::YUBICO_OTP_AES192,
            Algorithm::YUBICO_OTP_AES256 => OTPAlgorithm::YUBICO_OTP_AES256,
            _ => bail!("unsupported/bad OTP algorithm: {:?}", algorithm),
        })
    }

    /// Return the size of the given key (as expected by the `YubiHSM2`) in bytes
    pub fn key_len(self) -> usize {
        match self {
            OTPAlgorithm::YUBICO_OTP_AES128 => 16,
            OTPAlgorithm::YUBICO_OTP_AES192 => 24,
            OTPAlgorithm::YUBICO_OTP_AES256 => 32,
        }
    }
}

impl_algorithm!(OTPAlgorithm);
