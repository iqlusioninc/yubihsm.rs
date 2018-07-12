use failure::Error;

use super::Algorithm;

/// Valid algorithms for asymmetric keys
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum AsymmetricAlgorithm {
    /// 2048-bit RSA
    RSA2048 = Algorithm::RSA2048 as u8,

    /// 3072-bit RSA
    RSA3072 = Algorithm::RSA3072 as u8,

    /// 4096-bit RSA
    RSA4096 = Algorithm::RSA4096 as u8,

    /// Ed25519
    EC_ED25519 = Algorithm::EC_ED25519 as u8,

    /// NIST P-256 (a.k.a. secp256r1, prime256v1)
    EC_P256 = Algorithm::EC_P256 as u8,

    /// NIST P-384
    EC_P384 = Algorithm::EC_P384 as u8,

    /// NIST P-512
    EC_P521 = Algorithm::EC_P521 as u8,

    /// secp256k1
    EC_K256 = Algorithm::EC_K256 as u8,

    /// brainpoolP256r1
    EC_BP256 = Algorithm::EC_BP256 as u8,

    /// brainpoolP384r1
    EC_BP384 = Algorithm::EC_BP384 as u8,

    /// brainpoolP512r1
    EC_BP512 = Algorithm::EC_BP512 as u8,
}

impl AsymmetricAlgorithm {
    /// Convert from an `Algorithm` into an `AsymmetricAlgorithm`
    pub fn from_algorithm(algorithm: Algorithm) -> Result<Self, Error> {
        Ok(match algorithm {
            Algorithm::RSA2048 => AsymmetricAlgorithm::RSA2048,
            Algorithm::RSA3072 => AsymmetricAlgorithm::RSA3072,
            Algorithm::RSA4096 => AsymmetricAlgorithm::RSA4096,
            Algorithm::EC_ED25519 => AsymmetricAlgorithm::EC_ED25519,
            Algorithm::EC_P256 => AsymmetricAlgorithm::EC_P256,
            Algorithm::EC_P384 => AsymmetricAlgorithm::EC_P384,
            Algorithm::EC_P521 => AsymmetricAlgorithm::EC_P521,
            Algorithm::EC_K256 => AsymmetricAlgorithm::EC_P384,
            Algorithm::EC_BP256 => AsymmetricAlgorithm::EC_BP256,
            Algorithm::EC_BP384 => AsymmetricAlgorithm::EC_BP384,
            Algorithm::EC_BP512 => AsymmetricAlgorithm::EC_BP512,
            _ => bail!("unsupported/bad asymmetric algorithm: {:?}", algorithm),
        })
    }

    /// Return the size of the given key (as expected by the `YubiHSM2`) in bytes
    pub fn key_len(self) -> usize {
        match self {
            AsymmetricAlgorithm::RSA2048 => 256,
            AsymmetricAlgorithm::RSA3072 => 384,
            AsymmetricAlgorithm::RSA4096 => 512,
            AsymmetricAlgorithm::EC_ED25519 => 32,
            AsymmetricAlgorithm::EC_P256 => 32,
            AsymmetricAlgorithm::EC_K256 => 32,
            AsymmetricAlgorithm::EC_P384 => 48,
            AsymmetricAlgorithm::EC_P521 => 66,
            AsymmetricAlgorithm::EC_BP256 => 32,
            AsymmetricAlgorithm::EC_BP384 => 48,
            AsymmetricAlgorithm::EC_BP512 => 64,
        }
    }
}

impl_algorithm!(AsymmetricAlgorithm);
