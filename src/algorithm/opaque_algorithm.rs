use failure::Error;

use super::Algorithm;

/// Valid algorithms for opaque data
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum OpaqueAlgorithm {
    /// Arbitrary opaque data
    OPAQUE_DATA = Algorithm::OPAQUE_DATA as u8,

    /// X.509 certificates
    OPAQUE_X509_CERT = Algorithm::OPAQUE_X509_CERT as u8,
}

impl OpaqueAlgorithm {
    /// Convert from an `Algorithm` into an `OpaqueAlgorithm`
    pub fn from_algorithm(algorithm: Algorithm) -> Result<Self, Error> {
        Ok(match algorithm {
            Algorithm::OPAQUE_DATA => OpaqueAlgorithm::OPAQUE_DATA,
            Algorithm::OPAQUE_X509_CERT => OpaqueAlgorithm::OPAQUE_X509_CERT,
            _ => bail!("unsupported/bad opaque data algorithm: {:?}", algorithm),
        })
    }
}

impl_algorithm!(OpaqueAlgorithm);
