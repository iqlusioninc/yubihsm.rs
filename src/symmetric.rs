//! Symmetric encryption support

use crate::{object, Client};

pub mod algorithm;
pub mod cbc;
pub(crate) mod commands;

pub use self::algorithm::Algorithm;

/// Hsm Key holds a reference a symmetric key held on the HSM
/// and accessible by the client
pub struct HsmKey {
    /// YubiHSM client.
    client: Client,

    /// ID of a symmetric key to perform encryption with.
    cipher_key_id: object::Id,
}

impl HsmKey {
    /// Creates an accessor for a symmetric key held on the HSM connected to by the Client
    pub fn new(client: Client, cipher_key_id: object::Id) -> Self {
        Self {
            client,
            cipher_key_id,
        }
    }
}

/// Associated YubiHSM algoritm associated with a cipher
pub trait AssociatedHsmSymmetricAlgorithm: sealed::AssociatedHsmSymmetricAlgorithm {
    /// Associated YubiHSM algoritm associated with this cipher
    const HSM_SYMMETRIC_ALGORITHM: Algorithm;
}

mod sealed {
    /// Sealed trait for a symmetric algorithm supported by YubiHSM
    pub trait AssociatedHsmSymmetricAlgorithm {}

    impl AssociatedHsmSymmetricAlgorithm for aes::Aes128 {}

    impl AssociatedHsmSymmetricAlgorithm for aes::Aes192 {}

    impl AssociatedHsmSymmetricAlgorithm for aes::Aes256 {}
}

impl AssociatedHsmSymmetricAlgorithm for aes::Aes128 {
    const HSM_SYMMETRIC_ALGORITHM: Algorithm = Algorithm::Aes128;
}

impl AssociatedHsmSymmetricAlgorithm for aes::Aes192 {
    const HSM_SYMMETRIC_ALGORITHM: Algorithm = Algorithm::Aes192;
}

impl AssociatedHsmSymmetricAlgorithm for aes::Aes256 {
    const HSM_SYMMETRIC_ALGORITHM: Algorithm = Algorithm::Aes256;
}
