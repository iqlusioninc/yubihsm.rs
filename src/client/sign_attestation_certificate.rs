//! Obtain an X.509 attestation certificate for a key within the `YubiHSM2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Sign_Attestation_Certificate.html>

use crate::{
    command::{self, Command},
    object,
    response::Response,
};

/// Request parameters for `command::attest_asymmetric`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SignAttestationCertificateCommand {
    /// Key that attestation certificate will be generated for
    pub key_id: object::Id,

    /// Key to use to sign attestation certificate
    pub attestation_key_id: object::Id,
}

impl Command for SignAttestationCertificateCommand {
    type ResponseType = AttestationCertificate;
}

/// DER encoded X.509 attestation certificate
#[derive(Serialize, Deserialize, Debug)]
pub struct AttestationCertificate(pub Vec<u8>);

impl Response for AttestationCertificate {
    const COMMAND_CODE: command::Code = command::Code::SignAttestationCertificate;
}

#[allow(clippy::len_without_is_empty)]
impl AttestationCertificate {
    /// Unwrap inner byte vector
    pub fn into_vec(self) -> Vec<u8> {
        self.into()
    }

    /// Get length of the certificate
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Get slice of the inner byte vector
    pub fn as_slice(&self) -> &[u8] {
        self.as_ref()
    }
}

impl AsRef<[u8]> for AttestationCertificate {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl Into<Vec<u8>> for AttestationCertificate {
    fn into(self) -> Vec<u8> {
        self.0
    }
}
