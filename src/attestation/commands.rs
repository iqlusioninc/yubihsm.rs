//! Obtain an X.509 attestation certificate for a key within the `YubiHSM 2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Sign_Attestation_Certificate.html>

use super::certificate::Certificate;
use crate::{
    command::{self, Command},
    object,
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::attest_asymmetric`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SignAttestationCertificateCommand {
    /// Key that attestation certificate will be generated for
    pub key_id: object::Id,

    /// Key to use to sign attestation certificate
    pub attestation_key_id: object::Id,
}

impl Command for SignAttestationCertificateCommand {
    type ResponseType = Certificate;
}

/// DER encoded X.509 attestation certificate
#[derive(Serialize, Deserialize, Debug)]
pub struct SignAttestationCertificateResponse(Certificate);

impl Response for Certificate {
    const COMMAND_CODE: command::Code = command::Code::SignAttestationCertificate;
}
