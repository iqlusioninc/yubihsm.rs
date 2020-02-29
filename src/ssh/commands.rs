//! Secure Shell (SSH) Certificate Authority Commands
//!
//! **WARNING**: This functionality has not been tested and has not yet been
//! confirmed to actually work! USE AT YOUR OWN RISK!
//!
//! You will need to enable the `untested` cargo feature to use it.

use crate::{
    algorithm::Algorithm,
    command::{self, Command},
    object,
    response::Response,
    ssh,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::sign_ssh_certificate`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SignSshCertificateCommand {
    /// Object ID of the asymmetric key to perform the signature with
    pub key_id: object::Id,

    /// Object ID of the SSH certificate template
    pub template_id: object::Id,

    /// Algorithm
    pub algorithm: Algorithm,

    /// Timestamp
    pub timestamp: u32,

    /// Signature over the request and timestamp
    pub signature: [u8; 32],

    /// Data to be signed
    pub request: Vec<u8>,
}

impl Command for SignSshCertificateCommand {
    type ResponseType = SignSshCertificateResponse;
}

/// Signed SSH certificates
#[derive(Serialize, Deserialize, Debug)]
pub struct SignSshCertificateResponse(ssh::Certificate);

impl Response for SignSshCertificateResponse {
    const COMMAND_CODE: command::Code = command::Code::SignSshCertificate;
}

impl From<SignSshCertificateResponse> for ssh::Certificate {
    fn from(response: SignSshCertificateResponse) -> ssh::Certificate {
        response.0
    }
}
