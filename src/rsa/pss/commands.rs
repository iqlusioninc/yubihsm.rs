//! RSASSA-PSS commands

use crate::{
    command::{self, Command},
    object,
    response::Response,
    rsa,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::sign_rsa_pss*`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SignPssCommand {
    /// ID of the key to perform the signature with
    pub key_id: object::Id,

    /// Hash algorithm to use for MGF1
    pub mgf1_hash_alg: rsa::mgf::Algorithm,

    /// Salt length
    pub salt_len: u16,

    /// Digest of data to be signed
    pub digest: Vec<u8>,
}

impl Command for SignPssCommand {
    type ResponseType = SignPssResponse;
}

/// RSASSA-PSS signatures (ASN.1 DER encoded)
#[derive(Serialize, Deserialize, Debug)]
pub struct SignPssResponse(pub(crate) rsa::pss::Signature);

impl Response for SignPssResponse {
    const COMMAND_CODE: command::Code = command::Code::SignPss;
}

impl From<SignPssResponse> for rsa::pss::Signature {
    fn from(response: SignPssResponse) -> rsa::pss::Signature {
        response.0
    }
}
