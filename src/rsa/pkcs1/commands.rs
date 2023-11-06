//! RSASSA-PKCS#1v1.5 commands

use crate::{
    command::{self, Command},
    object,
    response::Response,
    rsa,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::sign_rsa_pkcs1v15*`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SignPkcs1Command {
    /// ID of the key to perform the signature with
    pub key_id: object::Id,

    /// Digest of data to be signed
    pub digest: Vec<u8>,
}

impl Command for SignPkcs1Command {
    type ResponseType = SignPkcs1Response;
}

/// RSASSA-PKCS#1v1.5 signatures (ASN.1 DER encoded)
#[derive(Serialize, Deserialize, Debug)]
pub struct SignPkcs1Response(pub(crate) rsa::pkcs1::Signature);

impl Response for SignPkcs1Response {
    const COMMAND_CODE: command::Code = command::Code::SignPkcs1;
}

impl From<SignPkcs1Response> for rsa::pkcs1::Signature {
    fn from(response: SignPkcs1Response) -> rsa::pkcs1::Signature {
        response.0
    }
}
