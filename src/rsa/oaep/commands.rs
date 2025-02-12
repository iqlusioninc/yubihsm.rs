//! RSA OAEP commands

use crate::{
    command::{self, Command},
    object,
    response::Response,
    rsa,
};
use serde::{de::Deserializer, Deserialize, Serialize};
use sha1::Sha1;
use sha2::{
    digest::{typenum::Unsigned, OutputSizeUser},
    Sha256, Sha384, Sha512,
};

/// Request parameters for `command::decrypt_rsa_oaep`
#[derive(Serialize, Debug)]
pub(crate) struct DecryptOaepCommand {
    /// ID of the decryption key
    pub key_id: object::Id,

    /// Hash algorithm to use for MGF1
    pub mgf1_hash_alg: rsa::mgf::Algorithm,

    /// Data to be decrypted
    pub data: Vec<u8>,

    /// Hash of the OAEP label
    pub label_hash: Vec<u8>,
}

impl Command for DecryptOaepCommand {
    type ResponseType = DecryptOaepResponse;
}

/// RSA OAEP decrypted data
#[derive(Serialize, Deserialize, Debug)]
pub struct DecryptOaepResponse(pub(crate) rsa::oaep::DecryptedData);

impl Response for DecryptOaepResponse {
    const COMMAND_CODE: command::Code = command::Code::DecryptOaep;
}

impl From<DecryptOaepResponse> for rsa::oaep::DecryptedData {
    fn from(response: DecryptOaepResponse) -> rsa::oaep::DecryptedData {
        response.0
    }
}

impl<'de> Deserialize<'de> for DecryptOaepCommand {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct DecryptOaepCommand {
            /// ID of the decryption key
            key_id: object::Id,

            /// Hash algorithm to use for MGF1
            mgf1_hash_alg: rsa::mgf::Algorithm,

            /// Data to be decrypted
            data: Vec<u8>,
        }

        let mut value = DecryptOaepCommand::deserialize(deserializer)?;

        let label_hash = match value.mgf1_hash_alg {
            rsa::mgf::Algorithm::Sha1 => value
                .data
                .split_off(value.data.len() - <Sha1 as OutputSizeUser>::OutputSize::USIZE),
            rsa::mgf::Algorithm::Sha256 => value
                .data
                .split_off(value.data.len() - <Sha256 as OutputSizeUser>::OutputSize::USIZE),
            rsa::mgf::Algorithm::Sha384 => value
                .data
                .split_off(value.data.len() - <Sha384 as OutputSizeUser>::OutputSize::USIZE),
            rsa::mgf::Algorithm::Sha512 => value
                .data
                .split_off(value.data.len() - <Sha512 as OutputSizeUser>::OutputSize::USIZE),
        };

        Ok(Self {
            key_id: value.key_id,
            mgf1_hash_alg: value.mgf1_hash_alg,
            data: value.data,
            label_hash,
        })
    }
}
