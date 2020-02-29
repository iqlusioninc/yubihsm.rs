//! Elliptic Curve Diffie Hellman Commands
//!
//! **WARNING**: This functionality has not been tested and has not yet been
//! confirmed to actually work! USE AT YOUR OWN RISK!
//!
//! You will need to enable the `untested` cargo feature to use it.
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Derive_Ecdh.html>

use crate::{
    command::{self, Command},
    ecdh, object,
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::derive_ecdh`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct DeriveEcdhCommand {
    /// Object ID of the asymmetric key to perform ECDH with
    pub key_id: object::Id,

    /// Uncompressed curve point to compute ECDH with
    pub public_key: ecdh::UncompressedPoint,
}

impl Command for DeriveEcdhCommand {
    type ResponseType = DeriveEcdhResponse;
}

/// Signed SSH certificates
#[derive(Serialize, Deserialize, Debug)]
pub struct DeriveEcdhResponse(ecdh::UncompressedPoint);

impl Response for DeriveEcdhResponse {
    const COMMAND_CODE: command::Code = command::Code::DeriveEcdh;
}

impl From<DeriveEcdhResponse> for ecdh::UncompressedPoint {
    fn from(response: DeriveEcdhResponse) -> ecdh::UncompressedPoint {
        response.0
    }
}
