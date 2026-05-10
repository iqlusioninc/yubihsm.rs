//! Authentication key commands for the `YubiHSM 2`
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Authentication_Key.html>
//! <https://developers.yubico.com/YubiHSM2/Commands/Change_Authentication_Key.html>

use crate::{
    authentication,
    capability::Capability,
    command::{self, Command},
    object,
    response::Response,
    Algorithm,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::put_authentication_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutAuthenticationKeyCommand {
    /// Common parameters to all put object command
    pub params: object::put::Params,

    /// Delegated capabilities
    pub delegated_capabilities: Capability,

    /// Authentication key
    pub authentication_key: authentication::Key,
}

impl Command for PutAuthenticationKeyCommand {
    type ResponseType = PutAuthenticationKeyResponse;
}

/// Response from `command::put_authentication_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutAuthenticationKeyResponse {
    /// ID of the key
    pub key_id: object::Id,
}

impl Response for PutAuthenticationKeyResponse {
    const COMMAND_CODE: command::Code = command::Code::PutAuthenticationKey;
}

/// Request parameters for `command::change_authentication_key`
///
/// Available with firmware version 2.2.0 or later.
/// Atomically replaces the key material of the Authentication Key used to
/// establish the current session, preserving all metadata (domains,
/// capabilities, delegated capabilities).
///
/// Protocol: `Tc = 0x6c  Vc = I || A || Ke || Km`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ChangeAuthenticationKeyCommand {
    /// Object ID of the authentication key to change (must be the session key)
    pub key_id: object::Id,

    /// Algorithm identifier (1 byte)
    pub algorithm: Algorithm,

    /// New authentication key (Ke || Km, 32 bytes)
    pub authentication_key: authentication::Key,
}

impl Command for ChangeAuthenticationKeyCommand {
    type ResponseType = ChangeAuthenticationKeyResponse;
}

/// Response from `command::change_authentication_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ChangeAuthenticationKeyResponse {
    /// ID of the changed key
    pub key_id: object::Id,
}

impl Response for ChangeAuthenticationKeyResponse {
    const COMMAND_CODE: command::Code = command::Code::ChangeAuthenticationKey;
}
