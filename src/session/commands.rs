//! Create a new encrypted session with the YubiHSM 2 using the given connector
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Create_Session.html>

use super::securechannel::{Challenge, Cryptogram};
use crate::{
    command::{self, Command},
    object,
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::create_session`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct CreateSessionCommand {
    /// Authentication key ID to use
    pub authentication_key_id: object::Id,

    /// Randomly generated challenge from the host
    pub host_challenge: Challenge,
}

impl Command for CreateSessionCommand {
    type ResponseType = CreateSessionResponse;
}

/// Response from `command::create_session`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct CreateSessionResponse {
    /// Randomly generated challenge from the card
    pub card_challenge: Challenge,

    /// MAC-like authentication tag across host and card challenges
    pub card_cryptogram: Cryptogram,
}

impl Response for CreateSessionResponse {
    const COMMAND_CODE: command::Code = command::Code::CreateSession;
}

/// Close the current session and release its resources for reuse
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Close_Session.html>
#[derive(Serialize, Deserialize, Debug)]
pub(super) struct CloseSessionCommand {}

impl Command for CloseSessionCommand {
    type ResponseType = CloseSessionResponse;
}

#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct CloseSessionResponse {}

impl Response for CloseSessionResponse {
    const COMMAND_CODE: command::Code = command::Code::CloseSession;
}
