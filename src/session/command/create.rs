//! Create a new encrypted session with the YubiHSM2 using the given connector
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Create_Session.html>

use crate::command::{Command, CommandCode};
use crate::object::ObjectId;
use crate::response::Response;
use crate::session::securechannel::{Challenge, Cryptogram};

/// Request parameters for `command::create_session`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct CreateSessionCommand {
    /// Authentication key ID to use
    pub authentication_key_id: ObjectId,

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
    const COMMAND_CODE: CommandCode = CommandCode::CreateSession;
}
