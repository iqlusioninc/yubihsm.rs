//! Create a new encrypted session with the YubiHSM2 using the given connector
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Create_Session.html>

use super::{
    securechannel::{Challenge, Cryptogram},
    SessionError,
    SessionErrorKind::*,
};
use crate::{
    command::{self, Command},
    connector::Connection,
    object,
    response::{self, Response},
    serialization::deserialize,
    session,
};

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

/// Create a new encrypted session with the HSM over the given `Connection`
pub(super) fn create_session(
    connection: &dyn Connection,
    authentication_key_id: object::Id,
    host_challenge: Challenge,
) -> Result<(session::Id, CreateSessionResponse), SessionError> {
    let command_message: command::Message = CreateSessionCommand {
        authentication_key_id,
        host_challenge,
    }
    .into();

    let uuid = command_message.uuid;
    let response_body = connection.send_message(uuid, command_message.into())?;
    let response_message = response::Message::parse(response_body)?;

    if response_message.is_err() {
        fail!(ResponseError, "HSM error: {:?}", response_message.code);
    }

    if response_message.command().unwrap() != command::Code::CreateSession {
        fail!(
            ProtocolError,
            "command type mismatch: expected {:?}, got {:?}",
            command::Code::CreateSession,
            response_message.command().unwrap()
        );
    }

    let session_id = response_message
        .session_id
        .ok_or_else(|| err!(CreateFailed, "no session ID in response"))?;

    let session_response = deserialize(response_message.data.as_ref())?;

    Ok((session_id, session_response))
}
