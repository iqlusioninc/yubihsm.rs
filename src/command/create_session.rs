//! Create a new encrypted session with the YubiHSM2 using the given connector
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Create_Session.html>

use super::{Command, Response};
use serialization::deserialize;
use session::{
    securechannel::{Challenge, Cryptogram},
    CommandMessage, ResponseMessage,
};
use session::{SessionError, SessionErrorKind::*};
use {CommandType, Connection, ObjectId, SessionId};

/// Create a new encrypted session with the YubiHSM2 using the given connector
pub(crate) fn create_session<A: Connection>(
    connection: &A,
    auth_key_id: ObjectId,
    host_challenge: Challenge,
) -> Result<(SessionId, CreateSessionResponse), SessionError> {
    let command_message: CommandMessage = CreateSessionCommand {
        auth_key_id,
        host_challenge,
    }.into();

    let uuid = command_message.uuid;
    let response_body = connection.send_message(uuid, command_message.into())?;
    let response_message = ResponseMessage::parse(response_body)?;

    if response_message.is_err() {
        fail!(ResponseError, "HSM error: {:?}", response_message.code);
    }

    if response_message.command().unwrap() != CommandType::CreateSession {
        fail!(
            ProtocolError,
            "command type mismatch: expected {:?}, got {:?}",
            CommandType::CreateSession,
            response_message.command().unwrap()
        );
    }

    let session_id = response_message
        .session_id
        .ok_or_else(|| err!(CreateFailed, "no session ID in response"))?;

    let session_response = deserialize(response_message.data.as_ref())?;

    Ok((session_id, session_response))
}

/// Request parameters for `command::create_session`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct CreateSessionCommand {
    /// Authentication key ID to use
    pub auth_key_id: ObjectId,

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
    const COMMAND_TYPE: CommandType = CommandType::CreateSession;
}
