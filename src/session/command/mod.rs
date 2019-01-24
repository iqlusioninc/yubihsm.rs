//! HSM commands used for session management

pub(crate) mod close;
pub(crate) mod create;

use self::create::*;
use super::{securechannel::Challenge, SessionError, SessionErrorKind::*, SessionId};
use crate::command::{CommandCode, CommandMessage};
use crate::connector::Connection;
use crate::object::ObjectId;
use crate::response::ResponseMessage;
use crate::serialization::deserialize;

/// Create a new encrypted session with the HSM over the given `Connection`
pub(super) fn create_session(
    connection: &Connection,
    auth_key_id: ObjectId,
    host_challenge: Challenge,
) -> Result<(SessionId, CreateSessionResponse), SessionError> {
    let command_message: CommandMessage = CreateSessionCommand {
        auth_key_id,
        host_challenge,
    }
    .into();

    let uuid = command_message.uuid;
    let response_body = connection.send_message(uuid, command_message.into())?;
    let response_message = ResponseMessage::parse(response_body)?;

    if response_message.is_err() {
        fail!(ResponseError, "HSM error: {:?}", response_message.code);
    }

    if response_message.command().unwrap() != CommandCode::CreateSession {
        fail!(
            ProtocolError,
            "command type mismatch: expected {:?}, got {:?}",
            CommandCode::CreateSession,
            response_message.command().unwrap()
        );
    }

    let session_id = response_message
        .session_id
        .ok_or_else(|| err!(CreateFailed, "no session ID in response"))?;

    let session_response = deserialize(response_message.data.as_ref())?;

    Ok((session_id, session_response))
}
