//! Set the index of the last consumed index of the `YubiHSM2` audit log
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Set_Log_Index.html>

use super::{Command, CommandType, Response};
use connector::Connector;
use session::{Session, SessionError};

/// Set the index of the last consumed index of the `YubiHSM2` audit log
pub fn set_log_index<C: Connector>(
    session: &mut Session<C>,
    log_index: u16,
) -> Result<(), SessionError> {
    session.send_encrypted_command(SetLogIndexCommand { log_index })?;
    Ok(())
}

/// Request parameters for `commands::set_log_index`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SetLogIndexCommand {
    /// Number of seconds to set_log_index for
    pub log_index: u16,
}

impl Command for SetLogIndexCommand {
    type ResponseType = SetLogIndexResponse;
}

/// Response from `commands::set_log_index`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SetLogIndexResponse {}

impl Response for SetLogIndexResponse {
    const COMMAND_TYPE: CommandType = CommandType::SetLogIndex;
}
