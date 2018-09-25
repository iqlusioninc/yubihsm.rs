//! Set the index of the last consumed entry in the `YubiHSM2` audit log.
//! Useful in conjunction with the force audit option, which blocks performing
//! audited HSM operations until audit data has been consumed from the device.
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Set_Log_Index.html>

use super::{Command, CommandType, Response};
use adapter::Adapter;
use client::{Client, SessionError};

/// Set the index of the last consumed index of the `YubiHSM2` audit log
pub fn set_log_index<A: Adapter>(
    session: &mut Client<A>,
    log_index: u16,
) -> Result<(), SessionError> {
    session.send_command(SetLogIndexCommand { log_index })?;
    Ok(())
}

/// Request parameters for `command::set_log_index`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SetLogIndexCommand {
    /// Index of the last log entry seen
    pub log_index: u16,
}

impl Command for SetLogIndexCommand {
    type ResponseType = SetLogIndexResponse;
}

/// Response from `command::set_log_index`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SetLogIndexResponse {}

impl Response for SetLogIndexResponse {
    const COMMAND_TYPE: CommandType = CommandType::SetLogIndex;
}
