//! Set the index of the last consumed entry in the `YubiHSM 2` audit log.
//! Useful in conjunction with the force audit option, which blocks performing
//! audited HSM operations until audit data has been consumed from the device.
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Set_Log_Index.html>

use crate::{
    command::{self, Command},
    response::Response,
};
use serde::{Deserialize, Serialize};

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
    const COMMAND_CODE: command::Code = command::Code::SetLogIndex;
}
