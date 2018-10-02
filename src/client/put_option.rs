//! Put auditing options which have been configured on the device.
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Option.html>

use audit::*;
use command::{Command, CommandCode};
use response::Response;

/// Request parameters for `command::put_option`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutOptionCommand {
    /// Tag byte for `Force` vs `Command` options
    pub tag: AuditTag,

    /// Length of the option-specific data
    pub length: u16,

    /// Option specific data
    pub value: Vec<u8>,
}

impl Command for PutOptionCommand {
    type ResponseType = PutOptionResponse;
}

/// Response from `command::put_option`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutOptionResponse {}

impl Response for PutOptionResponse {
    const COMMAND_CODE: CommandCode = CommandCode::PutOption;
}
