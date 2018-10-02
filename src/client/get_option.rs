//! Get auditing options which have been configured on the device.
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Option.html>

use audit::*;
use command::{Command, CommandCode};
use response::Response;

/// Request parameters for `command::get_option`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetOptionCommand {
    /// Tag byte for `Force` vs `Command` options
    pub tag: AuditTag,
}

impl Command for GetOptionCommand {
    type ResponseType = GetOptionResponse;
}

/// Response from `command::get_option`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetOptionResponse(pub(crate) Vec<u8>);

impl Response for GetOptionResponse {
    const COMMAND_CODE: CommandCode = CommandCode::GetOption;
}
