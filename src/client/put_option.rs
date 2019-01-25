//! Put auditing options which have been configured on the device.
//!
//! The following methods of [yubihsm::Client] implement this command:
//!
//! - [put_command_audit_option()]: set options for a particular command
//! - [put_force_audit_option()]: force auditing (require all events be logged)
//!
//! For more information, see:
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Option.html>
//!
//! [yubihsm::Client]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html
//! [put_command_audit_option()]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.put_command_audit_option
//! [put_force_audit_option()]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.put_force_audit_option

use crate::audit::*;
use crate::command::{Command, CommandCode};
use crate::response::Response;

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
    const COMMAND_CODE: CommandCode = CommandCode::SetOption;
}
