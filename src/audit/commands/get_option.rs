//! Get auditing options which have been configured on the device.
//!
//! The following methods of [yubihsm::Client] implement this command:
//!
//! - [get_command_audit_option()]: get audit setting for a particular command
//! - [get_commands_audit_options()]: get audit settings for all command
//! - [get_force_audit_option()]: get option for forced auditing (ensure events are logged)
//!
//! For more information, see:
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Option.html>
//!
//! [yubihsm::Client]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html
//! [get_command_audit_option()]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.get_command_audit_option
//! [get_commands_audit_options()]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.get_commands_audit_options
//! [get_force_audit_option()]: https://docs.rs/yubihsm/latest/yubihsm/client/struct.Client.html#method.get_force_audit_option

use crate::{
    audit::AuditTag,
    command::{self, Command},
    response::Response,
};
use serde::{Deserialize, Serialize};

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
    const COMMAND_CODE: command::Code = command::Code::GetOption;
}
