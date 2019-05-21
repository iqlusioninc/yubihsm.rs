//! Set auditing options which have been configured on the device.
//!
//! For more information, see:
//! <https://developers.yubico.com/YubiHSM2/Commands/Set_Option.html>

use crate::{
    audit::*,
    command::{self, Command},
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::put_option`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SetOptionCommand {
    /// Tag byte for `Force` vs `Command` options
    pub tag: AuditTag,

    /// Length of the option-specific data
    pub length: u16,

    /// Option specific data
    pub value: Vec<u8>,
}

impl Command for SetOptionCommand {
    type ResponseType = PutOptionResponse;
}

/// Response from `command::put_option`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutOptionResponse {}

impl Response for PutOptionResponse {
    const COMMAND_CODE: command::Code = command::Code::SetOption;
}
