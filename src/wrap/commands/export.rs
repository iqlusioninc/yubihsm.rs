//! Export an encrypted object from the `YubiHSM 2` using the given key-wrapping key
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Export_Wrapped.html>

use crate::{
    command::{self, Command},
    object,
    response::Response,
    wrap,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::export_wrapped`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ExportWrappedCommand {
    /// ID of the wrap key to encrypt the object with
    pub wrap_key_id: object::Id,

    /// Type of object to be wrapped
    pub object_type: object::Type,

    /// Object ID of the object to be exported (in encrypted form)
    pub object_id: object::Id,
}

impl Command for ExportWrappedCommand {
    type ResponseType = ExportWrappedResponse;
}

/// Response from `command::export_wrapped`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ExportWrappedResponse(pub(crate) wrap::Message);

impl Response for ExportWrappedResponse {
    const COMMAND_CODE: command::Code = command::Code::ExportWrapped;
}
