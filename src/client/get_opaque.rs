//! Get the public key for an asymmetric key stored on the device
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Opaque.html>

use command::{Command, CommandCode};
use object::ObjectId;
use response::Response;

/// Request parameters for `command::get_opaque`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetOpaqueCommand {
    /// Object ID of the key to obtain the corresponding opaque for
    pub object_id: ObjectId,
}

impl Command for GetOpaqueCommand {
    type ResponseType = GetOpaqueResponse;
}

/// Response from `command::get_opaque`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetOpaqueResponse(pub(crate) Vec<u8>);

impl Response for GetOpaqueResponse {
    const COMMAND_CODE: CommandCode = CommandCode::GetOpaqueObject;
}
