//! Get the public key for an asymmetric key stored on the device
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Opaque.html>

use super::{Command, Response};
use {Client, ClientError, CommandType, Connection, ObjectId};

/// Get the public key for an asymmetric key stored on the device
pub fn get_opaque<A: Connection>(
    session: &mut Client<A>,
    object_id: ObjectId,
) -> Result<Vec<u8>, ClientError> {
    session
        .send_command(GetOpaqueCommand { object_id })
        .map(|response| response.0)
}

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
    const COMMAND_TYPE: CommandType = CommandType::GetOpaqueObject;
}
