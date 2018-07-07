//! Get information about an object
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Object_Info.html>
//!
use super::{Command, Response};
use {
    Algorithm, Capability, CommandType, Connector, Domain, ObjectId, ObjectLabel, ObjectOrigin,
    ObjectType, SequenceId, Session, SessionError,
};

/// Get information about an object
pub fn get_object_info<C: Connector>(
    session: &mut Session<C>,
    object_id: ObjectId,
    object_type: ObjectType,
) -> Result<ObjectInfo, SessionError> {
    session.send_encrypted_command(GetObjectInfoCommand {
        object_id,
        object_type,
    })
}

/// Request parameters for `commands::get_object_info`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetObjectInfoCommand {
    /// Object ID to obtain information about
    pub object_id: ObjectId,

    /// Type of object to obtain information about
    pub object_type: ObjectType,
}

impl Command for GetObjectInfoCommand {
    type ResponseType = ObjectInfo;
}

/// Response from `commands::get_object_info`
#[derive(Serialize, Deserialize, Debug)]
pub struct ObjectInfo {
    /// Capabilities (bitfield)
    pub capabilities: Capability,

    /// Object identifier
    pub id: u16,

    /// Length of object in bytes
    pub length: u16,

    /// Domains from which object is accessible
    pub domains: Domain,

    /// Object type
    pub object_type: ObjectType,

    /// Algorithm this object is intended to be used with
    pub algorithm: Algorithm,

    /// Sequence: number of times an object with this key ID and type has
    /// previously existed
    pub sequence: SequenceId,

    /// How did this object originate? (generated, imported, etc)
    pub origin: ObjectOrigin,

    /// Label of object
    pub label: ObjectLabel,

    /// Delegated Capabilities (bitfield)
    pub delegated_capabilities: Capability,
}

impl Response for ObjectInfo {
    const COMMAND_TYPE: CommandType = CommandType::GetObjectInfo;
}
