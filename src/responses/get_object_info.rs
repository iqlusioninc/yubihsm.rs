//! Response from `CommandType::GetObjectInfo`

use {Algorithm, Capabilities, Domains, ObjectLabel, ObjectOrigin, ObjectType, SequenceId};
use super::{CommandType, Response};

/// Response from `CommandType::GetObjectInfo`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Get_Object_Info.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct GetObjectInfoResponse {
    /// Capabilities
    pub capabilities: Capabilities,

    /// Object identifier
    pub id: u16,

    /// Length of object in bytes
    pub length: u16,

    /// Domains from which object is accessible
    pub domains: Domains,

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

    /// Delegated Capabilities
    pub delegated_capabilities: Capabilities,
}

impl Response for GetObjectInfoResponse {
    const COMMAND_TYPE: CommandType = CommandType::GetObjectInfo;
}
