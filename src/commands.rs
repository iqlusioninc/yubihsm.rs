//! Command (i.e. request) structs for `YubiHSM2` commands
//!
//! <https://developers.yubico.com/YubiHSM2/Commands>

use responses::Response;
use securechannel::{CommandMessage, CommandType};
use serde::ser::Serialize;
use serde::de::DeserializeOwned;
use serializers::serialize;

use {Algorithm, Capabilities, Domains, ObjectId, ObjectLabel, ObjectType};
use securechannel::Challenge;
use responses::*;

pub(crate) trait Command: Serialize + DeserializeOwned + Sized {
    /// Response type for this command
    type ResponseType: Response;

    /// Command ID for this command
    const COMMAND_TYPE: CommandType = Self::ResponseType::COMMAND_TYPE;
}

impl<C: Command> From<C> for CommandMessage {
    fn from(command: C) -> CommandMessage {
        Self::new(C::COMMAND_TYPE, serialize(&command).unwrap())
    }
}

/// Request parameters for `CommandType::CreateSession`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Create_Session.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct CreateSessionCommand {
    /// Authentication key ID to use
    pub auth_key_id: ObjectId,

    /// Randomly generated challenge from the host
    pub host_challenge: Challenge,
}

impl Command for CreateSessionCommand {
    type ResponseType = CreateSessionResponse;
}

/// Request parameters for `CommandType::DeleteObject`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Delete_Object.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteObjectCommand {
    /// Object ID to delete
    pub object_id: ObjectId,

    /// Type of object to delete
    pub object_type: ObjectType,
}

impl Command for DeleteObjectCommand {
    type ResponseType = DeleteObjectResponse;
}

/// Request parameters for `CommandType::Echo`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Echo.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct EchoCommand {
    /// Message to echo
    pub message: Vec<u8>,
}

impl Command for EchoCommand {
    type ResponseType = EchoResponse;
}

/// Request parameters for `CommandType::GenAsymmetricKey`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Generate_Asymmetric_Key.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct GenAsymmetricKeyCommand {
    /// ID of the key
    pub key_id: ObjectId,

    /// Label for the key (40-bytes)
    pub label: ObjectLabel,

    /// Domains in which the key will be accessible
    pub domains: Domains,

    /// Capabilities of the key
    pub capabilities: Capabilities,

    /// Key algorithm
    pub algorithm: Algorithm,
}

impl Command for GenAsymmetricKeyCommand {
    type ResponseType = GenAsymmetricKeyResponse;
}

/// Request parameters for `CommandType::GetPubKey`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Get_Pubkey.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct GetPubKeyCommand {
    /// Object ID of the key to obtain the corresponding pubkey for
    pub key_id: ObjectId,
}

impl Command for GetPubKeyCommand {
    type ResponseType = GetPubKeyResponse;
}

/// Request parameters for `CommandType::GetObjectInfo`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Delete_Object.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct GetObjectInfoCommand {
    /// Object ID to obtain information about
    pub object_id: ObjectId,

    /// Type of object to obtain information about
    pub object_type: ObjectType,
}

impl Command for GetObjectInfoCommand {
    type ResponseType = GetObjectInfoResponse;
}

/// Request parameters for `CommandType::ListObjects`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/List_Objects.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct ListObjectsCommand {}

impl Command for ListObjectsCommand {
    type ResponseType = ListObjectsResponse;
}

/// Request parameters `CommandType::SignDataEdDSA`
#[derive(Serialize, Deserialize, Debug)]
pub struct SignDataEdDSACommand {
    /// ID of the key to perform the signature with
    pub key_id: ObjectId,

    /// Data to be signed
    pub data: Vec<u8>,
}

impl Command for SignDataEdDSACommand {
    type ResponseType = SignDataEdDSAResponse;
}
