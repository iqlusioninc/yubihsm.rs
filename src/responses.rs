//! Responses to commands sent from the HSM, intended as part of the public
//! API of this crate.

pub use failure::Error;
pub(crate) use securechannel::CommandType;
#[cfg(feature = "mockhsm")]
use securechannel::ResponseMessage;
use serde::ser::Serialize;
use serde::de::DeserializeOwned;

use {Algorithm, Capabilities, Domains, ObjectId, ObjectLabel, ObjectOrigin, ObjectType, SequenceId};
use securechannel::{Challenge, Cryptogram};
#[cfg(feature = "mockhsm")]
use serializers::serialize;

/// Structured responses to `Command` messages sent from the HSM
pub(crate) trait Response: Serialize + DeserializeOwned + Sized {
    /// Command ID this response is for
    const COMMAND_TYPE: CommandType;

    /// Serialize a response type into a ResponseMessage
    #[cfg(feature = "mockhsm")]
    fn serialize(&self) -> ResponseMessage {
        ResponseMessage::success(Self::COMMAND_TYPE, serialize(self).unwrap())
    }
}

/// Response from `CommandType::CreateSession`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Create_Session.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct CreateSessionResponse {
    /// Randomly generated challenge from the card
    pub card_challenge: Challenge,

    /// MAC-like authentication tag across host and card challenges
    pub card_cryptogram: Cryptogram,
}

impl Response for CreateSessionResponse {
    const COMMAND_TYPE: CommandType = CommandType::CreateSession;
}

/// Response from `CommandType::DeleteObject`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Delete_Object.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct DeleteObjectResponse {}

impl Response for DeleteObjectResponse {
    const COMMAND_TYPE: CommandType = CommandType::DeleteObject;
}

/// Response from `CommandType::Echo`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Echo.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct EchoResponse {
    /// Echo response
    pub message: Vec<u8>,
}

impl Response for EchoResponse {
    const COMMAND_TYPE: CommandType = CommandType::Echo;
}

/// Response from `CommandType::GenAsymmetricKey`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Generate_Asymmetric_Key.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct GenAsymmetricKeyResponse {
    /// ID of the key
    pub key_id: ObjectId,
}

impl Response for GenAsymmetricKeyResponse {
    const COMMAND_TYPE: CommandType = CommandType::GenAsymmetricKey;
}

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

/// Response from `CommandType::GetPubKey`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Get_Pubkey.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct GetPubKeyResponse {
    /// Algorithm of the public key
    pub algorithm: Algorithm,

    /// The public key in raw bytes. Keys have the following structure:
    ///
    /// - RSA: Public modulus N (0x100 | 0x200 | 0x400 bytes)
    /// - ECC (non-Ed25519):
    ///   - Public point X (0x20 | 0x30 | 0x40 | 0x42 bytes)
    ///   - Public point Y (0x20 | 0x30 | 0x40 | 0x42 bytes)
    /// - Ed25519: Public point A, compressed (0x20 bytes)
    pub data: Vec<u8>,
}

impl Response for GetPubKeyResponse {
    const COMMAND_TYPE: CommandType = CommandType::GetPubKey;
}

/// Response from `CommandType::ListObjects`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/List_Objects.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct ListObjectsResponse {
    /// Objects in the response
    pub objects: Vec<ListObjectsEntry>,
}

/// Brief information about an object as returned from the `ListObjects` command
#[derive(Serialize, Deserialize, Debug)]
pub struct ListObjectsEntry {
    /// Object identifier
    pub id: ObjectId,

    /// Object type
    pub object_type: ObjectType,

    /// Sequence: number of times an object with this key ID and type has
    /// previously existed
    pub sequence: SequenceId,
}

impl Response for ListObjectsResponse {
    const COMMAND_TYPE: CommandType = CommandType::ListObjects;
}

/// Response from `CommandType::SignDataEdDSA`
#[derive(Serialize, Deserialize, Debug)]
pub struct SignDataEdDSAResponse {
    /// Ed25519 signature (64-bytes)
    pub signature: Vec<u8>,
}

impl Response for SignDataEdDSAResponse {
    const COMMAND_TYPE: CommandType = CommandType::SignDataEdDSA;
}
