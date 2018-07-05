#![allow(unused_imports)]

pub use failure::Error;
#[cfg(feature = "mockhsm")]
use securechannel::ResponseMessage;
pub(crate) use securechannel::{CommandType, ResponseCode};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
use std::fmt::{self, Debug};

use securechannel::{Challenge, Cryptogram};
#[cfg(feature = "mockhsm")]
use serializers::serialize;
use {Algorithm, Capability, Domain, ObjectId, ObjectLabel, ObjectOrigin, ObjectType, SequenceId};

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

/// Response from `CommandType::Blink`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Blink.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct BlinkResponse {}

impl Response for BlinkResponse {
    const COMMAND_TYPE: CommandType = CommandType::Blink;
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

/// Response from `CommandType::GetDeviceInfo`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Device_Info.html>
///
#[derive(Serialize, Deserialize, Debug)]
pub struct GetDeviceInfoResponse {
    /// Device major version
    pub major_version: u8,

    /// Device minor version
    pub minor_version: u8,

    /// Device build version (i.e. patchlevel)
    pub build_version: u8,

    /// Device serial number
    pub serial_number: u32,

    /// Size of the log store (in lines/entries)
    pub log_store_capacity: u8,

    /// Number of log lines used
    pub log_store_used: u8,

    /// Supported algorithms
    pub algorithms: Vec<Algorithm>,
}

impl Response for GetDeviceInfoResponse {
    const COMMAND_TYPE: CommandType = CommandType::GetDeviceInfo;
}

/// Response from `CommandType::GetLogs`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Get_Logs.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct GetLogsResponse {
    /// Number of boot events which weren't logged (if buffer is full and audit enforce is set)
    pub unlogged_boot_events: u16,

    /// Number of unlogged authentication events (if buffer is full and audit enforce is set)
    pub unlogged_auth_events: u16,

    /// Number of entries in the response
    pub num_entries: u8,

    /// Entries in the log
    pub entries: Vec<LogEntry>,
}

impl Response for GetLogsResponse {
    const COMMAND_TYPE: CommandType = CommandType::GetLogs;
}

/// Entry in the log response
#[derive(Serialize, Deserialize, Debug)]
pub struct LogEntry {
    /// Entry number
    pub item: u16,

    /// Command type
    pub cmd: CommandType,

    /// Command length
    pub length: u16,

    /// Session key ID
    pub session_key: ObjectId,

    /// Target key ID
    pub target_key: ObjectId,

    /// Second key affected
    pub second_key: ObjectId,

    /// Result of the operation
    pub result: ResponseCode,

    /// Tick count of the HSM's internal clock
    pub tick: u32,

    /// 16-byte truncated SHA-256 digest of this log entry and the digest of the previous entry
    pub digest: LogDigest,
}

/// Size of a truncated digest in the log
pub const LOG_DIGEST_SIZE: usize = 16;

/// Truncated SHA-256 digest of a log entry and the previous log digest
#[derive(Serialize, Deserialize)]
pub struct LogDigest(pub [u8; LOG_DIGEST_SIZE]);

impl AsRef<[u8]> for LogDigest {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl Debug for LogDigest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LogDigest(")?;
        for (i, byte) in self.0.iter().enumerate() {
            write!(f, "{:02x}", byte)?;
            write!(f, "{}", if i == LOG_DIGEST_SIZE - 1 { ")" } else { ":" })?;
        }
        Ok(())
    }
}

/// Response from `CommandType::GetObjectInfo`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Get_Object_Info.html>
#[derive(Serialize, Deserialize, Debug)]
pub struct GetObjectInfoResponse {
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
    ///
    /// In particular note that in the case of e.g. ECDSA public keys, many
    /// libraries will expect a 0x04 (DER OCTET STRING) tag byte at the
    /// beginning of the key. The YubiHSM does not return this, so you may
    /// need to add it depending on your particular application.
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

/// Response from `CommandType::SignDataECDSA`
#[derive(Serialize, Deserialize, Debug)]
pub struct SignDataECDSAResponse {
    /// ECDSA signature (ASN.1 DER encoded)
    pub signature: Vec<u8>,
}

impl Response for SignDataECDSAResponse {
    const COMMAND_TYPE: CommandType = CommandType::SignDataECDSA;
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
