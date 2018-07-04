use responses::Response;
use securechannel::{CommandMessage, CommandType};
use serde::de::DeserializeOwned;
use serde::ser::Serialize;
#[cfg(feature = "sha2")]
use sha2::{Digest, Sha256};

use responses::*;
use securechannel::Challenge;
use serializers::serialize;
use session::{Session, SessionError};
use {Algorithm, Capability, Connector, Domain, ObjectId, ObjectLabel, ObjectType};

/// Blink the YubiHSM2's LEDs (to identify it) for the given number of seconds
pub fn blink<C: Connector>(
    session: &mut Session<C>,
    num_seconds: u8,
) -> Result<BlinkResponse, SessionError> {
    session.send_encrypted_command(BlinkCommand { num_seconds })
}

/// Delete an object of the given ID and type
pub fn delete_object<C: Connector>(
    session: &mut Session<C>,
    object_id: ObjectId,
    object_type: ObjectType,
) -> Result<DeleteObjectResponse, SessionError> {
    session.send_encrypted_command(DeleteObjectCommand {
        object_id,
        object_type,
    })
}

/// Have the card echo an input message
pub fn echo<C, T>(session: &mut Session<C>, message: T) -> Result<EchoResponse, SessionError>
where
    C: Connector,
    T: Into<Vec<u8>>,
{
    session.send_encrypted_command(EchoCommand {
        message: message.into(),
    })
}

/// Generate a new asymmetric key within the `YubiHSM2`
pub fn generate_asymmetric_key<C: Connector>(
    session: &mut Session<C>,
    key_id: ObjectId,
    label: ObjectLabel,
    domains: Domain,
    capabilities: Capability,
    algorithm: Algorithm,
) -> Result<GenAsymmetricKeyResponse, SessionError> {
    session.send_encrypted_command(GenAsymmetricKeyCommand {
        key_id,
        label,
        domains,
        capabilities,
        algorithm,
    })
}

/// Get information about an object
pub fn get_object_info<C: Connector>(
    session: &mut Session<C>,
    object_id: ObjectId,
    object_type: ObjectType,
) -> Result<GetObjectInfoResponse, SessionError> {
    session.send_encrypted_command(GetObjectInfoCommand {
        object_id,
        object_type,
    })
}

/// Get the public key for an asymmetric key stored on the device
///
/// See `GetPubKeyResponse` for more information about public key formats
pub fn get_pubkey<C: Connector>(
    session: &mut Session<C>,
    key_id: ObjectId,
) -> Result<GetPubKeyResponse, SessionError> {
    session.send_encrypted_command(GetPubKeyCommand { key_id })
}

/// List objects visible from the current session
pub fn list_objects<C: Connector>(
    session: &mut Session<C>,
) -> Result<ListObjectsResponse, SessionError> {
    // TODO: support for filtering objects
    session.send_encrypted_command(ListObjectsCommand {})
}

/// Compute an ECDSA signature of the SHA-256 hash of the given data with the given key ID
#[cfg(feature = "sha2")]
pub fn sign_ecdsa_sha2<C: Connector>(
    session: &mut Session<C>,
    key_id: ObjectId,
    data: &[u8],
) -> Result<SignDataECDSAResponse, SessionError> {
    sign_ecdsa_fixed(session, key_id, Sha256::digest(data).as_slice())
}

/// Compute an ECDSA signature of the given fixed-sized data (i.e. digest) with the given key ID
pub fn sign_ecdsa_fixed<C, T>(
    session: &mut Session<C>,
    key_id: ObjectId,
    digest: T,
) -> Result<SignDataECDSAResponse, SessionError>
where
    C: Connector,
    T: Into<Vec<u8>>,
{
    session.send_encrypted_command(SignDataECDSACommand {
        key_id,
        digest: digest.into(),
    })
}

/// Compute an Ed25519 signature with the given key ID
pub fn sign_ed25519<C, T>(
    session: &mut Session<C>,
    key_id: ObjectId,
    data: T,
) -> Result<SignDataEdDSAResponse, SessionError>
where
    C: Connector,
    T: Into<Vec<u8>>,
{
    session.send_encrypted_command(SignDataEdDSACommand {
        key_id,
        data: data.into(),
    })
}

/// Structured commands (i.e. requests) which are encrypted and then sent to
/// the HSM. Every command has a corresponding `ResponseType`.
///
/// See <https://developers.yubico.com/YubiHSM2/Commands>
pub(crate) trait Command: Serialize + DeserializeOwned + Sized {
    /// Response type for this command
    type ResponseType: Response;

    /// Command ID for this command
    const COMMAND_TYPE: CommandType = Self::ResponseType::COMMAND_TYPE;
}

impl<C: Command> From<C> for CommandMessage {
    fn from(command: C) -> CommandMessage {
        Self::new(C::COMMAND_TYPE, serialize(&command).unwrap()).unwrap()
    }
}

/// Request parameters for `CommandType::Blink`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Blink.html>
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct BlinkCommand {
    /// Number of seconds to blink for
    pub num_seconds: u8,
}

impl Command for BlinkCommand {
    type ResponseType = BlinkResponse;
}

/// Request parameters for `CommandType::CreateSession`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Create_Session.html>
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct CreateSessionCommand {
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
pub(crate) struct DeleteObjectCommand {
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
pub(crate) struct EchoCommand {
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
pub(crate) struct GenAsymmetricKeyCommand {
    /// ID of the key
    pub key_id: ObjectId,

    /// Label for the key (40-bytes)
    pub label: ObjectLabel,

    /// Domain in which the key will be accessible
    pub domains: Domain,

    /// Capability of the key
    pub capabilities: Capability,

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
pub(crate) struct GetPubKeyCommand {
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
pub(crate) struct GetObjectInfoCommand {
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
pub(crate) struct ListObjectsCommand {}

impl Command for ListObjectsCommand {
    type ResponseType = ListObjectsResponse;
}

/// Request parameters for `CommandType::SignDataECDSA`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SignDataECDSACommand {
    /// ID of the key to perform the signature with
    pub key_id: ObjectId,

    /// Digest of data to be signed
    pub digest: Vec<u8>,
}

impl Command for SignDataECDSACommand {
    type ResponseType = SignDataECDSAResponse;
}

/// Request parameters for `CommandType::SignDataEdDSA`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct SignDataEdDSACommand {
    /// ID of the key to perform the signature with
    pub key_id: ObjectId,

    /// Data to be signed
    pub data: Vec<u8>,
}

impl Command for SignDataEdDSACommand {
    type ResponseType = SignDataEdDSAResponse;
}
