use failure::Error;
use serde::de::{self, Deserialize, DeserializeOwned, Deserializer, Visitor};
use serde::ser::{Serialize, Serializer};
use std::fmt;

use securechannel::CommandMessage;
#[cfg(feature = "mockhsm")]
use securechannel::ResponseMessage;
use serializers::serialize;

/// Create a command error (presently just a `SessionError`)
macro_rules! command_err {
    ($kind:ident, $msg:expr) => {
        ::session::SessionError::new(
            ::session::SessionErrorKind::$kind,
            Some($msg.to_owned())
        )
    };
    ($kind:ident, $fmt:expr, $($arg:tt)+) => {
        ::session::SessionError::new(
            ::session::SessionErrorKind::$kind,
            Some(format!($fmt, $($arg)+))
        )
    };
}

/// Create and return a command error (presently just a `SessionError`)
macro_rules! command_fail {
    ($kind:ident, $msg:expr) => {
        return Err(command_err!($kind, $msg).into());
    };
    ($kind:ident, $fmt:expr, $($arg:tt)+) => {
        return Err(command_err!($kind, $fmt, $($arg)+).into());
    };
}

pub mod attest_asymmetric;
pub mod blink;
pub(crate) mod close_session;
pub(crate) mod create_session;
pub mod delete_object;
pub mod device_info;
pub mod echo;
pub mod export_wrapped;
pub mod generate_asymmetric_key;
pub mod generate_hmac_key;
pub mod generate_key;
pub mod generate_wrap_key;
pub mod get_logs;
pub mod get_object_info;
pub mod get_opaque;
pub mod get_pseudo_random;
pub mod get_pubkey;
pub mod hmac;
pub mod import_wrapped;
pub mod list_objects;
pub mod put_asymmetric_key;
pub mod put_auth_key;
pub mod put_hmac_key;
mod put_object;
pub mod put_opaque;
pub mod put_otp_aead_key;
pub mod put_wrap_key;
pub mod reset;
pub mod set_log_index;
pub mod sign_ecdsa;
pub mod sign_eddsa;
#[cfg(feature = "rsa")]
pub mod sign_rsa_pkcs1v15;
#[cfg(feature = "rsa")]
pub mod sign_rsa_pss;
pub mod storage_status;
pub mod unwrap_data;
pub mod verify_hmac;
pub mod wrap_data;

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

/// Command IDs for `YubiHSM2` operations
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum CommandType {
    Unknown = 0x00,
    Echo = 0x01,
    CreateSession = 0x03,
    AuthSession = 0x04,
    SessionMessage = 0x05,
    DeviceInfo = 0x06,
    BSL = 0x07,
    Reset = 0x08,
    CloseSession = 0x40,
    StorageStatus = 0x41,
    PutOpaqueObject = 0x42,
    GetOpaqueObject = 0x43,
    PutAuthKey = 0x44,
    PutAsymmetricKey = 0x45,
    GenerateAsymmetricKey = 0x46,
    SignDataPKCS1 = 0x47,
    ListObjects = 0x48,
    DecryptPKCS1 = 0x49,
    ExportWrapped = 0x4a,
    ImportWrapped = 0x4b,
    PutWrapKey = 0x4c,
    GetLogs = 0x4d,
    GetObjectInfo = 0x4e,
    PutOption = 0x4f,
    GetOption = 0x50,
    GetPseudoRandom = 0x51,
    PutHMACKey = 0x52,
    HMACData = 0x53,
    GetPubKey = 0x54,
    SignDataPSS = 0x55,
    SignDataECDSA = 0x56,
    DecryptECDH = 0x57,
    DeleteObject = 0x58,
    DecryptOAEP = 0x59,
    GenerateHMACKey = 0x5a,
    GenerateWrapKey = 0x5b,
    VerifyHMAC = 0x5c,
    SSHCertify = 0x5d,
    PutTemplate = 0x5e,
    GetTemplate = 0x5f,
    DecryptOTP = 0x60,
    CreateOTPAEAD = 0x61,
    RandomOTPAEAD = 0x62,
    RewrapOTPAEAD = 0x63,
    AttestAsymmetric = 0x64,
    PutOTPAEAD = 0x65,
    GenerateOTPAEAD = 0x66,
    SetLogIndex = 0x67,
    WrapData = 0x68,
    UnwrapData = 0x69,
    SignDataEdDSA = 0x6a,
    Blink = 0x6b,
    Error = 0x7f,
}

impl CommandType {
    /// Convert an unsigned byte into a CommandType (if valid)
    pub fn from_u8(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            0x00 => CommandType::Unknown,
            0x01 => CommandType::Echo,
            0x03 => CommandType::CreateSession,
            0x04 => CommandType::AuthSession,
            0x05 => CommandType::SessionMessage,
            0x06 => CommandType::DeviceInfo,
            0x07 => CommandType::BSL,
            0x08 => CommandType::Reset,
            0x40 => CommandType::CloseSession,
            0x41 => CommandType::StorageStatus,
            0x42 => CommandType::PutOpaqueObject,
            0x43 => CommandType::GetOpaqueObject,
            0x44 => CommandType::PutAuthKey,
            0x45 => CommandType::PutAsymmetricKey,
            0x46 => CommandType::GenerateAsymmetricKey,
            0x47 => CommandType::SignDataPKCS1,
            0x48 => CommandType::ListObjects,
            0x49 => CommandType::DecryptPKCS1,
            0x4a => CommandType::ExportWrapped,
            0x4b => CommandType::ImportWrapped,
            0x4c => CommandType::PutWrapKey,
            0x4d => CommandType::GetLogs,
            0x4e => CommandType::GetObjectInfo,
            0x4f => CommandType::PutOption,
            0x50 => CommandType::GetOption,
            0x51 => CommandType::GetPseudoRandom,
            0x52 => CommandType::PutHMACKey,
            0x53 => CommandType::HMACData,
            0x54 => CommandType::GetPubKey,
            0x55 => CommandType::SignDataPSS,
            0x56 => CommandType::SignDataECDSA,
            0x57 => CommandType::DecryptECDH,
            0x58 => CommandType::DeleteObject,
            0x59 => CommandType::DecryptOAEP,
            0x5a => CommandType::GenerateHMACKey,
            0x5b => CommandType::GenerateWrapKey,
            0x5c => CommandType::VerifyHMAC,
            0x5d => CommandType::SSHCertify,
            0x5e => CommandType::PutTemplate,
            0x5f => CommandType::GetTemplate,
            0x60 => CommandType::DecryptOTP,
            0x61 => CommandType::CreateOTPAEAD,
            0x62 => CommandType::RandomOTPAEAD,
            0x63 => CommandType::RewrapOTPAEAD,
            0x64 => CommandType::AttestAsymmetric,
            0x65 => CommandType::PutOTPAEAD,
            0x66 => CommandType::GenerateOTPAEAD,
            0x67 => CommandType::SetLogIndex,
            0x68 => CommandType::WrapData,
            0x69 => CommandType::UnwrapData,
            0x6a => CommandType::SignDataEdDSA,
            0x6b => CommandType::Blink,
            0x7f => CommandType::Error,
            _ => bail!("invalid command type: {}", byte),
        })
    }

    /// Serialize a command as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl Serialize for CommandType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.to_u8())
    }
}

impl<'de> Deserialize<'de> for CommandType {
    fn deserialize<D>(deserializer: D) -> Result<CommandType, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CommandTypeVisitor;

        impl<'de> Visitor<'de> for CommandTypeVisitor {
            type Value = CommandType;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an unsigned byte between 0x01 and 0x07")
            }

            fn visit_u8<E>(self, value: u8) -> Result<CommandType, E>
            where
                E: de::Error,
            {
                CommandType::from_u8(value).or_else(|e| Err(E::custom(format!("{}", e))))
            }
        }

        deserializer.deserialize_u8(CommandTypeVisitor)
    }
}
