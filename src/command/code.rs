use failure::Error;
use serde::{
    de::{Deserialize, Deserializer, Error as DeError},
    ser::{Serialize, Serializer},
};

/// Command IDs for `YubiHSM2` operations
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[allow(missing_docs)]
#[repr(u8)]
pub enum CommandCode {
    Unknown = 0x00,
    Echo = 0x01,
    CreateSession = 0x03,
    AuthenticateSession = 0x04,
    SessionMessage = 0x05,
    DeviceInfo = 0x06,
    Bsl = 0x07,
    ResetDevice = 0x08,
    Command9 = 0x09, // TODO: What is Command 9???
    CloseSession = 0x40,
    GetStorageInfo = 0x41,
    PutOpaqueObject = 0x42,
    GetOpaqueObject = 0x43,
    PutAuthenticationKey = 0x44,
    PutAsymmetricKey = 0x45,
    GenerateAsymmetricKey = 0x46,
    SignPkcs1 = 0x47,
    ListObjects = 0x48,
    DecryptPkcs1 = 0x49,
    ExportWrapped = 0x4a,
    ImportWrapped = 0x4b,
    PutWrapKey = 0x4c,
    GetLogEntries = 0x4d,
    GetObjectInfo = 0x4e,
    SetOption = 0x4f,
    GetOption = 0x50,
    GetPseudoRandom = 0x51,
    PutHmacKey = 0x52,
    SignHmac = 0x53,
    GetPublicKey = 0x54,
    SignPss = 0x55,
    SignEcdsa = 0x56,
    DeriveEcdh = 0x57,
    DeleteObject = 0x58,
    DecryptOaep = 0x59,
    GenerateHmacKey = 0x5a,
    GenerateWrapKey = 0x5b,
    VerifyHmac = 0x5c,
    SignSshCertificate = 0x5d,
    PutTemplate = 0x5e,
    GetTemplate = 0x5f,
    DecryptOtp = 0x60,
    CreateOtpAead = 0x61,
    RandomizeOtpAead = 0x62,
    RewrapOtpAead = 0x63,
    SignAttestationCertificate = 0x64,
    PutOtpAead = 0x65,
    GenerateOtpAead = 0x66,
    SetLogIndex = 0x67,
    WrapData = 0x68,
    UnwrapData = 0x69,
    SignEddsa = 0x6a,
    BlinkDevice = 0x6b,
    ChangeAuthenticationKey = 0x6c,
    Error = 0x7f,
}

impl CommandCode {
    /// Convert an unsigned byte into a `CommandCode` (if valid)
    pub fn from_u8(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            0x00 => CommandCode::Unknown,
            0x01 => CommandCode::Echo,
            0x03 => CommandCode::CreateSession,
            0x04 => CommandCode::AuthenticateSession,
            0x05 => CommandCode::SessionMessage,
            0x06 => CommandCode::DeviceInfo,
            0x07 => CommandCode::Bsl,
            0x08 => CommandCode::ResetDevice,
            0x09 => CommandCode::Command9,
            0x40 => CommandCode::CloseSession,
            0x41 => CommandCode::GetStorageInfo,
            0x42 => CommandCode::PutOpaqueObject,
            0x43 => CommandCode::GetOpaqueObject,
            0x44 => CommandCode::PutAuthenticationKey,
            0x45 => CommandCode::PutAsymmetricKey,
            0x46 => CommandCode::GenerateAsymmetricKey,
            0x47 => CommandCode::SignPkcs1,
            0x48 => CommandCode::ListObjects,
            0x49 => CommandCode::DecryptPkcs1,
            0x4a => CommandCode::ExportWrapped,
            0x4b => CommandCode::ImportWrapped,
            0x4c => CommandCode::PutWrapKey,
            0x4d => CommandCode::GetLogEntries,
            0x4e => CommandCode::GetObjectInfo,
            0x4f => CommandCode::SetOption,
            0x50 => CommandCode::GetOption,
            0x51 => CommandCode::GetPseudoRandom,
            0x52 => CommandCode::PutHmacKey,
            0x53 => CommandCode::SignHmac,
            0x54 => CommandCode::GetPublicKey,
            0x55 => CommandCode::SignPss,
            0x56 => CommandCode::SignEcdsa,
            0x57 => CommandCode::DeriveEcdh,
            0x58 => CommandCode::DeleteObject,
            0x59 => CommandCode::DecryptOaep,
            0x5a => CommandCode::GenerateHmacKey,
            0x5b => CommandCode::GenerateWrapKey,
            0x5c => CommandCode::VerifyHmac,
            0x5d => CommandCode::SignSshCertificate,
            0x5e => CommandCode::PutTemplate,
            0x5f => CommandCode::GetTemplate,
            0x60 => CommandCode::DecryptOtp,
            0x61 => CommandCode::CreateOtpAead,
            0x62 => CommandCode::RandomizeOtpAead,
            0x63 => CommandCode::RewrapOtpAead,
            0x64 => CommandCode::SignAttestationCertificate,
            0x65 => CommandCode::PutOtpAead,
            0x66 => CommandCode::GenerateOtpAead,
            0x67 => CommandCode::SetLogIndex,
            0x68 => CommandCode::WrapData,
            0x69 => CommandCode::UnwrapData,
            0x6a => CommandCode::SignEddsa,
            0x6b => CommandCode::BlinkDevice,
            0x6c => CommandCode::ChangeAuthenticationKey,
            0x7f => CommandCode::Error,
            _ => bail!("invalid command type: {}", byte),
        })
    }

    /// Serialize a command as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl Serialize for CommandCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.to_u8())
    }
}

impl<'de> Deserialize<'de> for CommandCode {
    fn deserialize<D>(deserializer: D) -> Result<CommandCode, D::Error>
    where
        D: Deserializer<'de>,
    {
        CommandCode::from_u8(u8::deserialize(deserializer)?)
            .or_else(|e| Err(D::Error::custom(format!("{}", e))))
    }
}
