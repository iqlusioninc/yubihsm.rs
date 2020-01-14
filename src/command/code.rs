//! YubiHSM2 command codes

use super::{Error, ErrorKind};
use anomaly::fail;
use serde::{de, ser, Deserialize, Serialize};

/// Command IDs for `YubiHSM 2` operations
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[allow(missing_docs)]
#[repr(u8)]
pub enum Code {
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

impl Code {
    /// Convert an unsigned byte into a `command::Code` (if valid)
    pub fn from_u8(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            0x00 => Code::Unknown,
            0x01 => Code::Echo,
            0x03 => Code::CreateSession,
            0x04 => Code::AuthenticateSession,
            0x05 => Code::SessionMessage,
            0x06 => Code::DeviceInfo,
            0x07 => Code::Bsl,
            0x08 => Code::ResetDevice,
            0x09 => Code::Command9,
            0x40 => Code::CloseSession,
            0x41 => Code::GetStorageInfo,
            0x42 => Code::PutOpaqueObject,
            0x43 => Code::GetOpaqueObject,
            0x44 => Code::PutAuthenticationKey,
            0x45 => Code::PutAsymmetricKey,
            0x46 => Code::GenerateAsymmetricKey,
            0x47 => Code::SignPkcs1,
            0x48 => Code::ListObjects,
            0x49 => Code::DecryptPkcs1,
            0x4a => Code::ExportWrapped,
            0x4b => Code::ImportWrapped,
            0x4c => Code::PutWrapKey,
            0x4d => Code::GetLogEntries,
            0x4e => Code::GetObjectInfo,
            0x4f => Code::SetOption,
            0x50 => Code::GetOption,
            0x51 => Code::GetPseudoRandom,
            0x52 => Code::PutHmacKey,
            0x53 => Code::SignHmac,
            0x54 => Code::GetPublicKey,
            0x55 => Code::SignPss,
            0x56 => Code::SignEcdsa,
            0x57 => Code::DeriveEcdh,
            0x58 => Code::DeleteObject,
            0x59 => Code::DecryptOaep,
            0x5a => Code::GenerateHmacKey,
            0x5b => Code::GenerateWrapKey,
            0x5c => Code::VerifyHmac,
            0x5d => Code::SignSshCertificate,
            0x5e => Code::PutTemplate,
            0x5f => Code::GetTemplate,
            0x60 => Code::DecryptOtp,
            0x61 => Code::CreateOtpAead,
            0x62 => Code::RandomizeOtpAead,
            0x63 => Code::RewrapOtpAead,
            0x64 => Code::SignAttestationCertificate,
            0x65 => Code::PutOtpAead,
            0x66 => Code::GenerateOtpAead,
            0x67 => Code::SetLogIndex,
            0x68 => Code::WrapData,
            0x69 => Code::UnwrapData,
            0x6a => Code::SignEddsa,
            0x6b => Code::BlinkDevice,
            0x6c => Code::ChangeAuthenticationKey,
            0x7f => Code::Error,
            _ => fail!(ErrorKind::CodeInvalid, "invalid command type: {}", byte),
        })
    }

    /// Serialize a command as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl Serialize for Code {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_u8(self.to_u8())
    }
}

impl<'de> Deserialize<'de> for Code {
    fn deserialize<D>(deserializer: D) -> Result<Code, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        use de::Error;
        Code::from_u8(u8::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}
