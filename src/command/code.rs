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
    AuthSession = 0x04,
    SessionMessage = 0x05,
    DeviceInfo = 0x06,
    BSL = 0x07,
    Reset = 0x08,
    Command9 = 0x09, // What is Command 9???
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

impl CommandCode {
    /// Convert an unsigned byte into a `CommandCode` (if valid)
    pub fn from_u8(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            0x00 => CommandCode::Unknown,
            0x01 => CommandCode::Echo,
            0x03 => CommandCode::CreateSession,
            0x04 => CommandCode::AuthSession,
            0x05 => CommandCode::SessionMessage,
            0x06 => CommandCode::DeviceInfo,
            0x07 => CommandCode::BSL,
            0x08 => CommandCode::Reset,
            0x09 => CommandCode::Command9,
            0x40 => CommandCode::CloseSession,
            0x41 => CommandCode::StorageStatus,
            0x42 => CommandCode::PutOpaqueObject,
            0x43 => CommandCode::GetOpaqueObject,
            0x44 => CommandCode::PutAuthKey,
            0x45 => CommandCode::PutAsymmetricKey,
            0x46 => CommandCode::GenerateAsymmetricKey,
            0x47 => CommandCode::SignDataPKCS1,
            0x48 => CommandCode::ListObjects,
            0x49 => CommandCode::DecryptPKCS1,
            0x4a => CommandCode::ExportWrapped,
            0x4b => CommandCode::ImportWrapped,
            0x4c => CommandCode::PutWrapKey,
            0x4d => CommandCode::GetLogs,
            0x4e => CommandCode::GetObjectInfo,
            0x4f => CommandCode::PutOption,
            0x50 => CommandCode::GetOption,
            0x51 => CommandCode::GetPseudoRandom,
            0x52 => CommandCode::PutHMACKey,
            0x53 => CommandCode::HMACData,
            0x54 => CommandCode::GetPubKey,
            0x55 => CommandCode::SignDataPSS,
            0x56 => CommandCode::SignDataECDSA,
            0x57 => CommandCode::DecryptECDH,
            0x58 => CommandCode::DeleteObject,
            0x59 => CommandCode::DecryptOAEP,
            0x5a => CommandCode::GenerateHMACKey,
            0x5b => CommandCode::GenerateWrapKey,
            0x5c => CommandCode::VerifyHMAC,
            0x5d => CommandCode::SSHCertify,
            0x5e => CommandCode::PutTemplate,
            0x5f => CommandCode::GetTemplate,
            0x60 => CommandCode::DecryptOTP,
            0x61 => CommandCode::CreateOTPAEAD,
            0x62 => CommandCode::RandomOTPAEAD,
            0x63 => CommandCode::RewrapOTPAEAD,
            0x64 => CommandCode::AttestAsymmetric,
            0x65 => CommandCode::PutOTPAEAD,
            0x66 => CommandCode::GenerateOTPAEAD,
            0x67 => CommandCode::SetLogIndex,
            0x68 => CommandCode::WrapData,
            0x69 => CommandCode::UnwrapData,
            0x6a => CommandCode::SignDataEdDSA,
            0x6b => CommandCode::Blink,
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
