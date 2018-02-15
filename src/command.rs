//! Commands sent to/from the YubiHSM2

use byteorder::{BigEndian, ByteOrder};
use failure::Error;

/// Command IDs for YubiHSM2 operations
#[allow(dead_code, missing_docs)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CommandType {
    Unknown = 0x00,
    Echo = 0x01,
    CreateSession = 0x03,
    AuthSession = 0x04,
    SessionMessage = 0x05,
    GetDeviceInfo = 0x06,
    BSL = 0x07,
    Reset = 0x08,
    CloseSession = 0x40,
    Stats = 0x41,
    PutOpaqueObject = 0x42,
    GetOpaqueObject = 0x43,
    PutAuthKey = 0x44,
    PutAsymmetricKey = 0x45,
    GenAsymmetricKey = 0x46,
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
    pub fn from_byte(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            0x00 => CommandType::Unknown,
            0x01 => CommandType::Echo,
            0x03 => CommandType::CreateSession,
            0x04 => CommandType::AuthSession,
            0x05 => CommandType::SessionMessage,
            0x06 => CommandType::GetDeviceInfo,
            0x07 => CommandType::BSL,
            0x08 => CommandType::Reset,
            0x40 => CommandType::CloseSession,
            0x41 => CommandType::Stats,
            0x42 => CommandType::PutOpaqueObject,
            0x43 => CommandType::GetOpaqueObject,
            0x44 => CommandType::PutAuthKey,
            0x45 => CommandType::PutAsymmetricKey,
            0x46 => CommandType::GenAsymmetricKey,
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
            _ => bail!("invalid response code: {}", byte),
        })
    }
}

/// Command responses
#[derive(Debug, Eq, PartialEq)]
pub struct Response {
    code: ResponseCode,
    body: Vec<u8>,
}

impl Response {
    /// Parse a response into a response struct
    pub fn parse(mut bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.len() < 3 {
            bail!("response too short: {}", bytes.len())
        }

        let code = ResponseCode::from_byte(bytes[0])?;

        // Check that the length is valid
        let length = BigEndian::read_u16(&bytes[1..3]) as usize;
        if length + 3 != bytes.len() {
            bail!(
                "unexpected response length {} (expecting {})",
                bytes.len() - 3,
                length
            );
        }

        bytes.drain(..3);
        Ok(Response { code, body: bytes })
    }

    /// Was this command successful?
    pub fn is_ok(&self) -> bool {
        match self.code {
            ResponseCode::Success(_) => true,
            _ => false,
        }
    }

    /// Did an error occur?
    pub fn is_err(&self) -> bool {
        !self.is_ok()
    }

    /// Get the command being responded to
    pub fn command(&self) -> Option<CommandType> {
        match self.code {
            ResponseCode::Success(cmd) => Some(cmd),
            _ => None,
        }
    }

    /// Get the code for this response
    pub fn code(&self) -> ResponseCode {
        self.code
    }

    /// Get the body of this response
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

/// Codes associated with YubiHSM2 responses
#[allow(dead_code, missing_docs)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ResponseCode {
    Success(CommandType),
    MemoryError,
    InitError,
    NetError,
    ConnectorNotFound,
    InvalidParams,
    WrongLength,
    BufferTooSmall,
    CryptogramMismatch,
    AuthSessionError,
    MACMismatch,
    DeviceOK,
    DeviceInvalidCommand,
    DeviceInvalidData,
    DeviceInvalidSession,
    DeviceAuthFail,
    DeviceSessionsFull,
    DeviceSessionFailed,
    DeviceStorageFailed,
    DeviceWrongLength,
    DeviceInvalidPermission,
    DeviceLogFull,
    DeviceObjNotFound,
    DeviceIDIllegal,
    DeviceInvalidOTP,
    DeviceDemoMode,
    DeviceCmdUnexecuted,
    GenericError,
    DeviceObjectExists,
    ConnectorError,
}

impl ResponseCode {
    /// Convert an unsigned byte into a ResponseCode (if valid)
    pub fn from_byte(byte: u8) -> Result<Self, Error> {
        Ok(match byte {
            127 => ResponseCode::MemoryError,
            126 => ResponseCode::InitError,
            125 => ResponseCode::NetError,
            124 => ResponseCode::ConnectorNotFound,
            123 => ResponseCode::InvalidParams,
            122 => ResponseCode::WrongLength,
            121 => ResponseCode::BufferTooSmall,
            120 => ResponseCode::CryptogramMismatch,
            119 => ResponseCode::AuthSessionError,
            118 => ResponseCode::MACMismatch,
            117 => ResponseCode::DeviceOK,
            116 => ResponseCode::DeviceInvalidCommand,
            115 => ResponseCode::DeviceInvalidData,
            114 => ResponseCode::DeviceInvalidSession,
            113 => ResponseCode::DeviceAuthFail,
            112 => ResponseCode::DeviceSessionsFull,
            111 => ResponseCode::DeviceSessionFailed,
            110 => ResponseCode::DeviceStorageFailed,
            109 => ResponseCode::DeviceWrongLength,
            108 => ResponseCode::DeviceInvalidPermission,
            107 => ResponseCode::DeviceLogFull,
            106 => ResponseCode::DeviceObjNotFound,
            105 => ResponseCode::DeviceIDIllegal,
            104 => ResponseCode::DeviceInvalidOTP,
            103 => ResponseCode::DeviceDemoMode,
            102 => ResponseCode::DeviceCmdUnexecuted,
            101 => ResponseCode::GenericError,
            100 => ResponseCode::DeviceObjectExists,
            99 => ResponseCode::ConnectorError,
            _ => {
                if byte > 127 {
                    ResponseCode::Success(CommandType::from_byte(byte - 128)?)
                } else {
                    bail!("invalid response code: {}", 128 - byte)
                }
            }
        })
    }
}
