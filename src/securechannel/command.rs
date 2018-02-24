//! Commands sent to/from the `YubiHSM2`. The protocol resembles but is (or
//! appears to be?) distinct from Application Protocol Data Units (APDU)
//!
//! Documentation for the available commands and their message structure
//! is available on Yubico's `YubiHSM2` web site:
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/>

use byteorder::{BigEndian, ByteOrder, WriteBytesExt};
use failure::Error;
use super::{Mac, SecureChannelError, SessionId, MAC_SIZE};

/// A command sent from the host to the `YubiHSM2`. May or may not be
/// authenticated using SCP03's chained/evolving MAC protocol.
#[allow(dead_code)]
pub(crate) struct Command {
    /// Type of command to be invoked
    pub command_type: CommandType,

    /// Session ID for this command
    pub session_id: Option<SessionId>,

    /// Command Data field (i.e. message payload)
    pub data: Vec<u8>,

    /// Optional Message Authentication Code (MAC)
    pub mac: Option<Mac>,
}

impl Command {
    /// Create a new command message without a MAC
    pub fn new(command_type: CommandType, command_data: &[u8]) -> Self {
        Self {
            command_type,
            session_id: None,
            data: command_data.into(),
            mac: None,
        }
    }

    /// Create a new command message with a MAC
    pub fn new_with_mac(
        command_type: CommandType,
        session_id: SessionId,
        command_data: &[u8],
        mac: Mac,
    ) -> Self {
        Self {
            command_type,
            session_id: Some(session_id),
            data: command_data.into(),
            mac: Some(mac),
        }
    }

    /// Parse a command structure from a vector, taking ownership of the vector
    #[cfg(feature = "mockhsm")]
    pub fn parse(mut bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.len() < 3 {
            Err(SecureChannelError::ProtocolError {
                description: format!(
                    "command too short: {} (expected at least 3-bytes)",
                    bytes.len()
                ),
            })?;
        }

        let command_type = CommandType::from_byte(bytes[0])?;
        let length = BigEndian::read_u16(&bytes[1..3]) as usize;

        if length + 3 != bytes.len() {
            Err(SecureChannelError::ProtocolError {
                description: format!(
                    "unexpected command length {} (expecting {})",
                    bytes.len() - 3,
                    length
                ),
            })?;
        }

        bytes.drain(..3);

        let session_id = if command_type.has_session_id() {
            if bytes.is_empty() {
                Err(SecureChannelError::ProtocolError {
                    description: "expected session ID but command data is empty".to_owned(),
                })?;
            }

            Some(SessionId::new(bytes.remove(0))?)
        } else {
            None
        };

        let mac = if command_type.has_mac() {
            if bytes.len() < MAC_SIZE {
                Err(SecureChannelError::ProtocolError {
                    description: format!(
                        "expected MAC for {:?} but command data is too short: {}",
                        command_type,
                        bytes.len(),
                    ),
                })?;
            }

            let mac_index = bytes.len() - MAC_SIZE;
            Some(Mac::from_slice(&bytes.split_off(mac_index)))
        } else {
            None
        };

        Ok(Self {
            command_type,
            session_id,
            data: bytes,
            mac,
        })
    }

    /// Calculate the length of the serialized message, sans command type and length field
    pub fn len(&self) -> usize {
        if self.mac.is_some() {
            // Include extra byte for session ID
            1 + self.data.len() + MAC_SIZE
        } else {
            self.data.len()
        }
    }

    /// Serialize this Command, consuming it and creating a Vec<u8>
    pub fn into_vec(mut self) -> Vec<u8> {
        let mut result = Vec::with_capacity(3 + self.len());
        result.push(self.command_type as u8);
        result.write_u16::<BigEndian>(self.len() as u16).unwrap();

        if let Some(session_id) = self.session_id {
            result.push(session_id.to_u8());
        }

        result.append(&mut self.data);

        if let Some(mac) = self.mac {
            result.extend_from_slice(mac.as_slice());
        }

        result
    }
}

/// Command IDs for `YubiHSM2` operations
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
            _ => Err(SecureChannelError::ProtocolError {
                description: format!("invalid command type: {}", byte),
            })?,
        })
    }

    /// Does this command include a session ID?
    #[cfg(feature = "mockhsm")]
    pub fn has_session_id(&self) -> bool {
        match *self {
            CommandType::CreateSession => false,
            _ => true,
        }
    }

    /// Does this command have a Command-MAC (C-MAC) value on the end?
    #[cfg(feature = "mockhsm")]
    pub fn has_mac(&self) -> bool {
        match *self {
            CommandType::CreateSession => false,
            // NOTE: there are other command types that don't carry a C-MAC which aren't
            // enumerated here, but most should have a C-MAC so we otherwise assume that they do
            _ => true,
        }
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
            Err(SecureChannelError::ProtocolError {
                description: format!(
                    "response too short: {} (expected at least 3-bytes)",
                    bytes.len()
                ),
            })?;
        }

        let code = ResponseCode::from_byte(bytes[0])?;
        let length = BigEndian::read_u16(&bytes[1..3]) as usize;

        if length + 3 != bytes.len() {
            Err(SecureChannelError::ProtocolError {
                description: format!(
                    "unexpected response length {} (expecting {})",
                    bytes.len() - 3,
                    length
                ),
            })?;
        }

        bytes.drain(..3);
        Ok(Self { code, body: bytes })
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

/// Codes associated with `YubiHSM2` responses
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
            0x7f => ResponseCode::MemoryError,
            0x7e => ResponseCode::InitError,
            0x7d => ResponseCode::NetError,
            0x7c => ResponseCode::ConnectorNotFound,
            0x7b => ResponseCode::InvalidParams,
            0x7a => ResponseCode::WrongLength,
            0x79 => ResponseCode::BufferTooSmall,
            0x78 => ResponseCode::CryptogramMismatch,
            0x77 => ResponseCode::AuthSessionError,
            0x76 => ResponseCode::MACMismatch,
            0x75 => ResponseCode::DeviceOK,
            0x74 => ResponseCode::DeviceInvalidCommand,
            0x73 => ResponseCode::DeviceInvalidData,
            0x72 => ResponseCode::DeviceInvalidSession,
            0x71 => ResponseCode::DeviceAuthFail,
            0x70 => ResponseCode::DeviceSessionsFull,
            0x6f => ResponseCode::DeviceSessionFailed,
            0x6e => ResponseCode::DeviceStorageFailed,
            0x6d => ResponseCode::DeviceWrongLength,
            0x6c => ResponseCode::DeviceInvalidPermission,
            0x6b => ResponseCode::DeviceLogFull,
            0x6a => ResponseCode::DeviceObjNotFound,
            0x69 => ResponseCode::DeviceIDIllegal,
            0x68 => ResponseCode::DeviceInvalidOTP,
            0x67 => ResponseCode::DeviceDemoMode,
            0x66 => ResponseCode::DeviceCmdUnexecuted,
            0x65 => ResponseCode::GenericError,
            0x64 => ResponseCode::DeviceObjectExists,
            0x63 => ResponseCode::ConnectorError,
            _ => {
                if byte >= 0x80 {
                    ResponseCode::Success(CommandType::from_byte(byte - 0x80)?)
                } else {
                    Err(SecureChannelError::ProtocolError {
                        description: format!("invalid response code: {}", 80 - byte),
                    })?
                }
            }
        })
    }
}
