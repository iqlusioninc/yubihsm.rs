//! Commands sent to/from the `YubiHSM2`. The protocol resembles but is (or
//! appears to be?) distinct from Application Protocol Data Units (APDU)
//!
//! Documentation for the available commands and their message structure
//! is available on Yubico's `YubiHSM2` web site:
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/>

use byteorder::{BigEndian, WriteBytesExt};
#[cfg(feature = "mockhsm")]
use byteorder::ByteOrder;
use failure::Error;
use super::{Mac, SecureChannelError, SessionId, MAC_SIZE};

/// A command sent from the host to the `YubiHSM2`. May or may not be
/// authenticated using SCP03's chained/evolving MAC protocol.
#[derive(Debug)]
pub(crate) struct CommandMessage {
    /// Type of command to be invoked
    pub command_type: CommandType,

    /// Session ID for this command
    pub session_id: Option<SessionId>,

    /// Command Data field (i.e. message payload)
    pub data: Vec<u8>,

    /// Optional Message Authentication Code (MAC)
    pub mac: Option<Mac>,
}

impl CommandMessage {
    /// Create a new command message without a MAC
    pub fn new<T>(command_type: CommandType, command_data: T) -> Self
    where
        T: Into<Vec<u8>>,
    {
        Self {
            command_type,
            session_id: None,
            data: command_data.into(),
            mac: None,
        }
    }

    /// Create a new command message with a MAC
    pub fn new_with_mac<D, M>(
        command_type: CommandType,
        session_id: SessionId,
        command_data: D,
        mac: M,
    ) -> Self
    where
        D: Into<Vec<u8>>,
        M: Into<Mac>,
    {
        Self {
            command_type,
            session_id: Some(session_id),
            data: command_data.into(),
            mac: Some(mac.into()),
        }
    }

    /// Parse a command structure from a vector, taking ownership of the vector
    #[cfg(feature = "mockhsm")]
    pub fn parse(mut bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.len() < 3 {
            fail!(
                SecureChannelError::ProtocolError,
                "command too short: {} (expected at least 3-bytes)",
                bytes.len()
            );
        }

        let command_type = CommandType::from_u8(bytes[0])?;
        let length = BigEndian::read_u16(&bytes[1..3]) as usize;

        if length + 3 != bytes.len() {
            fail!(
                SecureChannelError::ProtocolError,
                "unexpected command length {} (expecting {})",
                bytes.len() - 3,
                length
            );
        }

        bytes.drain(..3);

        let session_id = if command_type.has_session_id() {
            if bytes.is_empty() {
                fail!(
                    SecureChannelError::ProtocolError,
                    "expected session ID but command data is empty"
                );
            }

            Some(SessionId::new(bytes.remove(0))?)
        } else {
            None
        };

        let mac = if command_type.has_mac() {
            if bytes.len() < MAC_SIZE {
                fail!(
                    SecureChannelError::ProtocolError,
                    "expected MAC for {:?} but command data is too short: {}",
                    command_type,
                    bytes.len(),
                );
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
        let mut result = self.data.len();

        if self.session_id.is_some() {
            result += 1;
        }

        if self.mac.is_some() {
            result += MAC_SIZE;
        }

        result
    }
}

impl Into<Vec<u8>> for CommandMessage {
    /// Serialize this Command, consuming it and creating a Vec<u8>
    fn into(mut self) -> Vec<u8> {
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
    pub fn from_u8(byte: u8) -> Result<Self, Error> {
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
            _ => fail!(
                SecureChannelError::ProtocolError,
                "invalid command type: {}",
                byte
            ),
        })
    }

    /// Serialize a command as a byte
    pub fn to_u8(&self) -> u8 {
        *self as u8
    }

    /// Does this command include a session ID?
    #[cfg(feature = "mockhsm")]
    pub fn has_session_id(&self) -> bool {
        match *self {
            CommandType::AuthSession | CommandType::SessionMessage => true,
            _ => false,
        }
    }

    /// Does this command have a Command-MAC (C-MAC) value on the end?
    #[cfg(feature = "mockhsm")]
    pub fn has_mac(&self) -> bool {
        match *self {
            CommandType::AuthSession | CommandType::SessionMessage => true,
            _ => false,
        }
    }
}
