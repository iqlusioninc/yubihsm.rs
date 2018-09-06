//! Responses sent back from the YubiHSM2

#[cfg(feature = "mockhsm")]
use byteorder::WriteBytesExt;
use byteorder::{BigEndian, ByteOrder};
use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::ser::{Serialize, Serializer};
use std::fmt;

use super::{Mac, SecureChannelError, SessionId, MAC_SIZE};
use commands::CommandType;

/// Command responses
#[derive(Debug)]
pub(crate) struct ResponseMessage {
    /// Success (for a given command type) or an error type
    pub code: ResponseCode,

    /// Session ID for this response
    pub session_id: Option<SessionId>,

    /// "Response Data Field"
    pub data: Vec<u8>,

    /// Optional Message Authentication Code (MAC)
    pub mac: Option<Mac>,
}

impl ResponseMessage {
    /// Parse a response into a Response struct
    pub fn parse(mut bytes: Vec<u8>) -> Result<Self, SecureChannelError> {
        if bytes.len() < 3 {
            secure_channel_fail!(
                ProtocolError,
                "response too short: {} (expected at least 3-bytes)",
                bytes.len()
            );
        }

        let code = ResponseCode::from_u8(bytes[0])?;
        let length = BigEndian::read_u16(&bytes[1..3]) as usize;

        if length + 3 != bytes.len() {
            secure_channel_fail!(
                ProtocolError,
                "unexpected response length {} (expecting {})",
                bytes.len() - 3,
                length
            );
        }

        bytes.drain(..3);

        let session_id = if code.has_session_id() {
            if bytes.is_empty() {
                secure_channel_fail!(
                    ProtocolError,
                    "expected session ID but response data is empty"
                );
            }

            Some(SessionId::new(bytes.remove(0))?)
        } else {
            None
        };

        let mac = if code.has_rmac() {
            if bytes.len() < MAC_SIZE {
                secure_channel_fail!(
                    ProtocolError,
                    "expected R-MAC for {:?} but response data is too short: {}",
                    code,
                    bytes.len(),
                );
            }

            let mac_index = bytes.len() - MAC_SIZE;
            Some(Mac::from_slice(&bytes.split_off(mac_index)))
        } else {
            None
        };

        Ok(Self {
            code,
            session_id,
            data: bytes,
            mac,
        })
    }

    /// Create a new response without an associated session
    #[cfg(feature = "mockhsm")]
    pub fn new<T>(code: ResponseCode, response_data: T) -> ResponseMessage
    where
        T: Into<Vec<u8>>,
    {
        ResponseMessage {
            code,
            session_id: None,
            data: response_data.into(),
            mac: None,
        }
    }

    /// Create a new response message with a MAC
    #[cfg(feature = "mockhsm")]
    pub fn new_with_mac<D, M>(
        code: ResponseCode,
        session_id: SessionId,
        response_data: D,
        mac: M,
    ) -> Self
    where
        D: Into<Vec<u8>>,
        M: Into<Mac>,
    {
        Self {
            code,
            session_id: Some(session_id),
            data: response_data.into(),
            mac: Some(mac.into()),
        }
    }

    /// Create a successful response
    #[cfg(feature = "mockhsm")]
    pub fn success<T>(command_type: CommandType, response_data: T) -> ResponseMessage
    where
        T: Into<Vec<u8>>,
    {
        Self::new(ResponseCode::Success(command_type), response_data)
    }

    /// Create an error response
    #[cfg(feature = "mockhsm")]
    pub fn error(message: &str) -> ResponseMessage {
        ResponseMessage::new(ResponseCode::MemoryError, message.as_bytes())
    }

    /// Did an error occur?
    pub fn is_err(&self) -> bool {
        match self.code {
            ResponseCode::Success(_) => false,
            _ => true,
        }
    }

    /// Get the command being responded to
    pub fn command(&self) -> Option<CommandType> {
        match self.code {
            ResponseCode::Success(cmd) => Some(cmd),
            _ => None,
        }
    }

    /// Total length of the response
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

#[cfg(feature = "mockhsm")]
impl Into<Vec<u8>> for ResponseMessage {
    /// Serialize this response, consuming it and producing a Vec<u8>
    fn into(mut self) -> Vec<u8> {
        let mut result = Vec::with_capacity(3 + self.len());
        result.push(self.code.to_u8());
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

/// Codes associated with `YubiHSM2` responses
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
    pub fn from_u8(byte: u8) -> Result<Self, SecureChannelError> {
        let code = (i16::from(byte) - 0x80) as i8;

        if code >= 0 {
            let command_type = CommandType::from_u8(code as u8)
                .map_err(|e| secure_channel_err!(ProtocolError, "{}", e))?;

            return Ok(ResponseCode::Success(command_type));
        }

        Ok(match code {
            -1 => ResponseCode::MemoryError,
            -2 => ResponseCode::InitError,
            -3 => ResponseCode::NetError,
            -4 => ResponseCode::ConnectorNotFound,
            -5 => ResponseCode::InvalidParams,
            -6 => ResponseCode::WrongLength,
            -7 => ResponseCode::BufferTooSmall,
            -8 => ResponseCode::CryptogramMismatch,
            -9 => ResponseCode::AuthSessionError,
            -10 => ResponseCode::MACMismatch,
            -11 => ResponseCode::DeviceOK,
            -12 => ResponseCode::DeviceInvalidCommand,
            -13 => ResponseCode::DeviceInvalidData,
            -14 => ResponseCode::DeviceInvalidSession,
            -15 => ResponseCode::DeviceAuthFail,
            -16 => ResponseCode::DeviceSessionsFull,
            -17 => ResponseCode::DeviceSessionFailed,
            -18 => ResponseCode::DeviceStorageFailed,
            -19 => ResponseCode::DeviceWrongLength,
            -20 => ResponseCode::DeviceInvalidPermission,
            -21 => ResponseCode::DeviceLogFull,
            -22 => ResponseCode::DeviceObjNotFound,
            -23 => ResponseCode::DeviceIDIllegal,
            -24 => ResponseCode::DeviceInvalidOTP,
            -25 => ResponseCode::DeviceDemoMode,
            -26 => ResponseCode::DeviceCmdUnexecuted,
            -27 => ResponseCode::GenericError,
            -28 => ResponseCode::DeviceObjectExists,
            -29 => ResponseCode::ConnectorError,
            _ => secure_channel_fail!(ProtocolError, "invalid response code: {}", code),
        })
    }

    /// Convert a ResponseCode back into its original byte form
    pub fn to_u8(self) -> u8 {
        let code: i8 = match self {
            ResponseCode::Success(cmd_type) => cmd_type as i8,
            ResponseCode::MemoryError => -1,
            ResponseCode::InitError => -2,
            ResponseCode::NetError => -3,
            ResponseCode::ConnectorNotFound => -4,
            ResponseCode::InvalidParams => -5,
            ResponseCode::WrongLength => -6,
            ResponseCode::BufferTooSmall => -7,
            ResponseCode::CryptogramMismatch => -8,
            ResponseCode::AuthSessionError => -9,
            ResponseCode::MACMismatch => -10,
            ResponseCode::DeviceOK => -11,
            ResponseCode::DeviceInvalidCommand => -12,
            ResponseCode::DeviceInvalidData => -13,
            ResponseCode::DeviceInvalidSession => -14,
            ResponseCode::DeviceAuthFail => -15,
            ResponseCode::DeviceSessionsFull => -16,
            ResponseCode::DeviceSessionFailed => -17,
            ResponseCode::DeviceStorageFailed => -18,
            ResponseCode::DeviceWrongLength => -19,
            ResponseCode::DeviceInvalidPermission => -20,
            ResponseCode::DeviceLogFull => -21,
            ResponseCode::DeviceObjNotFound => -22,
            ResponseCode::DeviceIDIllegal => -23,
            ResponseCode::DeviceInvalidOTP => -24,
            ResponseCode::DeviceDemoMode => -25,
            ResponseCode::DeviceCmdUnexecuted => -26,
            ResponseCode::GenericError => -27,
            ResponseCode::DeviceObjectExists => -28,
            ResponseCode::ConnectorError => -29,
        };

        (i16::from(code) + 0x80) as u8
    }

    /// Does this response include a session ID?
    pub fn has_session_id(self) -> bool {
        match self {
            ResponseCode::Success(cmd_type) => match cmd_type {
                CommandType::CreateSession | CommandType::SessionMessage => true,
                _ => false,
            },
            _ => false,
        }
    }

    /// Does this response have a Response-MAC (R-MAC) value on the end?
    pub fn has_rmac(self) -> bool {
        match self {
            ResponseCode::Success(cmd_type) => match cmd_type {
                CommandType::SessionMessage => true,
                _ => false,
            },
            _ => false,
        }
    }
}

impl Serialize for ResponseCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u8(self.to_u8())
    }
}

impl<'de> Deserialize<'de> for ResponseCode {
    fn deserialize<D>(deserializer: D) -> Result<ResponseCode, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ResponseCodeVisitor;

        impl<'de> Visitor<'de> for ResponseCodeVisitor {
            type Value = ResponseCode;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an unsigned byte between 0x01 and 0x07")
            }

            fn visit_u8<E>(self, value: u8) -> Result<ResponseCode, E>
            where
                E: de::Error,
            {
                ResponseCode::from_u8(value)
                    .or_else(|_| ResponseCode::from_u8(ResponseCode::DeviceOK.to_u8() - value))
                    .or_else(|e| Err(E::custom(format!("{}", e))))
            }
        }

        deserializer.deserialize_u8(ResponseCodeVisitor)
    }
}
