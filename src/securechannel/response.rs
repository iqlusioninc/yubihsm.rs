//! Responses sent back from the YubiHSM2

#[cfg(feature = "mockhsm")]
use byteorder::WriteBytesExt;
use byteorder::{BigEndian, ByteOrder};

use super::{Mac, SecureChannelError, SecureChannelErrorKind::ProtocolError, SessionId, MAC_SIZE};
use commands::CommandType;
#[cfg(feature = "mockhsm")]
use error::HsmErrorKind;
use response::ResponseCode;

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
            fail!(
                ProtocolError,
                "response too short: {} (expected at least 3-bytes)",
                bytes.len()
            );
        }

        let code = ResponseCode::from_u8(bytes[0]).map_err(|e| err!(ProtocolError, "{}", e))?;
        let length = BigEndian::read_u16(&bytes[1..3]) as usize;

        if length.checked_add(3).unwrap() != bytes.len() {
            fail!(
                ProtocolError,
                "unexpected response length {} (expecting {})",
                bytes.len().checked_sub(3).unwrap(),
                length
            );
        }

        bytes.drain(..3);

        let session_id = if has_session_id(code) {
            if bytes.is_empty() {
                fail!(ProtocolError, "session ID missing");
            } else {
                Some(SessionId::new(bytes.remove(0))?)
            }
        } else {
            None
        };

        let mac = if has_rmac(code) {
            if bytes.len() < MAC_SIZE {
                fail!(ProtocolError, "missing R-MAC for {:?}", code,);
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
impl From<HsmErrorKind> for ResponseMessage {
    fn from(kind: HsmErrorKind) -> Self {
        Self::new(ResponseCode::MemoryError, vec![kind.to_u8()])
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

/// Do responses with the given code include a session ID?
fn has_session_id(code: ResponseCode) -> bool {
    match code {
        ResponseCode::Success(cmd_type) => match cmd_type {
            CommandType::CreateSession | CommandType::SessionMessage => true,
            _ => false,
        },
        _ => false,
    }
}

/// Do responses with the given code have a Response-MAC (R-MAC) value?
fn has_rmac(code: ResponseCode) -> bool {
    match code {
        ResponseCode::Success(cmd_type) => match cmd_type {
            CommandType::SessionMessage => true,
            _ => false,
        },
        _ => false,
    }
}
