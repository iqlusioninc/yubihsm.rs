//! Messages sent to/from the `YubiHSM 2`, i.e Application Protocol Data Units
//! (a.k.a. APDU)
//!
//! Documentation for the available command and their message structure
//! is available on Yubico's `YubiHSM 2` web site:
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/>

// TODO: this code predates the serde serializers. It could be rewritten with serde.

use super::MAX_MSG_SIZE;
use crate::{
    command, connector,
    session::{
        self,
        securechannel::{Mac, MAC_SIZE},
        ErrorKind::ProtocolError,
    },
    uuid::{self, Uuid},
};
use anomaly::ensure;
#[cfg(any(feature = "http-server", feature = "mockhsm"))]
use anomaly::{fail, format_err};

/// A command sent from the host to the `YubiHSM 2`. May or may not be
/// authenticated using SCP03's chained/evolving MAC protocol.
#[derive(Debug)]
pub(crate) struct Message {
    /// UUID which uniquely identifies this command
    pub uuid: Uuid,

    /// Type of command to be invoked
    pub command_type: command::Code,

    /// Session ID for this command
    pub session_id: Option<session::Id>,

    /// Command Data field (i.e. message payload)
    pub data: Vec<u8>,

    /// Optional Message Authentication Code (MAC)
    pub mac: Option<Mac>,
}

impl Message {
    /// Create a new command message without a MAC
    pub fn create<T>(command_type: command::Code, command_data: T) -> Result<Self, session::Error>
    where
        T: Into<Vec<u8>>,
    {
        let command_data_vec: Vec<u8> = command_data.into();

        ensure!(
            command_data_vec.len() <= MAX_MSG_SIZE,
            ProtocolError,
            "command data too long: {} bytes (max {})",
            command_data_vec.len(),
            MAX_MSG_SIZE
        );

        Ok(Self {
            uuid: uuid::new_v4(),
            command_type,
            session_id: None,
            data: command_data_vec,
            mac: None,
        })
    }

    /// Create a new command message with a MAC
    pub fn new_with_mac<D, M>(
        command_type: command::Code,
        session_id: session::Id,
        command_data: D,
        mac: M,
    ) -> Result<Self, session::Error>
    where
        D: Into<Vec<u8>>,
        M: Into<Mac>,
    {
        let command_data_vec: Vec<u8> = command_data.into();

        ensure!(
            command_data_vec.len() <= MAX_MSG_SIZE,
            ProtocolError,
            "command data too long: {} bytes (max {})",
            command_data_vec.len(),
            MAX_MSG_SIZE
        );

        Ok(Self {
            uuid: uuid::new_v4(),
            command_type,
            session_id: Some(session_id),
            data: command_data_vec,
            mac: Some(mac.into()),
        })
    }

    /// Parse a command structure from a vector, taking ownership of the vector
    #[cfg(any(feature = "http-server", feature = "mockhsm"))]
    pub fn parse(mut bytes: Vec<u8>) -> Result<Self, session::Error> {
        if bytes.len() < 3 {
            fail!(
                ProtocolError,
                "command too short: {} (expected at least 3-bytes)",
                bytes.len()
            );
        }

        let command_type =
            command::Code::from_u8(bytes[0]).map_err(|e| format_err!(ProtocolError, "{}", e))?;

        let mut length_bytes = [0u8; 2];
        length_bytes.copy_from_slice(&bytes[1..3]);
        let length = u16::from_be_bytes(length_bytes) as usize;

        if length + 3 != bytes.len() {
            fail!(
                ProtocolError,
                "unexpected command length {} (expecting {})",
                bytes.len() - 3,
                length
            );
        }

        bytes.drain(..3);

        let (session_id, mac) = match command_type {
            command::Code::AuthenticateSession | command::Code::SessionMessage => {
                if bytes.is_empty() {
                    fail!(
                        ProtocolError,
                        "expected session ID but command data is empty"
                    );
                }

                let id = session::Id::from_u8(bytes.remove(0))?;

                if bytes.len() < MAC_SIZE {
                    fail!(
                        ProtocolError,
                        "expected MAC for {:?} but command data is too short: {}",
                        command_type,
                        bytes.len(),
                    );
                }

                let mac_index = bytes.len() - MAC_SIZE;

                (Some(id), Some(Mac::from_slice(&bytes.split_off(mac_index))))
            }
            _ => (None, None),
        };

        Ok(Self {
            uuid: uuid::new_v4(),
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

    /// Serialize this message as a byte vector
    pub fn serialize(mut self) -> Vec<u8> {
        let mut result = Vec::with_capacity(3 + self.len());
        result.push(self.command_type as u8);

        let length = self.len() as u16;
        result.extend_from_slice(&length.to_be_bytes());

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

impl Into<connector::Message> for Message {
    /// Serialize this Command, consuming it and creating a Vec<u8>
    fn into(self) -> connector::Message {
        connector::Message(self.serialize())
    }
}
