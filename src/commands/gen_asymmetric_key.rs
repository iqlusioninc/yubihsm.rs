//! Request data for `CommandType::GenAsymmetricKey`

use {Algorithm, Capability, Domain, ObjectId, ObjectLabel};
use byteorder::{BigEndian, WriteBytesExt};
#[cfg(feature = "mockhsm")]
use byteorder::ByteOrder;
use responses::GenAsymmetricKeyResponse;
use super::{Command, CommandType};
#[cfg(feature = "mockhsm")]
use super::{CommandMessage, Error};

// NOTE: this is incorrectly documented as 2 + 40 + 2 + 4 + 1
const LENGTH: usize = 2 + 40 + 2 + 8 + 1;

/// Request data for `CommandType::GenAsymmetricKey`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Generate_Asymmetric_Key.html>
#[derive(Debug)]
pub struct GenAsymmetricKeyCommand {
    /// ID of the key
    pub key_id: ObjectId,

    /// Label for the key (40-bytes)
    pub label: ObjectLabel,

    /// Domains in which the key will be accessible
    pub domains: Vec<Domain>,

    /// Capabilities of the key
    pub capabilities: Vec<Capability>,

    /// Key algorithm
    pub algorithm: Algorithm,
}

impl Command for GenAsymmetricKeyCommand {
    const COMMAND_TYPE: CommandType = CommandType::GenAsymmetricKey;
    type ResponseType = GenAsymmetricKeyResponse;

    /// Serialize data
    // TODO: procedurally generate this
    fn into_vec(self) -> Vec<u8> {
        let mut data = Vec::with_capacity(LENGTH);

        // Key ID
        data.write_u16::<BigEndian>(self.key_id).unwrap();

        // Label (padded to 40-bytes)
        data.extend_from_slice(&self.label.0);

        // Domains
        data.write_u16::<BigEndian>(Domain::bitfield(&self.domains))
            .unwrap();

        // Capabilities
        data.write_u64::<BigEndian>(Capability::bitfield(&self.capabilities))
            .unwrap();

        // Algorithm
        data.push(self.algorithm.to_u8());

        data
    }

    /// Deserialize data
    #[cfg(feature = "mockhsm")]
    fn parse(command_msg: CommandMessage) -> Result<Self, Error> {
        let bytes = command_msg.data;

        if bytes.len() != LENGTH {
            bail!(
                "expected {}-byte object entry (got {})",
                LENGTH,
                bytes.len()
            );
        }

        Ok(Self {
            key_id: BigEndian::read_u16(&bytes[..2]),
            label: ObjectLabel::new(&bytes[2..42])?,
            domains: Domain::parse(&bytes[42..44])?,
            capabilities: Capability::parse(&bytes[44..52])?,
            algorithm: Algorithm::from_u8(bytes[52])?,
        })
    }
}
