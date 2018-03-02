//! Response from `CommandType::GetObjectInfo`

use {Algorithm, Capability, Domain, ObjectLabel, ObjectOrigin, ObjectType, SequenceId};
use byteorder::{BigEndian, ByteOrder};
#[cfg(feature = "mockhsm")]
use byteorder::WriteBytesExt;
use failure::Error;
use super::{CommandType, Response};

/// Size of a `CommandType::GetObjectInfo` response
const LENGTH: usize = 8 + 2 + 2 + 2 + 1 + 1 + 1 + 1 + 40 + 8;

/// Response from `CommandType::GetObjectInfo`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/Get_Object_Info.html>
#[derive(Debug)]
pub struct GetObjectInfoResponse {
    /// Capabilities
    pub capabilities: Vec<Capability>,

    /// Object identifier
    pub id: u16,

    /// Length of object in bytes
    pub length: u16,

    /// Domains from which object is accessible
    pub domains: Vec<Domain>,

    /// Object type
    pub object_type: ObjectType,

    /// Algorithm this object is intended to be used with
    pub algorithm: Algorithm,

    /// Sequence: number of times an object with this key ID and type has
    /// previously existed
    pub sequence: SequenceId,

    /// How did this object originate? (generated, imported, etc)
    pub origin: ObjectOrigin,

    /// Label of object
    pub label: ObjectLabel,

    /// Delegated Capabilities
    pub delegated_capabilities: Vec<Capability>,
}

impl Response for GetObjectInfoResponse {
    const COMMAND_TYPE: CommandType = CommandType::GetObjectInfo;

    /// Parse response from HSM
    // TODO: procedurally generate this
    fn parse(bytes: Vec<u8>) -> Result<Self, Error> {
        if bytes.len() != LENGTH {
            bail!(
                "expected {}-byte object entry (got {})",
                LENGTH,
                bytes.len()
            );
        }

        Ok(Self {
            capabilities: Capability::parse(&bytes[..8])?,
            id: BigEndian::read_u16(&bytes[8..10]),
            length: BigEndian::read_u16(&bytes[10..12]),
            domains: Domain::parse(&bytes[12..14])?,
            object_type: ObjectType::from_u8(bytes[14])?,
            algorithm: Algorithm::from_u8(bytes[15])?,
            sequence: bytes[16],
            origin: ObjectOrigin::from_u8(bytes[17])?,
            label: ObjectLabel::new(&bytes[18..58])?,
            delegated_capabilities: Capability::parse(&bytes[58..66])?,
        })
    }

    /// Serialize data
    // TODO: procedurally generate this
    #[cfg(feature = "mockhsm")]
    fn into_vec(self) -> Vec<u8> {
        let mut data = Vec::with_capacity(LENGTH);

        // Capabilities
        data.write_u64::<BigEndian>(Capability::bitfield(&self.capabilities))
            .unwrap();

        // Object ID
        data.write_u16::<BigEndian>(self.id).unwrap();

        // Object Length
        data.write_u16::<BigEndian>(self.length).unwrap();

        // Domains
        data.write_u16::<BigEndian>(Domain::bitfield(&self.domains))
            .unwrap();

        // Object Type
        data.push(self.object_type.to_u8());

        // Algorithm
        data.push(self.algorithm.to_u8());

        // Sequence Number
        data.push(self.sequence);

        // Object Origin (Generated/Imported)
        data.push(self.origin.to_u8());

        // Label (padded to 40-bytes)
        data.extend_from_slice(&self.label.0);

        // Delegated Capabilities
        data.write_u64::<BigEndian>(Capability::bitfield(&self.delegated_capabilities))
            .unwrap();

        data
    }
}
