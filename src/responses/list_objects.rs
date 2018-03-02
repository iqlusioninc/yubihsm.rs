//! Response from `CommandType::ListObjects`

use {ObjectId, ObjectType, SequenceId};
use byteorder::{BigEndian, ByteOrder};
#[cfg(feature = "mockhsm")]
use byteorder::WriteBytesExt;
use failure::Error;
use super::{CommandType, Response};

/// Response from `CommandType::ListObjects`
///
/// <https://developers.yubico.com/YubiHSM2/Commands/List_Objects.html>
#[derive(Debug)]
pub struct ListObjectsResponse {
    /// Objects in the response
    pub objects: Vec<ListObjectsEntry>,
}

/// Brief information about an object as returned from the `ListObjects` command
#[derive(Debug)]
pub struct ListObjectsEntry {
    /// Object identifier
    pub id: ObjectId,

    /// Object type
    pub object_type: ObjectType,

    /// Sequence: number of times an object with this key ID and type has
    /// previously existed
    pub sequence: SequenceId,
}

impl Response for ListObjectsResponse {
    const COMMAND_TYPE: CommandType = CommandType::ListObjects;

    /// Parse response from HSM
    // TODO: procedurally generate this
    fn parse(bytes: Vec<u8>) -> Result<Self, Error> {
        let mut objects = Vec::with_capacity(bytes.len() / 4);

        for chunk in bytes.chunks(4) {
            if chunk.len() != 4 {
                bail!("expected 4-byte object entry (got {})", chunk.len());
            }

            objects.push(ListObjectsEntry {
                id: BigEndian::read_u16(&chunk[..2]),
                object_type: ObjectType::from_u8(chunk[2])?,
                sequence: chunk[3],
            })
        }

        Ok(Self { objects })
    }

    /// Serialize data
    // TODO: procedurally generate this
    #[cfg(feature = "mockhsm")]
    fn into_vec(self) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 * self.objects.len());

        for entry in self.objects {
            data.write_u16::<BigEndian>(entry.id).unwrap();
            data.push(entry.object_type.to_u8());
            data.push(entry.sequence);
        }

        data
    }
}
