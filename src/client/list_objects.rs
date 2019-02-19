//! List objects visible from the current session
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/List_Objects.html>

use super::ClientError;
#[cfg(feature = "mockhsm")]
use super::ClientErrorKind::ProtocolError;
#[cfg(feature = "mockhsm")]
use crate::object::LABEL_SIZE;
use crate::{
    algorithm::Algorithm,
    capability::Capability,
    command::{self, Command},
    domain::Domain,
    object,
    response::Response,
};
#[cfg(feature = "mockhsm")]
use byteorder::ReadBytesExt;
use byteorder::{WriteBytesExt, BE};
#[cfg(feature = "mockhsm")]
use std::io::Read;
use std::io::Write;

/// Request parameters for `command::list_objects`
#[derive(Serialize, Deserialize, Debug)]
// TODO: use serde to serialize filters
pub(crate) struct ListObjectsCommand(pub(crate) Vec<u8>);

impl Command for ListObjectsCommand {
    type ResponseType = ListObjectsResponse;
}

/// Response from `command::list_objects`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct ListObjectsResponse(pub(crate) Vec<ListObjectsEntry>);

impl Response for ListObjectsResponse {
    const COMMAND_CODE: command::Code = command::Code::ListObjects;
}

/// Filters to apply when listing objects
pub enum Filter {
    /// Filter objects by algorithm
    Algorithm(Algorithm),

    /// Filter objects by capability
    Capabilities(Capability),

    /// Filter objects by domain
    Domains(Domain),

    /// Filter objects by label
    Label(object::Label),

    /// Filter by object ID
    Id(object::Id),

    /// Filter by object type
    Type(object::Type),
}

impl Filter {
    /// Tag value for TLV serialization for this filter
    pub fn tag(&self) -> u8 {
        match *self {
            Filter::Id(_) => 0x01,
            Filter::Type(_) => 0x02,
            Filter::Domains(_) => 0x03,
            Filter::Capabilities(_) => 0x04,
            Filter::Algorithm(_) => 0x05,
            Filter::Label(_) => 0x06,
        }
    }

    // TODO: replace this with serde
    pub(crate) fn serialize<W: Write>(&self, mut writer: W) -> Result<W, ClientError> {
        writer.write_u8(self.tag())?;

        match *self {
            Filter::Algorithm(alg) => writer.write_u8(alg.to_u8())?,
            Filter::Capabilities(caps) => writer.write_u64::<BE>(caps.bits())?,
            Filter::Domains(doms) => writer.write_u16::<BE>(doms.bits())?,
            Filter::Label(ref label) => {
                writer.write_all(label.as_ref())?;
            }
            Filter::Id(id) => writer.write_u16::<BE>(id)?,
            Filter::Type(ty) => writer.write_u8(ty.to_u8())?,
        }

        Ok(writer)
    }

    // TODO: replace this with serde
    #[cfg(feature = "mockhsm")]
    pub(crate) fn deserialize<R: Read>(mut reader: R) -> Result<Self, ClientError> {
        let tag = reader.read_u8()?;

        Ok(match tag {
            0x01 => Filter::Id(reader.read_u16::<BE>()?),
            0x02 => Filter::Type(
                object::Type::from_u8(reader.read_u8()?).map_err(|e| err!(ProtocolError, e))?,
            ),
            0x03 => Filter::Domains(
                Domain::from_bits(reader.read_u16::<BE>()?)
                    .ok_or_else(|| err!(ProtocolError, "invalid domain bitflags"))?,
            ),
            0x04 => Filter::Capabilities(
                Capability::from_bits(reader.read_u64::<BE>()?)
                    .ok_or_else(|| err!(ProtocolError, "invalid capability bitflags"))?,
            ),
            0x05 => Filter::Algorithm(
                Algorithm::from_u8(reader.read_u8()?).map_err(|e| err!(ProtocolError, e))?,
            ),
            0x06 => {
                let mut label_bytes = [0u8; LABEL_SIZE];
                reader.read_exact(&mut label_bytes)?;
                Filter::Label(object::Label(label_bytes))
            }
            _ => fail!(ProtocolError, "invalid filter tag: 0x{:2x}", tag),
        })
    }
}

/// Brief information about an object as included in `ListObjectsCommand`
#[derive(Serialize, Deserialize, Debug)]
pub struct ListObjectsEntry {
    /// Object identifier
    pub object_id: object::Id,

    /// Object type
    pub object_type: object::Type,

    /// Sequence: number of times an object with this key ID and type has
    /// previously existed
    pub sequence: object::SequenceId,
}
