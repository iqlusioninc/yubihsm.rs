//! Filters for selecting objects in the list object command

use crate::{algorithm::Algorithm, capability::Capability, client, domain::Domain, object};
use std::io::Write;

#[cfg(feature = "mockhsm")]
use crate::client::ErrorKind::ProtocolError;
#[cfg(feature = "mockhsm")]
use crate::object::LABEL_SIZE;
#[cfg(feature = "mockhsm")]
use anomaly::{fail, format_err};
#[cfg(feature = "mockhsm")]
use std::io::Read;

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

#[cfg(feature = "mockhsm")]
macro_rules! read_byte {
    ($reader:expr) => {{
        let mut byte = [0u8];
        $reader.read_exact(&mut byte)?;
        byte[0]
    }};
}

#[cfg(feature = "mockhsm")]
macro_rules! read_be_bytes {
    ($reader:expr, $type:path) => {{
        let mut bytes = [0u8; std::mem::size_of::<$type>()];
        $reader.read_exact(&mut bytes)?;
        <$type>::from_be_bytes(bytes)
    }};
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
    pub(crate) fn serialize<W: Write>(&self, mut writer: W) -> Result<W, client::Error> {
        writer.write_all(&[self.tag()])?;

        match *self {
            Filter::Algorithm(alg) => writer.write_all(&[alg.to_u8()])?,
            Filter::Capabilities(caps) => writer.write_all(&caps.bits().to_be_bytes())?,
            Filter::Domains(doms) => writer.write_all(&doms.bits().to_be_bytes())?,
            Filter::Label(ref label) => {
                writer.write_all(label.as_ref())?;
            }
            Filter::Id(id) => writer.write_all(&id.to_be_bytes())?,
            Filter::Type(ty) => writer.write_all(&[ty.to_u8()])?,
        }

        Ok(writer)
    }

    // TODO: replace this with serde
    #[cfg(feature = "mockhsm")]
    pub(crate) fn deserialize<R: Read>(mut reader: R) -> Result<Self, client::Error> {
        let tag = read_byte!(reader);

        Ok(match tag {
            0x01 => Filter::Id(read_be_bytes!(reader, u16)),
            0x02 => Filter::Type(
                object::Type::from_u8(read_byte!(reader))
                    .map_err(|e| format_err!(ProtocolError, e))?,
            ),
            0x03 => Filter::Domains(
                Domain::from_bits(read_be_bytes!(reader, u16))
                    .ok_or_else(|| format_err!(ProtocolError, "invalid domain bitflags"))?,
            ),
            0x04 => Filter::Capabilities(
                Capability::from_bits(read_be_bytes!(reader, u64))
                    .ok_or_else(|| format_err!(ProtocolError, "invalid capability bitflags"))?,
            ),
            0x05 => Filter::Algorithm(
                Algorithm::from_u8(read_byte!(reader))
                    .map_err(|e| format_err!(ProtocolError, e))?,
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
