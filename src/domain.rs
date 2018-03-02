//! Logical partitions within the `YubiHSM2`, allowing several applications to
//! share the device concurrently

use byteorder::{BigEndian, ByteOrder};
use failure::Error;

use super::SessionError;

/// Logical partition within the `YubiHSM2`
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Domain(pub(crate) u8);

impl Domain {
    /// Parse domains from a byte serialization
    pub fn parse(bytes: &[u8]) -> Result<Vec<Self>, Error> {
        if bytes.len() != 2 {
            bail!("invalid domain length {} (expected {})", bytes.len(), 2);
        }

        let bitfield = BigEndian::read_u16(bytes);
        let mut result = vec![];

        for i in 1..16 {
            if bitfield & (1 << i) != 0 {
                result.push(Domain::new(i).unwrap())
            }
        }

        Ok(result)
    }

    /// Convert an array of Domain objects to a 16-bit integer bitfield
    pub fn bitfield(domains: &[Self]) -> u16 {
        domains
            .iter()
            .fold(0, |result, domain| result | (1 << domain.0))
    }

    /// Create a new Domain
    pub fn new(domain: u8) -> Result<Self, Error> {
        if domain < 1 || domain > 16 {
            fail!(SessionError::ProtocolError, "invalid domain: {}", domain);
        }

        Ok(Domain(domain))
    }

    /// Create a Domain from a byte serialization
    #[inline]
    pub fn from_u8(domain: u8) -> Result<Self, Error> {
        Self::new(domain)
    }

    /// Serialize this domain as a byte
    pub fn to_u8(&self) -> u8 {
        self.0
    }
}
