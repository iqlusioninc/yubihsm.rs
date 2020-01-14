//! SSH certificate templates

use crate::algorithm;
use anomaly::fail;

/// Template algorithms (for SSH)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Algorithm {
    /// `template-ssh`
    Ssh = 0x24,
}

impl Algorithm {
    /// Convert an unsigned byte tag into a `template::Algorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, algorithm::Error> {
        Ok(match tag {
            0x24 => Algorithm::Ssh,
            _ => fail!(
                algorithm::ErrorKind::TagInvalid,
                "unknown SSH template algorithm ID: 0x{:02x}",
                tag
            ),
        })
    }

    /// Serialize algorithm ID as a byte
    pub fn to_u8(self) -> u8 {
        self as u8
    }
}

impl_algorithm_serializers!(Algorithm);
