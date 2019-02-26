//! SSH certificate templates

use crate::algorithm::{AlgorithmError, AlgorithmErrorKind::TagInvalid};

/// Template algorithms (for SSH)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum Algorithm {
    /// template-ssh
    SSH = 0x24,
}

impl Algorithm {
    /// Convert an unsigned byte tag into a `template::Algorithmorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, AlgorithmError> {
        Ok(match tag {
            0x24 => Algorithm::SSH,
            _ => fail!(
                TagInvalid,
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
