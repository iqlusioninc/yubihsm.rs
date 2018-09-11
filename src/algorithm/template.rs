use super::{Algorithm, AlgorithmError, AlgorithmErrorKind::TagInvalid};

/// Template algorithms (for SSH)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(non_camel_case_types)]
#[repr(u8)]
pub enum TemplateAlg {
    /// template-ssh
    SSH = 0x24,
}

impl TemplateAlg {
    /// Convert an unsigned byte tag into a `TemplateAlgorithm` (if valid)
    pub fn from_u8(tag: u8) -> Result<Self, AlgorithmError> {
        Ok(match tag {
            0x24 => TemplateAlg::SSH,
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

impl From<TemplateAlg> for Algorithm {
    fn from(alg: TemplateAlg) -> Algorithm {
        Algorithm::Template(alg)
    }
}

impl_algorithm_serializers!(TemplateAlg);
