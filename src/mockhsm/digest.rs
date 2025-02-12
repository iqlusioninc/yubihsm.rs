//! Mock `Digest` type for use with ECDSA signatures

use crate::ecdsa::commands::SignEcdsaCommand;
use digest::{array::Array, consts::U32, Output, OutputSizeUser, Reset, Update};

/// Mock 256-bit digest
#[derive(Clone, Default)]
pub struct MockDigest256 {
    output: Option<Output<Self>>,
}

impl From<&SignEcdsaCommand> for MockDigest256 {
    fn from(cmd: &SignEcdsaCommand) -> MockDigest256 {
        assert_eq!(cmd.digest.len(), 32);
        Self {
            output: Some(Array::try_from(&cmd.digest[..]).expect("digest size violation")),
        }
    }
}

impl Update for MockDigest256 {
    fn update(&mut self, _: &[u8]) {
        unimplemented!("use explicit conversion from SignEcdsaCommand");
    }
}

impl Reset for MockDigest256 {
    fn reset(&mut self) {
        self.output = None;
    }
}

impl OutputSizeUser for MockDigest256 {
    type OutputSize = U32;
}
