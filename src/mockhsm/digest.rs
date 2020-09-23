//! Mock `Digest` type for use with ECDSA signatures

use crate::ecdsa::commands::SignEcdsaCommand;
use digest::{
    consts::U32, generic_array::GenericArray, BlockInput, FixedOutputDirty, Output, Reset, Update,
};

/// Mock 256-bit digest
#[derive(Clone, Default)]
pub struct MockDigest256 {
    output: Option<Output<Self>>,
}

impl From<&SignEcdsaCommand> for MockDigest256 {
    fn from(cmd: &SignEcdsaCommand) -> MockDigest256 {
        assert_eq!(cmd.digest.len(), 32);
        Self {
            output: Some(GenericArray::clone_from_slice(&cmd.digest[..])),
        }
    }
}

impl BlockInput for MockDigest256 {
    type BlockSize = U32;
}

impl Update for MockDigest256 {
    fn update(&mut self, _data: impl AsRef<[u8]>) {
        unimplemented!("use explicit conversion from SignEcdsaCommand");
    }
}

impl Reset for MockDigest256 {
    fn reset(&mut self) {
        self.output = None;
    }
}

impl FixedOutputDirty for MockDigest256 {
    type OutputSize = U32;

    fn finalize_into_dirty(&mut self, output: &mut Output<Self>) {
        *output = self.output.take().expect("never initialized!");
    }
}
