//! Authentication cryptograms (8-byte MACs) used for session verification

use aesni::Aes128;
use byteorder::{BigEndian, ByteOrder};
use clear_on_drop::clear::Clear;
use constant_time_eq::constant_time_eq;
use cmac::Cmac;
use cmac::crypto_mac::Mac;

use challenge::CHALLENGE_SIZE;
use context::Context;
use super::KEY_SIZE;

/// Authentication cryptograms used to verify sessions
#[derive(Eq)]
pub struct Cryptogram([u8; CHALLENGE_SIZE]);

impl Cryptogram {
    /// Create a new cryptogram from a slice
    ///
    /// Panics if the slice is not 8-bytes
    pub fn from_slice(slice: &[u8]) -> Self {
        assert_eq!(slice.len(), 8, "cryptogram must be 8-bytes long");

        let mut cryptogram = [0u8; CHALLENGE_SIZE];
        cryptogram.copy_from_slice(slice);
        Cryptogram(cryptogram)
    }

    /// Borrow the cryptogram value as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl PartialEq for Cryptogram {
    fn eq(&self, other: &Cryptogram) -> bool {
        constant_time_eq(&self.0[..], &other.0[..])
    }
}

impl Drop for Cryptogram {
    fn drop(&mut self) {
        self.0.clear();
    }
}

/// Calculate an SCP03 cryptogram of arbitrary size
pub(crate) fn calculate(
    mac_key: &[u8; KEY_SIZE],
    derivation_constant: u8,
    context: &Context,
    output: &mut [u8],
) {
    let output_len = output.len();
    assert!(
        output_len <= 16,
        "up to 16-bytes of data supported ({} requested)",
        output_len
    );

    let mut derivation_data = [0u8; 32];

    // "label": 11-bytes of '0' followed by 1-byte derivation constant
    // See Table 4-1: Data Derivation Constants in GPC_SPE_014
    derivation_data[11] = derivation_constant;

    // "separation indicator": 1-byte '0'
    derivation_data[12] = 0x00;

    // "L": length of derived data in bits
    BigEndian::write_u16(&mut derivation_data[13..15], (output_len * 8) as u16);

    // "i": KDF counter for deriving more than one block-length of data
    // Hardcoded to 1 as we don't support deriving more than 128-bits
    derivation_data[15] = 0x01;

    // Derivation context (i.e. challenges concatenated)
    derivation_data[16..].copy_from_slice(context.as_slice());

    let mut mac = Cmac::<Aes128>::new_varkey(&mac_key[..]).unwrap();
    mac.input(&derivation_data);
    output.copy_from_slice(&mac.result().code().as_slice()[..output_len]);
}
