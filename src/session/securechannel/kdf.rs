//! SCP03 Key Derivation Function: CMAC (NIST 800-38B) as the PRF for a
//! counter mode KDF as described in NIST SP 800-108 (NIST 800-108)
//! with "fixed input data" specific to the SCP03 protocol

use aes::Aes128;
use byteorder::{BigEndian, ByteOrder};
use cmac::crypto_mac::Mac;
use cmac::Cmac;

use super::{Context, KEY_SIZE};

/// Derive a slice of output data using SCP03's KDF
pub fn derive(mac_key: &[u8], derivation_constant: u8, context: &Context, output: &mut [u8]) {
    assert_eq!(mac_key.len(), KEY_SIZE, "16-byte MAC key expected");

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

    let mut mac = Cmac::<Aes128>::new_varkey(mac_key).unwrap();
    mac.input(&derivation_data);
    output.copy_from_slice(&mac.result().code().as_slice()[..output_len]);
}
