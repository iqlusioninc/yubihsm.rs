//! Get an RSA-wrapped key from the `YubiHSM 2`
//!
//! Exports only the raw key material of a symmetric or asymmetric key,
//! encrypted via RSA-AES key wrapping (CKM_RSA_AES_KEY_WRAP).

use crate::{
    aes, command::{self, Command}, object, response::Response, rsa,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::get_rsa_wrapped_key`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetRsaWrappedKeyCommand {
    /// Object ID of the RSA public wrap key
    pub wrap_key_id: object::Id,

    /// Target object type (must be asymmetric-key or symmetric-key)
    pub target_type: object::Type,

    /// Object ID of the target key to wrap
    pub target_id: object::Id,

    /// Ephemeral AES key size algorithm
    pub aes_algorithm: aes::Algorithm,

    /// OAEP hash algorithm
    pub oaep_algorithm: rsa::oaep::Algorithm,

    /// MGF1 hash algorithm
    pub mgf1_algorithm: rsa::mgf::Algorithm,

    /// OAEP label digest (20, 32, 48, or 64 bytes depending on hash)
    pub oaep_label: Vec<u8>,
}

impl Command for GetRsaWrappedKeyCommand {
    type ResponseType = GetRsaWrappedKeyResponse;
}

/// Response from `command::get_rsa_wrapped_key`
///
/// Contains RSA-OAEP(ephemeral_AES_key) || AES-KW(target_key_material)
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetRsaWrappedKeyResponse(pub(crate) Vec<u8>);

impl Response for GetRsaWrappedKeyResponse {
    const COMMAND_CODE: command::Code = command::Code::GetRsaWrappedKey;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialization::{deserialize, serialize};

    /// SHA-256 hash of the empty string (standard OAEP default label digest)
    const SHA256_EMPTY: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
        0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
        0x78, 0x52, 0xb8, 0x55,
    ];

    /// SHA-1 hash of the empty string
    const SHA1_EMPTY: [u8; 20] = [
        0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
        0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
    ];

    #[test]
    fn command_code() {
        assert_eq!(
            GetRsaWrappedKeyCommand::COMMAND_CODE,
            command::Code::GetRsaWrappedKey
        );
        assert_eq!(command::Code::GetRsaWrappedKey.to_u8(), 0x74);
    }

    #[test]
    fn serialize_sha256_asymmetric_key() {
        let cmd = GetRsaWrappedKeyCommand {
            wrap_key_id: 0x0001,
            target_type: object::Type::AsymmetricKey,
            target_id: 0x0002,
            aes_algorithm: aes::Algorithm::Aes256,
            oaep_algorithm: rsa::oaep::Algorithm::Sha256,
            mgf1_algorithm: rsa::mgf::Algorithm::Sha256,
            oaep_label: SHA256_EMPTY.to_vec(),
        };

        let bytes = serialize(&cmd).unwrap();

        // Total: 8 header bytes + 32 label bytes = 40
        assert_eq!(bytes.len(), 40);

        // wrap_key_id: big-endian 0x0001
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1], 0x01);

        // target_type: AsymmetricKey = 0x03
        assert_eq!(bytes[2], 0x03);

        // target_id: big-endian 0x0002
        assert_eq!(bytes[3], 0x00);
        assert_eq!(bytes[4], 0x02);

        // aes_algorithm: Aes256 = 0x34
        assert_eq!(bytes[5], 0x34);

        // oaep_algorithm: Sha256 = 0x1a
        assert_eq!(bytes[6], 0x1a);

        // mgf1_algorithm: Sha256 = 0x21
        assert_eq!(bytes[7], 0x21);

        // OAEP label digest
        assert_eq!(&bytes[8..], &SHA256_EMPTY);
    }

    #[test]
    fn serialize_symmetric_key_target() {
        let cmd = GetRsaWrappedKeyCommand {
            wrap_key_id: 0x0003,
            target_type: object::Type::SymmetricKey,
            target_id: 0x0004,
            aes_algorithm: aes::Algorithm::Aes256,
            oaep_algorithm: rsa::oaep::Algorithm::Sha256,
            mgf1_algorithm: rsa::mgf::Algorithm::Sha256,
            oaep_label: SHA256_EMPTY.to_vec(),
        };

        let bytes = serialize(&cmd).unwrap();
        assert_eq!(bytes.len(), 40);

        // target_type: SymmetricKey = 0x08
        assert_eq!(bytes[2], 0x08);
    }

    #[test]
    fn serialize_sha1_label() {
        let cmd = GetRsaWrappedKeyCommand {
            wrap_key_id: 0x0001,
            target_type: object::Type::AsymmetricKey,
            target_id: 0x0002,
            aes_algorithm: aes::Algorithm::Aes256,
            oaep_algorithm: rsa::oaep::Algorithm::Sha1,
            mgf1_algorithm: rsa::mgf::Algorithm::Sha1,
            oaep_label: SHA1_EMPTY.to_vec(),
        };

        let bytes = serialize(&cmd).unwrap();

        // 8 header + 20 SHA-1 digest = 28 bytes
        assert_eq!(bytes.len(), 28);
        assert_eq!(bytes[6], 0x19); // oaep Sha1
        assert_eq!(bytes[7], 0x20); // mgf1 Sha1
        assert_eq!(&bytes[8..], &SHA1_EMPTY);
    }

    #[test]
    fn serialize_sha384_label() {
        let label = [0xAA; 48]; // placeholder 48-byte digest
        let cmd = GetRsaWrappedKeyCommand {
            wrap_key_id: 0x0001,
            target_type: object::Type::AsymmetricKey,
            target_id: 0x0002,
            aes_algorithm: aes::Algorithm::Aes256,
            oaep_algorithm: rsa::oaep::Algorithm::Sha384,
            mgf1_algorithm: rsa::mgf::Algorithm::Sha384,
            oaep_label: label.to_vec(),
        };

        let bytes = serialize(&cmd).unwrap();
        assert_eq!(bytes.len(), 56); // 8 + 48
        assert_eq!(bytes[6], 0x1b); // oaep Sha384
        assert_eq!(bytes[7], 0x22); // mgf1 Sha384
    }

    #[test]
    fn serialize_sha512_label() {
        let label = [0xBB; 64]; // placeholder 64-byte digest
        let cmd = GetRsaWrappedKeyCommand {
            wrap_key_id: 0x0001,
            target_type: object::Type::AsymmetricKey,
            target_id: 0x0002,
            aes_algorithm: aes::Algorithm::Aes256,
            oaep_algorithm: rsa::oaep::Algorithm::Sha512,
            mgf1_algorithm: rsa::mgf::Algorithm::Sha512,
            oaep_label: label.to_vec(),
        };

        let bytes = serialize(&cmd).unwrap();
        assert_eq!(bytes.len(), 72); // 8 + 64
        assert_eq!(bytes[6], 0x1c); // oaep Sha512
        assert_eq!(bytes[7], 0x23); // mgf1 Sha512
    }

    #[test]
    fn serialize_aes_key_sizes() {
        for (alg, expected_byte) in [
            (aes::Algorithm::Aes128, 0x32u8),
            (aes::Algorithm::Aes192, 0x33u8),
            (aes::Algorithm::Aes256, 0x34u8),
        ] {
            let cmd = GetRsaWrappedKeyCommand {
                wrap_key_id: 0x0001,
                target_type: object::Type::AsymmetricKey,
                target_id: 0x0002,
                aes_algorithm: alg,
                oaep_algorithm: rsa::oaep::Algorithm::Sha256,
                mgf1_algorithm: rsa::mgf::Algorithm::Sha256,
                oaep_label: SHA256_EMPTY.to_vec(),
            };

            let bytes = serialize(&cmd).unwrap();
            assert_eq!(bytes[5], expected_byte, "AES algorithm byte mismatch for {alg:?}");
        }
    }

    #[test]
    fn serialize_deserialize_round_trip() {
        let cmd = GetRsaWrappedKeyCommand {
            wrap_key_id: 0x1234,
            target_type: object::Type::AsymmetricKey,
            target_id: 0x5678,
            aes_algorithm: aes::Algorithm::Aes256,
            oaep_algorithm: rsa::oaep::Algorithm::Sha256,
            mgf1_algorithm: rsa::mgf::Algorithm::Sha256,
            oaep_label: SHA256_EMPTY.to_vec(),
        };

        let bytes = serialize(&cmd).unwrap();
        let decoded: GetRsaWrappedKeyCommand = deserialize(&bytes).unwrap();

        assert_eq!(decoded.wrap_key_id, 0x1234);
        assert_eq!(decoded.target_type, object::Type::AsymmetricKey);
        assert_eq!(decoded.target_id, 0x5678);
        assert_eq!(decoded.aes_algorithm, aes::Algorithm::Aes256);
        assert_eq!(decoded.oaep_algorithm, rsa::oaep::Algorithm::Sha256);
        assert_eq!(decoded.mgf1_algorithm, rsa::mgf::Algorithm::Sha256);
        assert_eq!(decoded.oaep_label, SHA256_EMPTY.to_vec());
    }

    #[test]
    fn serialize_deserialize_round_trip_sha1() {
        let cmd = GetRsaWrappedKeyCommand {
            wrap_key_id: 0xABCD,
            target_type: object::Type::SymmetricKey,
            target_id: 0x0099,
            aes_algorithm: aes::Algorithm::Aes128,
            oaep_algorithm: rsa::oaep::Algorithm::Sha1,
            mgf1_algorithm: rsa::mgf::Algorithm::Sha1,
            oaep_label: SHA1_EMPTY.to_vec(),
        };

        let bytes = serialize(&cmd).unwrap();
        let decoded: GetRsaWrappedKeyCommand = deserialize(&bytes).unwrap();

        assert_eq!(decoded.wrap_key_id, 0xABCD);
        assert_eq!(decoded.target_type, object::Type::SymmetricKey);
        assert_eq!(decoded.target_id, 0x0099);
        assert_eq!(decoded.aes_algorithm, aes::Algorithm::Aes128);
        assert_eq!(decoded.oaep_algorithm, rsa::oaep::Algorithm::Sha1);
        assert_eq!(decoded.mgf1_algorithm, rsa::mgf::Algorithm::Sha1);
        assert_eq!(decoded.oaep_label, SHA1_EMPTY.to_vec());
    }

    /// The shell test uses `--oaep rsa-oaep-sha1 --mgf1 mgf1-sha384` (line 260 of test_wrapkey.sh).
    /// OAEP hash and MGF1 hash are independent — they don't need to match.
    #[test]
    fn serialize_mixed_oaep_sha1_mgf1_sha384() {
        let cmd = GetRsaWrappedKeyCommand {
            wrap_key_id: 0x0010,
            target_type: object::Type::AsymmetricKey,
            target_id: 0x0064,
            aes_algorithm: aes::Algorithm::Aes256,
            oaep_algorithm: rsa::oaep::Algorithm::Sha1,
            mgf1_algorithm: rsa::mgf::Algorithm::Sha384,
            oaep_label: SHA1_EMPTY.to_vec(),
        };

        let bytes = serialize(&cmd).unwrap();

        // 8 header + 20 SHA-1 label = 28 bytes
        assert_eq!(bytes.len(), 28);
        assert_eq!(bytes[6], 0x19); // oaep Sha1
        assert_eq!(bytes[7], 0x22); // mgf1 Sha384

        // Round-trip
        let decoded: GetRsaWrappedKeyCommand = deserialize(&bytes).unwrap();
        assert_eq!(decoded.oaep_algorithm, rsa::oaep::Algorithm::Sha1);
        assert_eq!(decoded.mgf1_algorithm, rsa::mgf::Algorithm::Sha384);
        assert_eq!(decoded.oaep_label, SHA1_EMPTY.to_vec());
    }

    /// The shell test uses `--oaep rsa-oaep-sha384 --mgf1 mgf1-sha1` (line 293 of test_wrapkey.sh).
    #[test]
    fn serialize_mixed_oaep_sha384_mgf1_sha1() {
        let label = [0xCC; 48]; // 48-byte SHA-384 digest placeholder
        let cmd = GetRsaWrappedKeyCommand {
            wrap_key_id: 0x0010,
            target_type: object::Type::SymmetricKey,
            target_id: 0x00C8,
            aes_algorithm: aes::Algorithm::Aes256,
            oaep_algorithm: rsa::oaep::Algorithm::Sha384,
            mgf1_algorithm: rsa::mgf::Algorithm::Sha1,
            oaep_label: label.to_vec(),
        };

        let bytes = serialize(&cmd).unwrap();

        // 8 header + 48 SHA-384 label = 56 bytes
        assert_eq!(bytes.len(), 56);
        assert_eq!(bytes[5], 0x34); // aes256
        assert_eq!(bytes[6], 0x1b); // oaep Sha384
        assert_eq!(bytes[7], 0x20); // mgf1 Sha1

        let decoded: GetRsaWrappedKeyCommand = deserialize(&bytes).unwrap();
        assert_eq!(decoded.oaep_algorithm, rsa::oaep::Algorithm::Sha384);
        assert_eq!(decoded.mgf1_algorithm, rsa::mgf::Algorithm::Sha1);
    }

    /// The shell test uses `--oaep rsa-oaep-sha512 --mgf1 mgf1-sha512` (line 340 of test_wrapkey.sh).
    #[test]
    fn serialize_mixed_oaep_sha512_mgf1_sha512() {
        let label = [0xDD; 64]; // 64-byte SHA-512 digest placeholder
        let cmd = GetRsaWrappedKeyCommand {
            wrap_key_id: 0x0010,
            target_type: object::Type::AsymmetricKey,
            target_id: 0x0064,
            aes_algorithm: aes::Algorithm::Aes256,
            oaep_algorithm: rsa::oaep::Algorithm::Sha512,
            mgf1_algorithm: rsa::mgf::Algorithm::Sha512,
            oaep_label: label.to_vec(),
        };

        let bytes = serialize(&cmd).unwrap();

        // 8 header + 64 SHA-512 label = 72 bytes
        assert_eq!(bytes.len(), 72);
        assert_eq!(bytes[6], 0x1c); // oaep Sha512
        assert_eq!(bytes[7], 0x23); // mgf1 Sha512

        let decoded: GetRsaWrappedKeyCommand = deserialize(&bytes).unwrap();
        assert_eq!(decoded.oaep_algorithm, rsa::oaep::Algorithm::Sha512);
        assert_eq!(decoded.mgf1_algorithm, rsa::mgf::Algorithm::Sha512);
    }
}
