//! Put an RSA public wrap key into the `YubiHSM 2`
//!
//! Imports an RSA public key (modulus only) as a public wrap key object,
//! used for RSA-AES key wrap operations (`get_rsa_wrapped_key`, `export_rsa_wrapped`).

use crate::{
    capability::Capability,
    command::{self, Command},
    object,
    response::Response,
};
use serde::{Deserialize, Serialize};

/// Request parameters for `command::put_public_wrap_key`
///
/// Wire layout (big-endian):
///
/// | Offset | Size | Field                    |
/// |--------|------|--------------------------|
/// | 0      | 2    | key_id                   |
/// | 2      | 40   | label                    |
/// | 42     | 2    | domains                  |
/// | 44     | 8    | capabilities             |
/// | 52     | 1    | algorithm                |
/// | 53     | 8    | delegated_capabilities   |
/// | 61     | N    | RSA modulus (256/384/512) |
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutPublicWrapKeyCommand {
    /// Common parameters to all put object commands
    pub params: object::put::Params,

    /// Delegated capabilities (what keys this wrap key is allowed to wrap)
    pub delegated_capabilities: Capability,

    /// RSA public key modulus bytes (256, 384, or 512 bytes for RSA-2048/3072/4096)
    pub data: Vec<u8>,
}

impl Command for PutPublicWrapKeyCommand {
    type ResponseType = PutPublicWrapKeyResponse;
}

/// Response from `command::put_public_wrap_key`
///
/// Contains the device-assigned or confirmed key ID.
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutPublicWrapKeyResponse {
    /// ID of the stored public wrap key
    pub key_id: object::Id,
}

impl Response for PutPublicWrapKeyResponse {
    const COMMAND_CODE: command::Code = command::Code::PutPublicWrapKey;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialization::{deserialize, serialize};

    /// A fake 256-byte RSA-2048 modulus for testing.
    fn fake_modulus_2048() -> Vec<u8> {
        vec![0xAA; 256]
    }

    /// A fake 384-byte RSA-3072 modulus for testing.
    fn fake_modulus_3072() -> Vec<u8> {
        vec![0xBB; 384]
    }

    /// A fake 512-byte RSA-4096 modulus for testing.
    fn fake_modulus_4096() -> Vec<u8> {
        vec![0xCC; 512]
    }

    #[test]
    fn command_code() {
        assert_eq!(
            PutPublicWrapKeyCommand::COMMAND_CODE,
            command::Code::PutPublicWrapKey
        );
        assert_eq!(command::Code::PutPublicWrapKey.to_u8(), 0x73);
    }

    #[test]
    fn serialize_rsa2048() {
        let cmd = PutPublicWrapKeyCommand {
            params: object::put::Params {
                id: 0x0001,
                label: "test_pubwrap".into(),
                domains: crate::Domain::DOM1,
                capabilities: Capability::EXPORT_WRAPPED,
                algorithm: crate::asymmetric::Algorithm::Rsa2048.into(),
            },
            delegated_capabilities: Capability::empty(),
            data: fake_modulus_2048(),
        };

        let bytes = serialize(&cmd).unwrap();

        // Header: id(2) + label(40) + domains(2) + capabilities(8) + algorithm(1)
        //       + delegated_capabilities(8) = 61
        // Data: 256 bytes (RSA-2048 modulus)
        // Total: 61 + 256 = 317
        assert_eq!(bytes.len(), 317);

        // key_id: big-endian 0x0001
        assert_eq!(bytes[0], 0x00);
        assert_eq!(bytes[1], 0x01);

        // algorithm byte at offset 52: Rsa2048 = 0x09
        assert_eq!(bytes[52], 0x09);

        // modulus starts at offset 61
        assert_eq!(&bytes[61..], &fake_modulus_2048()[..]);
    }

    #[test]
    fn serialize_rsa3072() {
        let cmd = PutPublicWrapKeyCommand {
            params: object::put::Params {
                id: 0x0002,
                label: "test_pubwrap_3072".into(),
                domains: crate::Domain::DOM1,
                capabilities: Capability::EXPORT_WRAPPED,
                algorithm: crate::asymmetric::Algorithm::Rsa3072.into(),
            },
            delegated_capabilities: Capability::empty(),
            data: fake_modulus_3072(),
        };

        let bytes = serialize(&cmd).unwrap();

        // 61 header + 384 modulus = 445
        assert_eq!(bytes.len(), 445);
        assert_eq!(bytes[52], 0x0a); // Rsa3072
        assert_eq!(&bytes[61..], &fake_modulus_3072()[..]);
    }

    #[test]
    fn serialize_rsa4096() {
        let cmd = PutPublicWrapKeyCommand {
            params: object::put::Params {
                id: 0x0003,
                label: "test_pubwrap_4096".into(),
                domains: crate::Domain::DOM1,
                capabilities: Capability::EXPORT_WRAPPED,
                algorithm: crate::asymmetric::Algorithm::Rsa4096.into(),
            },
            delegated_capabilities: Capability::empty(),
            data: fake_modulus_4096(),
        };

        let bytes = serialize(&cmd).unwrap();

        // 61 header + 512 modulus = 573
        assert_eq!(bytes.len(), 573);
        assert_eq!(bytes[52], 0x0b); // Rsa4096
        assert_eq!(&bytes[61..], &fake_modulus_4096()[..]);
    }

    #[test]
    fn serialize_with_delegated_capabilities() {
        let cmd = PutPublicWrapKeyCommand {
            params: object::put::Params {
                id: 0x000A,
                label: "delegated_test".into(),
                domains: crate::Domain::DOM1 | crate::Domain::DOM2,
                capabilities: Capability::EXPORT_WRAPPED,
                algorithm: crate::asymmetric::Algorithm::Rsa2048.into(),
            },
            delegated_capabilities: Capability::SIGN_ECDSA | Capability::SIGN_EDDSA,
            data: fake_modulus_2048(),
        };

        let bytes = serialize(&cmd).unwrap();
        assert_eq!(bytes.len(), 317);

        // delegated_capabilities is at offset 53..61 (8 bytes)
        // Verify it's not all zeros (unlike the empty case)
        let deleg_bytes = &bytes[53..61];
        assert!(
            deleg_bytes.iter().any(|&b| b != 0),
            "delegated capabilities should be non-zero"
        );
    }

    #[test]
    fn serialize_deserialize_round_trip_rsa2048() {
        let cmd = PutPublicWrapKeyCommand {
            params: object::put::Params {
                id: 0x1234,
                label: "roundtrip_test".into(),
                domains: crate::Domain::DOM1,
                capabilities: Capability::EXPORT_WRAPPED,
                algorithm: crate::asymmetric::Algorithm::Rsa2048.into(),
            },
            delegated_capabilities: Capability::SIGN_ECDSA,
            data: fake_modulus_2048(),
        };

        let bytes = serialize(&cmd).unwrap();
        let decoded: PutPublicWrapKeyCommand = deserialize(&bytes).unwrap();

        assert_eq!(decoded.params.id, 0x1234);
        assert_eq!(
            decoded.params.algorithm,
            crate::asymmetric::Algorithm::Rsa2048.into()
        );
        assert_eq!(decoded.delegated_capabilities, Capability::SIGN_ECDSA);
        assert_eq!(decoded.data, fake_modulus_2048());
    }

    #[test]
    fn serialize_deserialize_round_trip_rsa4096() {
        let cmd = PutPublicWrapKeyCommand {
            params: object::put::Params {
                id: 0xABCD,
                label: "roundtrip_4096".into(),
                domains: crate::Domain::DOM1 | crate::Domain::DOM3,
                capabilities: Capability::EXPORT_WRAPPED,
                algorithm: crate::asymmetric::Algorithm::Rsa4096.into(),
            },
            delegated_capabilities: Capability::empty(),
            data: fake_modulus_4096(),
        };

        let bytes = serialize(&cmd).unwrap();
        let decoded: PutPublicWrapKeyCommand = deserialize(&bytes).unwrap();

        assert_eq!(decoded.params.id, 0xABCD);
        assert_eq!(
            decoded.params.algorithm,
            crate::asymmetric::Algorithm::Rsa4096.into()
        );
        assert_eq!(decoded.data, fake_modulus_4096());
    }

    #[test]
    fn response_deserialize() {
        // Response is just a 2-byte key ID
        let resp_bytes = [0x00, 0x42];
        let resp: PutPublicWrapKeyResponse = deserialize(&resp_bytes).unwrap();
        assert_eq!(resp.key_id, 0x0042);
    }
}
