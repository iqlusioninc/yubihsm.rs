//! Object attributes specifying which operations are allowed to be performed

use bitflags::bitflags;
use serde::{
    de::{self, Deserialize, Deserializer, Visitor},
    ser::{Serialize, Serializer},
};
use std::{
    fmt::{self, Display},
    str::{self, FromStr},
};

bitflags! {
    /// Object attributes specifying which operations are allowed to be performed
    ///
    /// <https://developers.yubico.com/YubiHSM2/Concepts/Capability.html>
    pub struct Capability: u64 {
        /// `derive-ecdh`: perform ECDH operation
        const DERIVE_ECDH = 0x800;

        /// `decrypt-oaep`: perform RSA-OAEP decryption
        const DECRYPT_OAEP = 0x400;

        /// `decrypt-pkcs`: perform RSA-PKCS1v1.5 decryption
        const DECRYPT_PKCS = 0x200;

        /// `generate-asymmetric-key`: generate asymmetric objects
        const GENERATE_ASYMMETRIC_KEY = 0x10;

        /// `sign-ecdsa`: compute ECDSA digital signature
        const SIGN_ECDSA = 0x80;

        /// `sign-eddsa`: compute EdDSA (i.e. Ed25519) digital signature
        const SIGN_EDDSA = 0x100;

        /// `sign-pkcs`: compute RSA-PKCS1v1.5 digital signature
        const SIGN_PKCS = 0x20;

        /// `sign-pss`: compute RSA-PSS digital signature
        const SIGN_PSS = 0x40;

        /// `sign-attestation-certificate`: create attestation (i.e. X.509 certificate)
        /// about an asymmetric object
        const SIGN_ATTESTATION_CERTIFICATE = 0x4_0000_0000;

        /// `get-log-entries`: read the log store
        const GET_LOG_ENTRIES = 0x100_0000;

        /// `delete-asymmetric-key`: delete asymmetric key objects
        const DELETE_ASYMMETRIC_KEY = 0x200_0000_0000;

        /// `delete-authentication-key`: delete authentication::Key objects
        const DELETE_AUTHENTICATION_KEY = 0x100_0000_0000;

        /// `delete-hmac-key`: delete HMACKey objects
        const DELETE_HMAC_KEY = 0x800_0000_0000;

        /// `delete-opaque`: delete opaque objects
        const DELETE_OPAQUE = 0x80_0000_0000;

        /// `delete-otp-aead-key`: delete Yubic OTP AEAD key objects
        const DELETE_OTP_AEAD_KEY = 0x2000_0000_0000;

        /// `delete-template`: delete template objects
        const DELETE_TEMPLATE = 0x1000_0000_0000;

        /// `delete-wrap-key`: delete WrapKey objects
        const DELETE_WRAP_KEY = 0x400_0000_0000;

        /// `exportable-under-wrap`: mark an object as exportable under keywrap
        const EXPORTABLE_UNDER_WRAP = 0x1_0000;

        /// `export-wrapped`: export objects under keywrap
        const EXPORT_WRAPPED = 0x1000;

        /// `generate-otp-aead-key`: generate Yubico OTP AEAD objects
        const GENERATE_OTP_AEAD_KEY = 0x10_0000_0000;

        /// `generate-wrap-key`: generate wrapkey objects
        const GENERATE_WRAP_KEY = 0x8000;

        /// `get-opaque`: read opaque objects
        const GET_OPAQUE = 0x1;

        /// `get-option`: read device-global options
        const GET_OPTION = 0x4_0000;

        /// `get-pseudo-random`: extract random bytes
        const GET_PSEUDO_RANDOM = 0x8_0000;

        /// `get-template`: read SSH template objects
        const GET_TEMPLATE = 0x400_0000;

        /// `generate-hmac-key`: generate HMAC key objects
        const GENERATE_HMAC_KEY = 0x20_0000;

        /// `sign-hmac`: compute HMAC for data
        const SIGN_HMAC = 0x40_0000;

        /// `verify-hmac`: verify HMAC for data
        const VERIFY_HMAC = 0x80_0000;

        /// `import-wrapped`: import keywrapped objects
        const IMPORT_WRAPPED = 0x2000;

        /// `create-otp-aead`: create an OTP AEAD
        const CREATE_OTP_AEAD = 0x4000_0000;

        /// `randomize-otp-aead`: create an OTP AEAD from random data
        const RANDOMIZE_OTP_AEAD = 0x8000_0000;

        /// `rewrap-from-otp-aead-key`: rewrap AEADs from an OTP AEAD key object to another
        const REWRAP_FROM_OTP_AEAD_KEY = 0x1_0000_0000;

        /// `rewrap-to-otp-aead-key`: rewrap AEADs to an OTP AEAD key object from another
        const REWRAP_TO_OTP_AEAD_KEY = 0x2_0000_0000;

        /// `decrypt-otp`: decrypt OTP
        const DECRYPT_OTP = 0x2000_0000;

        /// `put-asymmetric-key`: write asymmetric objects
        const PUT_ASYMMETRIC_KEY =  0x8;

        /// `put-authentication-key`: write authentication key objects
        const PUT_AUTHENTICATION_KEY = 0x4;

        /// `put-hmac-key`: write HMAC key objects
        const PUT_HMAC_KEY = 0x10_0000;

        /// `put-opaque`: Write Opaque Objects
        const PUT_OPAQUE = 0x2;

        /// `set-option`: write device-global options
        const PUT_OPTION = 0x2_0000;

        /// `put-otp-aead-key`: write OTP AEAD key objects
        const PUT_OTP_AEAD_KEY = 0x8_0000_0000;

        /// `put-template`: write template objects
        const PUT_TEMPLATE = 0x800_0000;

        /// `put-wrap-key`: write WrapKey objects
        const PUT_WRAP_KEY = 0x4000;

        /// `reset-device`: factory reset the device
        const RESET_DEVICE = 0x1000_0000;

        /// `sign-ssh-certificate`: sign SSH certificates
        const SIGN_SSH_CERTIFICATE = 0x200_0000;

        /// `unwrap-data`: unwrap user-provided data
        const UNWRAP_DATA = 0x40_0000_0000;

        /// `wrap-data`: wrap user-provided data
        const WRAP_DATA = 0x20_0000_0000;

        /// `change-authentication-key`: overwrite existing authentication key with new one
        const CHANGE_AUTHENTICATION_KEY = 0x4000_0000_0000;

        /// unknown capability: bit 47
        const UNKNOWN_CAPABILITY_47 = 0x8000_0000_0000;

        /// unknown capability: bit 48
        const UNKNOWN_CAPABILITY_48 = 0x1_0000_0000_0000;

        /// unknown capability: bit 49
        const UNKNOWN_CAPABILITY_49 = 0x2_0000_0000_0000;

        /// unknown capability: bit 50
        const UNKNOWN_CAPABILITY_50 = 0x4_0000_0000_0000;

        /// unknown capability: bit 51
        const UNKNOWN_CAPABILITY_51 = 0x8_0000_0000_0000;

        /// unknown capability: bit 52
        const UNKNOWN_CAPABILITY_52 = 0x10_0000_0000_0000;

        /// unknown capability: bit 53
        const UNKNOWN_CAPABILITY_53 = 0x20_0000_0000_0000;

        /// unknown capability: bit 54
        const UNKNOWN_CAPABILITY_54 = 0x40_0000_0000_0000;

        /// unknown capability: bit 55
        const UNKNOWN_CAPABILITY_55 = 0x80_0000_0000_0000;

        /// unknown capability: bit 56
        const UNKNOWN_CAPABILITY_56 = 0x100_0000_0000_0000;

        /// unknown capability: bit 57
        const UNKNOWN_CAPABILITY_57 = 0x200_0000_0000_0000;

        /// unknown capability: bit 58
        const UNKNOWN_CAPABILITY_58 = 0x400_0000_0000_0000;

        /// unknown capability: bit 59
        const UNKNOWN_CAPABILITY_59 = 0x800_0000_0000_0000;

        /// unknown capability: bit 60
        const UNKNOWN_CAPABILITY_60 = 0x1000_0000_0000_0000;

        /// unknown capability: bit 61
        const UNKNOWN_CAPABILITY_61 = 0x2000_0000_0000_0000;

        /// unknown capability: bit 62
        const UNKNOWN_CAPABILITY_62 = 0x4000_0000_0000_0000;

        /// unknown capability: bit 63
        const UNKNOWN_CAPABILITY_63 = 0x8000_0000_0000_0000;
    }
}

impl Default for Capability {
    fn default() -> Self {
        Capability::empty()
    }
}

impl Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match *self {
            Capability::DERIVE_ECDH => "derive-ecdh",
            Capability::DECRYPT_OAEP => "decrypt-oaep",
            Capability::DECRYPT_PKCS => "decrypt-pkcs",
            Capability::GENERATE_ASYMMETRIC_KEY => "generate-asymmetric-key",
            Capability::SIGN_ECDSA => "sign-ecdsa",
            Capability::SIGN_EDDSA => "sign-eddsa",
            Capability::SIGN_PKCS => "sign-pkcs",
            Capability::SIGN_PSS => "sign-pss",
            Capability::SIGN_ATTESTATION_CERTIFICATE => "sign-attestation-certificate",
            Capability::GET_LOG_ENTRIES => "get-log-entries",
            Capability::DELETE_ASYMMETRIC_KEY => "delete-asymmetric-key",
            Capability::DELETE_AUTHENTICATION_KEY => "delete-authentication-key",
            Capability::DELETE_HMAC_KEY => "delete-hmac-key",
            Capability::DELETE_OPAQUE => "delete-opaque",
            Capability::DELETE_OTP_AEAD_KEY => "delete-otp-aead-key",
            Capability::DELETE_TEMPLATE => "delete-template",
            Capability::DELETE_WRAP_KEY => "delete-wrap-key",
            Capability::EXPORTABLE_UNDER_WRAP => "exportable-under-wrap",
            Capability::EXPORT_WRAPPED => "export-wrapped",
            Capability::GENERATE_OTP_AEAD_KEY => "generate-otp-aead-key",
            Capability::GENERATE_WRAP_KEY => "generate-wrap-key",
            Capability::GET_OPAQUE => "get-opaque",
            Capability::GET_OPTION => "get-option",
            Capability::GET_PSEUDO_RANDOM => "get-pseudo-random",
            Capability::GET_TEMPLATE => "get-template",
            Capability::GENERATE_HMAC_KEY => "generate-hmac-key",
            Capability::SIGN_HMAC => "sign-hmac",
            Capability::VERIFY_HMAC => "verify-hmac",
            Capability::IMPORT_WRAPPED => "import-wrapped",
            Capability::CREATE_OTP_AEAD => "create-otp-aead",
            Capability::RANDOMIZE_OTP_AEAD => "randomize-otp-aead",
            Capability::REWRAP_FROM_OTP_AEAD_KEY => "rewrap-from-otp-aead-key",
            Capability::REWRAP_TO_OTP_AEAD_KEY => "rewrap-to-otp-aead-key",
            Capability::DECRYPT_OTP => "decrypt-otp",
            Capability::PUT_ASYMMETRIC_KEY => "put-asymmetric-key",
            Capability::PUT_AUTHENTICATION_KEY => "put-authentication-key",
            Capability::PUT_HMAC_KEY => "put-hmac-key",
            Capability::PUT_OPAQUE => "put-opaque",
            Capability::PUT_OPTION => "set-option",
            Capability::PUT_OTP_AEAD_KEY => "put-otp-aead-key",
            Capability::PUT_TEMPLATE => "put-template",
            Capability::PUT_WRAP_KEY => "put-wrap-key",
            Capability::RESET_DEVICE => "reset-device",
            Capability::SIGN_SSH_CERTIFICATE => "sign-ssh-certificate",
            Capability::UNWRAP_DATA => "unwrap-data",
            Capability::WRAP_DATA => "wrap-data",
            Capability::CHANGE_AUTHENTICATION_KEY => "change-authentication-key",
            _ => return Err(fmt::Error), // we don't support displaying this capability yet
        };

        write!(f, "{}", s)
    }
}

impl FromStr for Capability {
    type Err = ();

    fn from_str(s: &str) -> Result<Capability, ()> {
        Ok(match s {
            "derive-ecdh" => Capability::DERIVE_ECDH,
            "decrypt-oaep" => Capability::DECRYPT_OAEP,
            "decrypt-pkcs" => Capability::DECRYPT_PKCS,
            "generate-asymmetric-key" => Capability::GENERATE_ASYMMETRIC_KEY,
            "sign-ecdsa" => Capability::SIGN_ECDSA,
            "sign-eddsa" => Capability::SIGN_EDDSA,
            "sign-pkcs" => Capability::SIGN_PKCS,
            "sign-pss" => Capability::SIGN_PSS,
            "sign-attestation-certificate" => Capability::SIGN_ATTESTATION_CERTIFICATE,
            "get-log-entries" => Capability::GET_LOG_ENTRIES,
            "delete-asymmetric-key" => Capability::DELETE_ASYMMETRIC_KEY,
            "delete-authentication-key" => Capability::DELETE_AUTHENTICATION_KEY,
            "delete-hmac-key" => Capability::DELETE_HMAC_KEY,
            "delete-opaque" => Capability::DELETE_OPAQUE,
            "delete-otp-aead-key" => Capability::DELETE_OTP_AEAD_KEY,
            "delete-template" => Capability::DELETE_TEMPLATE,
            "delete-wrap-key" => Capability::DELETE_WRAP_KEY,
            "exportable-under-wrap" => Capability::EXPORTABLE_UNDER_WRAP,
            "export-wrapped" => Capability::EXPORT_WRAPPED,
            "generate-otp-aead-key" => Capability::GENERATE_OTP_AEAD_KEY,
            "generate-wrap-key" => Capability::GENERATE_WRAP_KEY,
            "get-opaque" => Capability::GET_OPAQUE,
            "get-option" => Capability::GET_OPTION,
            "get-pseudo-random" => Capability::GET_PSEUDO_RANDOM,
            "get-template" => Capability::GET_TEMPLATE,
            "generate-hmac-key" => Capability::GENERATE_HMAC_KEY,
            "sign-hmac" => Capability::SIGN_HMAC,
            "verify-hmac" => Capability::VERIFY_HMAC,
            "import-wrapped" => Capability::IMPORT_WRAPPED,
            "create-otp-aead" => Capability::CREATE_OTP_AEAD,
            "randomize-otp-aead" => Capability::RANDOMIZE_OTP_AEAD,
            "rewrap-from-otp-aead-key" => Capability::REWRAP_FROM_OTP_AEAD_KEY,
            "rewrap-to-otp-aead-key" => Capability::REWRAP_TO_OTP_AEAD_KEY,
            "decrypt-otp" => Capability::DECRYPT_OTP,
            "put-asymmetric-key" => Capability::PUT_ASYMMETRIC_KEY,
            "put-authentication-key" => Capability::PUT_AUTHENTICATION_KEY,
            "put-hmac-key" => Capability::PUT_HMAC_KEY,
            "put-opaque" => Capability::PUT_OPAQUE,
            "set-option" => Capability::PUT_OPTION,
            "put-otp-aead-key" => Capability::PUT_OTP_AEAD_KEY,
            "put-template" => Capability::PUT_TEMPLATE,
            "put-wrap-key" => Capability::PUT_WRAP_KEY,
            "reset-device" => Capability::RESET_DEVICE,
            "sign-ssh-certificate" => Capability::SIGN_SSH_CERTIFICATE,
            "unwrap-data" => Capability::UNWRAP_DATA,
            "wrap-data" => Capability::WRAP_DATA,
            "change-authentication-key" => Capability::CHANGE_AUTHENTICATION_KEY,
            _ => return Err(()),
        })
    }
}

impl Serialize for Capability {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(self.bits())
    }
}

impl<'de> Deserialize<'de> for Capability {
    fn deserialize<D>(deserializer: D) -> Result<Capability, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CapabilityVisitor;

        impl<'de> Visitor<'de> for CapabilityVisitor {
            type Value = Capability;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("8-bytes containing capability bitflags")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Capability, E>
            where
                E: de::Error,
            {
                Capability::from_bits(value).ok_or_else(|| E::custom("invalid capability bitflags"))
            }
        }

        deserializer.deserialize_u64(CapabilityVisitor)
    }
}
