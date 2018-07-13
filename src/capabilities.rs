// Apparently bitflags isn't clippy-safe
#![allow(unknown_lints, redundant_field_names, suspicious_arithmetic_impl)]

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, Visitor};
use serde::ser::{Serialize, Serializer};

bitflags! {
    /// Object attributes specifying which operations are allowed to be performed
    ///
    /// <https://developers.yubico.com/YubiHSM2/Concepts/Capability.html>
    pub struct Capability: u64 {
        /// asymmetric_decrypt_ecdh: perform ECDH operation
        const ASYMMETRIC_DECRYPT_ECDH = 0x800;

        /// asymmetric_decrypt_oaep: perform RSA-OAEP decryption
        const ASYMMETRIC_DECRYPT_OAEP = 0x400;

        /// asymmetric_decrypt_pkcs: perform RSA-PKCS1v1.5 decryption
        const ASYMMETRIC_DECRYPT_PKCS = 0x200;

        /// asymmetric_gen: generate asymmetric objects
        const ASYMMETRIC_GEN = 0x10;

        /// asymmetric_sign_ecdsa: compute ECDSA digital signature
        const ASYMMETRIC_SIGN_ECDSA = 0x80;

        /// asymmetric_sign_eddsa: compute EdDSA (i.e. Ed25519) digital signature
        const ASYMMETRIC_SIGN_EDDSA = 0x100;

        /// asymmetric_sign_pkcs: compute RSA-PKCS1v1.5 digital signature
        const ASYMMETRIC_SIGN_PKCS = 0x20;

        /// asymmetric_sign_pss: compute RSA-PSS digital signature
        const ASYMMETRIC_SIGN_PSS = 0x40;

        /// attest: create attestation (i.e. X.509 certificate) about an asymmetric object
        const ATTEST = 0x4_0000_0000;

        /// audit: read the log store
        const AUDIT = 0x100_0000;

        /// delete_asymmetric: delete asymmetric key objects
        const DELETE_ASYMMETRIC = 0x200_0000_0000;

        /// delete_auth_key: delete AuthKey objects
        const DELETE_AUTHKEY = 0x100_0000_0000;

        /// delete_hmac_key: delete HMACKey objects
        const DELETE_HMACKEY = 0x800_0000_0000;

        /// delete_opaque: delete opaque objects
        const DELETE_OPAQUE = 0x80_0000_0000;

        /// delete_otp_aead_key: delete OTPAEADKey objects
        const DELETE_OTP_AEAD_KEY = 0x2000_0000_0000;

        /// delete_template: delete template objects
        const DELETE_TEMPLATE = 0x1000_0000_0000;

        /// delete_wrap_key: delete WrapKey objects
        const DELETE_WRAPKEY = 0x400_0000_0000;

        /// export_under_wrap: mark an object as exportable under keywrap
        const EXPORT_UNDER_WRAP = 0x1_0000;

        /// export_wrapped: export objects under keywrap
        const EXPORT_WRAPPED = 0x1000;

        /// generate_otp_aead_key: generate OTPAEADKey objects
        const GENERATE_OTP_AEAD_KEY = 0x10_0000_0000;

        /// generate_wrapkey: generate wrapkey objects
        const GENERATE_WRAPKEY = 0x8000;

        /// get_opaque: read opaque objects
        const GET_OPAQUE = 0x1;

        /// get_option: read device-global options
        const GET_OPTION = 0x4_0000;

        /// get_randomness: extract random bytes
        const GET_RANDOMNESS = 0x8_0000;

        /// get_template: read template objects
        const GET_TEMPLATE = 0x400_0000;

        /// hmackey_generate: generate HMACKey objects
        const HMACKEY_GENERATE = 0x20_0000;

        /// hmac_data: compute HMAC for data
        const HMAC_DATA = 0x40_0000;

        /// hmac_verify: verify HMAC for data
        const HMAC_VERIFY = 0x80_0000;

        /// import_wrapped: import keywrapped objects
        const IMPORT_WRAPPED = 0x2000;

        /// otp_aead_create: create an OTP AEAD
        const OTP_AEAD_CREATE = 0x4000_0000;

        /// otp_aead_random: create an OTP AEAD from random data
        const OTP_AEAD_RANDOM = 0x8000_0000;

        /// otp_aead_rewrap_from: rewrap AEADs from one OTPAEADKey Object to another
        const OTP_AEAD_REWRAP_FROM = 0x1_0000_0000;

        /// otp_aead_rewrap_to: rewrap AEADs to one OTPAEADKey Object from another
        const OTP_AEAD_REWRAP_TO = 0x2_0000_0000;

        /// otp_decrypt: decrypt OTP
        const OTP_DECRYPT = 0x2000_0000;

        /// put_asymmetric_key: write asymmetric objects
        const PUT_ASYMMETRIC =  0x8;

        /// put_auth_key: write AuthKey objects
        const PUT_AUTHKEY = 0x4;

        /// put_hmac_key: write HMACKey objects
        const PUT_HMACKEY = 0x10_0000;

        /// put_opaque: Write Opaque Objects
        const PUT_OPAQUE = 0x2;

        /// put_option: write device-global options
        const PUT_OPTION = 0x2_0000;

        /// put_otp_aead_key: write OTPAEADKey objects
        const PUT_OTP_AEAD_KEY = 0x8_0000_0000;

        /// put_template: write template objects
        const PUT_TEMPLATE = 0x800_0000;

        /// put_wrapkey: write WrapKey objects
        const PUT_WRAPKEY = 0x4000;

        /// reset: factory reset the device
        const RESET = 0x1000_0000;

        /// ssh_certify: sign SSH certificates
        const SSH_CERTIFY = 0x200_0000;

        /// unwrap_data: unwrap user-provided data
        const UNWRAP_DATA = 0x40_0000_0000;

        /// wrap_data: wrap user-provided data
        const WRAP_DATA = 0x20_0000_0000;

        /// Unknown Capability bit 46
        const UNKNOWN_BIT46 = 0x4000_0000_0000;
        /// Unknown Capability bit 47
        const UNKNOWN_BIT47 = 0x8000_0000_0000;
        /// Unknown Capability bit 48
        const UNKNOWN_BIT48 = 0x1_0000_0000_0000;
        /// Unknown Capability bit 49
        const UNKNOWN_BIT49 = 0x2_0000_0000_0000;
        /// Unknown Capability bit 50
        const UNKNOWN_BIT50 = 0x4_0000_0000_0000;
        /// Unknown Capability bit 51
        const UNKNOWN_BIT51 = 0x8_0000_0000_0000;
        /// Unknown Capability bit 52
        const UNKNOWN_BIT52 = 0x10_0000_0000_0000;
        /// Unknown Capability bit 53
        const UNKNOWN_BIT53 = 0x20_0000_0000_0000;
        /// Unknown Capability bit 54
        const UNKNOWN_BIT54 = 0x40_0000_0000_0000;
        /// Unknown Capability bit 55
        const UNKNOWN_BIT55 = 0x80_0000_0000_0000;
        /// Unknown Capability bit 56
        const UNKNOWN_BIT56 = 0x100_0000_0000_0000;
        /// Unknown Capability bit 57
        const UNKNOWN_BIT57 = 0x200_0000_0000_0000;
        /// Unknown Capability bit 58
        const UNKNOWN_BIT58 = 0x400_0000_0000_0000;
        /// Unknown Capability bit 59
        const UNKNOWN_BIT59 = 0x800_0000_0000_0000;
        /// Unknown Capability bit 60
        const UNKNOWN_BIT60 = 0x1000_0000_0000_0000;
        /// Unknown Capability bit 61
        const UNKNOWN_BIT61 = 0x2000_0000_0000_0000;
        /// Unknown Capability bit 62
        const UNKNOWN_BIT62 = 0x4000_0000_0000_0000;
        /// Unknown Capability bit 63
        const UNKNOWN_BIT63 = 0x8000_0000_0000_0000;
    }
}

impl Default for Capability {
    fn default() -> Self {
        Capability::empty()
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

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
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
