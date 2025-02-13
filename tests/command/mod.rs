//! Integration tests for YubiHSM 2 commands

pub mod blink_device;
pub mod decrypt_oaep;
pub mod delete_object;
pub mod device_info;
pub mod export_wrapped;
pub mod generate_asymmetric_key;
pub mod generate_hmac_key;
pub mod generate_wrap_key;
pub mod get_log_entries;
pub mod get_object_info;
pub mod get_option;
pub mod get_pseudo_random;
pub mod get_storage_info;
pub mod list_objects;
pub mod put_asymmetric_key;
pub mod put_authentication_key;
pub mod put_opaque;
#[cfg(feature = "mockhsm")]
pub mod reset_device;
pub mod set_option;
pub mod sign_attestation_certificate;
#[cfg(not(feature = "mockhsm"))]
pub mod sign_ecdsa;
pub mod sign_eddsa;
pub mod verify_hmac;
