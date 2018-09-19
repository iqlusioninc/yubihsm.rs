//! Integration tests for YubiHSM2 commands

#[cfg(not(feature = "mockhsm"))]
pub mod attest_asymmetric;
pub mod blink;
pub mod delete_object;
pub mod device_info;
pub mod export_wrapped;
pub mod generate_asymmetric_key;
pub mod generate_hmac_key;
pub mod generate_wrap_key;
pub mod get_logs;
pub mod get_object_info;
pub mod get_option;
pub mod get_pseudo_random;
pub mod list_objects;
pub mod put_asymmetric_key;
pub mod put_auth_key;
pub mod put_opaque;
pub mod put_option;
#[cfg(feature = "mockhsm")]
pub mod reset;
pub mod sign_ecdsa;
pub mod sign_eddsa;
pub mod storage_status;
pub mod verify_hmac;
