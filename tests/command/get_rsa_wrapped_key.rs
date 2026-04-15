//! Integration tests for `get_rsa_wrapped_key` (command 0x74)
//!
//! Adapted from asym_wrap_test.c (CKM_RSA_AES_KEY_WRAP scenarios).
//! These tests require real HSM hardware and are gated on `#[cfg(not(feature = "mockhsm"))]`.
//!
//! The flow is: generate an RSA key pair on the HSM, extract the public key,
//! import it as a `PublicWrapKey` via `put_public_wrap_key`, then use
//! `get_rsa_wrapped_key` against that public wrap key.

use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use yubihsm::{aes, asymmetric, object, rsa, Capability, Domain};

/// RSA key pair slot (used to generate the key pair, then deleted)
const RSA_KEY_ID: object::Id = 230;

/// Public wrap key slot (the imported RSA public key)
const WRAP_KEY_ID: object::Id = 232;

/// Target key slot (key to be wrapped)
const TARGET_KEY_ID: object::Id = 231;

const TEST_DOMAINS: Domain = Domain::DOM1;

/// Compute the OAEP label digest for the empty label using the given hash.
fn sha1_empty_label() -> Vec<u8> {
    Sha1::digest(b"").to_vec()
}

fn sha256_empty_label() -> Vec<u8> {
    Sha256::digest(b"").to_vec()
}

fn sha512_empty_label() -> Vec<u8> {
    Sha512::digest(b"").to_vec()
}

/// Helper: ensure key slots are clear before each test
fn clear_key_slots(client: &yubihsm::Client) {
    let _ = client.delete_object(RSA_KEY_ID, object::Type::AsymmetricKey);
    let _ = client.delete_object(WRAP_KEY_ID, object::Type::PublicWrapKey);
    let _ = client.delete_object(TARGET_KEY_ID, object::Type::AsymmetricKey);
}

/// Helper: generate an RSA key pair on the HSM, extract the public key (modulus),
/// delete the key pair, and import the modulus as a `PublicWrapKey`.
fn setup_public_wrap_key(
    client: &yubihsm::Client,
    algorithm: asymmetric::Algorithm,
) {
    // Generate RSA key pair on the HSM
    client
        .generate_asymmetric_key(
            RSA_KEY_ID,
            "rsa_keypair".into(),
            TEST_DOMAINS,
            Capability::empty(),
            algorithm,
        )
        .unwrap_or_else(|err| panic!("error generating RSA key pair: {err}"));

    // Extract the public key (modulus for RSA)
    let pubkey = client
        .get_public_key(RSA_KEY_ID)
        .unwrap_or_else(|err| panic!("error getting public key: {err}"));

    let modulus = pubkey.as_slice().to_vec();

    // Delete the key pair — we only need the public key
    client
        .delete_object(RSA_KEY_ID, object::Type::AsymmetricKey)
        .unwrap_or_else(|err| panic!("error deleting RSA key pair: {err}"));

    // Import the modulus as a PublicWrapKey
    client
        .put_public_wrap_key(
            WRAP_KEY_ID,
            "rsa_pubwrap".into(),
            TEST_DOMAINS,
            Capability::EXPORT_WRAPPED,
            Capability::all(),
            algorithm,
            modulus,
        )
        .unwrap_or_else(|err| panic!("error importing public wrap key: {err}"));
}

/// Wrap an EC P-256 asymmetric key using an RSA-2048 public wrap key.
#[test]
fn wrap_ec_key_with_rsa2048() {
    let client = crate::get_hsm_client();
    clear_key_slots(&client);

    setup_public_wrap_key(&client, asymmetric::Algorithm::Rsa2048);

    // Generate EC P-256 target key (needs EXPORTABLE_UNDER_WRAP)
    client
        .generate_asymmetric_key(
            TARGET_KEY_ID,
            "ec_target".into(),
            TEST_DOMAINS,
            Capability::SIGN_ECDSA | Capability::EXPORTABLE_UNDER_WRAP,
            asymmetric::Algorithm::EcP256,
        )
        .unwrap_or_else(|err| panic!("error generating EC P-256 key: {err}"));

    let wrapped = client
        .get_rsa_wrapped_key(
            WRAP_KEY_ID,
            object::Type::AsymmetricKey,
            TARGET_KEY_ID,
            aes::Algorithm::Aes256,
            rsa::oaep::Algorithm::Sha256,
            rsa::mgf::Algorithm::Sha256,
            sha256_empty_label(),
        )
        .unwrap_or_else(|err| panic!("error wrapping EC key: {err}"));

    // Response: RSA-OAEP(ephemeral_AES_key) || AES-KW(target_key)
    // RSA-2048 OAEP ciphertext = 256 bytes
    // AES-KW adds 8 bytes overhead to the wrapped key
    // EC P-256 private key = 32 bytes -> AES-KW output = 40 bytes
    // Total expected: 256 + 40 = 296 bytes
    assert!(!wrapped.is_empty(), "wrapped key should not be empty");
    assert!(
        wrapped.len() > 256,
        "wrapped key should be larger than RSA-2048 ciphertext (got {} bytes)",
        wrapped.len()
    );

    clear_key_slots(&client);
}

/// Wrap an EC P-256 asymmetric key using an RSA-3072 public wrap key.
#[test]
fn wrap_ec_key_with_rsa3072() {
    let client = crate::get_hsm_client();
    clear_key_slots(&client);

    setup_public_wrap_key(&client, asymmetric::Algorithm::Rsa3072);

    client
        .generate_asymmetric_key(
            TARGET_KEY_ID,
            "ec_target".into(),
            TEST_DOMAINS,
            Capability::SIGN_ECDSA | Capability::EXPORTABLE_UNDER_WRAP,
            asymmetric::Algorithm::EcP256,
        )
        .unwrap_or_else(|err| panic!("error generating EC P-256 key: {err}"));

    let wrapped = client
        .get_rsa_wrapped_key(
            WRAP_KEY_ID,
            object::Type::AsymmetricKey,
            TARGET_KEY_ID,
            aes::Algorithm::Aes256,
            rsa::oaep::Algorithm::Sha256,
            rsa::mgf::Algorithm::Sha256,
            sha256_empty_label(),
        )
        .unwrap_or_else(|err| panic!("error wrapping EC key: {err}"));

    // RSA-3072 OAEP ciphertext = 384 bytes
    assert!(!wrapped.is_empty());
    assert!(
        wrapped.len() > 384,
        "wrapped key should be larger than RSA-3072 ciphertext (got {} bytes)",
        wrapped.len()
    );

    clear_key_slots(&client);
}

/// Wrap an EC P-256 asymmetric key using an RSA-4096 public wrap key.
#[test]
fn wrap_ec_key_with_rsa4096() {
    let client = crate::get_hsm_client();
    clear_key_slots(&client);

    setup_public_wrap_key(&client, asymmetric::Algorithm::Rsa4096);

    client
        .generate_asymmetric_key(
            TARGET_KEY_ID,
            "ec_target".into(),
            TEST_DOMAINS,
            Capability::SIGN_ECDSA | Capability::EXPORTABLE_UNDER_WRAP,
            asymmetric::Algorithm::EcP256,
        )
        .unwrap_or_else(|err| panic!("error generating EC P-256 key: {err}"));

    let wrapped = client
        .get_rsa_wrapped_key(
            WRAP_KEY_ID,
            object::Type::AsymmetricKey,
            TARGET_KEY_ID,
            aes::Algorithm::Aes256,
            rsa::oaep::Algorithm::Sha256,
            rsa::mgf::Algorithm::Sha256,
            sha256_empty_label(),
        )
        .unwrap_or_else(|err| panic!("error wrapping EC key: {err}"));

    // RSA-4096 OAEP ciphertext = 512 bytes
    assert!(!wrapped.is_empty());
    assert!(
        wrapped.len() > 512,
        "wrapped key should be larger than RSA-4096 ciphertext (got {} bytes)",
        wrapped.len()
    );

    clear_key_slots(&client);
}

/// Wrap EC key with mixed OAEP SHA-1 / MGF1 SHA-384.
///
/// Adapted from test_wrapkey.sh line 260:
///   `--oaep rsa-oaep-sha1 --mgf1 mgf1-sha384`
/// OAEP hash and MGF1 hash are independent — they don't need to match.
#[test]
fn wrap_ec_key_mixed_oaep_sha1_mgf1_sha384() {
    let client = crate::get_hsm_client();
    clear_key_slots(&client);

    setup_public_wrap_key(&client, asymmetric::Algorithm::Rsa2048);

    client
        .generate_asymmetric_key(
            TARGET_KEY_ID,
            "ec_target".into(),
            TEST_DOMAINS,
            Capability::SIGN_ECDSA | Capability::EXPORTABLE_UNDER_WRAP,
            asymmetric::Algorithm::EcP256,
        )
        .unwrap_or_else(|err| panic!("error generating EC P-256 key: {err}"));

    // OAEP uses SHA-1, so label digest is SHA-1 of empty string
    let wrapped = client
        .get_rsa_wrapped_key(
            WRAP_KEY_ID,
            object::Type::AsymmetricKey,
            TARGET_KEY_ID,
            aes::Algorithm::Aes256,
            rsa::oaep::Algorithm::Sha1,
            rsa::mgf::Algorithm::Sha384,
            sha1_empty_label(),
        )
        .unwrap_or_else(|err| panic!("error wrapping EC key with mixed OAEP/MGF1: {err}"));

    // RSA-2048 OAEP ciphertext = 256 bytes
    assert!(!wrapped.is_empty());
    assert!(
        wrapped.len() > 256,
        "wrapped key should be larger than RSA-2048 ciphertext (got {} bytes)",
        wrapped.len()
    );

    clear_key_slots(&client);
}

/// Wrap EC key with OAEP SHA-512 / MGF1 SHA-512.
///
/// Adapted from test_wrapkey.sh line 340:
///   `--oaep rsa-oaep-sha512 --mgf1 mgf1-sha512`
#[test]
fn wrap_ec_key_oaep_sha512_mgf1_sha512() {
    let client = crate::get_hsm_client();
    clear_key_slots(&client);

    setup_public_wrap_key(&client, asymmetric::Algorithm::Rsa2048);

    client
        .generate_asymmetric_key(
            TARGET_KEY_ID,
            "ec_target".into(),
            TEST_DOMAINS,
            Capability::SIGN_ECDSA | Capability::EXPORTABLE_UNDER_WRAP,
            asymmetric::Algorithm::EcP256,
        )
        .unwrap_or_else(|err| panic!("error generating EC P-256 key: {err}"));

    let wrapped = client
        .get_rsa_wrapped_key(
            WRAP_KEY_ID,
            object::Type::AsymmetricKey,
            TARGET_KEY_ID,
            aes::Algorithm::Aes256,
            rsa::oaep::Algorithm::Sha512,
            rsa::mgf::Algorithm::Sha512,
            sha512_empty_label(),
        )
        .unwrap_or_else(|err| panic!("error wrapping EC key with SHA-512: {err}"));

    // RSA-2048 OAEP ciphertext = 256 bytes
    assert!(!wrapped.is_empty());
    assert!(
        wrapped.len() > 256,
        "wrapped key should be larger than RSA-2048 ciphertext (got {} bytes)",
        wrapped.len()
    );

    clear_key_slots(&client);
}
