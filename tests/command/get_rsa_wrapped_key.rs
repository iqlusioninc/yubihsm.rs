//! Integration tests for `get_rsa_wrapped_key` (command 0x74)
//!
//! Adapted from asym_wrap_test.c (CKM_RSA_AES_KEY_WRAP scenarios).
//! These run against MockHSM as well as real hardware.
//!
//! The flow is: generate an RSA key pair on the HSM, extract the public key,
//! import it as a `PublicWrapKey` via `put_public_wrap_key`, then use
//! `get_rsa_wrapped_key` against that public wrap key.

use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
use yubihsm::{asymmetric, object, rsa, symmetric, Capability, Domain};

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
fn setup_public_wrap_key(client: &yubihsm::Client, algorithm: asymmetric::Algorithm) {
    // Generate RSA key pair on the HSM
    client
        .generate_asymmetric_key(
            RSA_KEY_ID,
            "rsa_keypair".parse().unwrap(),
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
            "rsa_pubwrap".parse().unwrap(),
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
            "ec_target".parse().unwrap(),
            TEST_DOMAINS,
            Capability::SIGN_ECDSA | Capability::EXPORTABLE_UNDER_WRAP,
            asymmetric::Algorithm::EcP256,
        )
        .unwrap_or_else(|err| panic!("error generating EC P-256 key: {err}"));

    let wrapped = client
        .get_rsa_wrapped_key(
            yubihsm::client::RsaWrappedKeyParams {
                wrap_key_id: WRAP_KEY_ID,
                target_type: object::Type::AsymmetricKey,
                target_id: TARGET_KEY_ID,
                aes_algorithm: symmetric::Algorithm::Aes256,
                oaep_algorithm: rsa::oaep::Algorithm::Sha256,
                mgf1_algorithm: rsa::mgf::Algorithm::Sha256,
            },
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
            "ec_target".parse().unwrap(),
            TEST_DOMAINS,
            Capability::SIGN_ECDSA | Capability::EXPORTABLE_UNDER_WRAP,
            asymmetric::Algorithm::EcP256,
        )
        .unwrap_or_else(|err| panic!("error generating EC P-256 key: {err}"));

    let wrapped = client
        .get_rsa_wrapped_key(
            yubihsm::client::RsaWrappedKeyParams {
                wrap_key_id: WRAP_KEY_ID,
                target_type: object::Type::AsymmetricKey,
                target_id: TARGET_KEY_ID,
                aes_algorithm: symmetric::Algorithm::Aes256,
                oaep_algorithm: rsa::oaep::Algorithm::Sha256,
                mgf1_algorithm: rsa::mgf::Algorithm::Sha256,
            },
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
            "ec_target".parse().unwrap(),
            TEST_DOMAINS,
            Capability::SIGN_ECDSA | Capability::EXPORTABLE_UNDER_WRAP,
            asymmetric::Algorithm::EcP256,
        )
        .unwrap_or_else(|err| panic!("error generating EC P-256 key: {err}"));

    let wrapped = client
        .get_rsa_wrapped_key(
            yubihsm::client::RsaWrappedKeyParams {
                wrap_key_id: WRAP_KEY_ID,
                target_type: object::Type::AsymmetricKey,
                target_id: TARGET_KEY_ID,
                aes_algorithm: symmetric::Algorithm::Aes256,
                oaep_algorithm: rsa::oaep::Algorithm::Sha256,
                mgf1_algorithm: rsa::mgf::Algorithm::Sha256,
            },
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
            "ec_target".parse().unwrap(),
            TEST_DOMAINS,
            Capability::SIGN_ECDSA | Capability::EXPORTABLE_UNDER_WRAP,
            asymmetric::Algorithm::EcP256,
        )
        .unwrap_or_else(|err| panic!("error generating EC P-256 key: {err}"));

    // OAEP uses SHA-1, so label digest is SHA-1 of empty string
    let wrapped = client
        .get_rsa_wrapped_key(
            yubihsm::client::RsaWrappedKeyParams {
                wrap_key_id: WRAP_KEY_ID,
                target_type: object::Type::AsymmetricKey,
                target_id: TARGET_KEY_ID,
                aes_algorithm: symmetric::Algorithm::Aes256,
                oaep_algorithm: rsa::oaep::Algorithm::Sha1,
                mgf1_algorithm: rsa::mgf::Algorithm::Sha384,
            },
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
            "ec_target".parse().unwrap(),
            TEST_DOMAINS,
            Capability::SIGN_ECDSA | Capability::EXPORTABLE_UNDER_WRAP,
            asymmetric::Algorithm::EcP256,
        )
        .unwrap_or_else(|err| panic!("error generating EC P-256 key: {err}"));

    let wrapped = client
        .get_rsa_wrapped_key(
            yubihsm::client::RsaWrappedKeyParams {
                wrap_key_id: WRAP_KEY_ID,
                target_type: object::Type::AsymmetricKey,
                target_id: TARGET_KEY_ID,
                aes_algorithm: symmetric::Algorithm::Aes256,
                oaep_algorithm: rsa::oaep::Algorithm::Sha512,
                mgf1_algorithm: rsa::mgf::Algorithm::Sha512,
            },
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

/// End-to-end round trip: the wrapped blob must actually decrypt back to the
/// original key material.
///
/// The other tests here only assert the response is longer than the RSA
/// ciphertext, which a device returning random bytes of the right length would
/// also satisfy. This one holds the RSA private key, so it can undo the whole
/// CKM_RSA_AES_KEY_WRAP construction and compare.
///
/// The label is the digest of the empty string, which is what standard OAEP
/// computes for an absent label — so the plain `Oaep::new` decryptor here and
/// the device's pre-hashed-label form agree.
#[test]
fn wrapped_key_round_trips_to_the_original_material() {
    use ::rsa::{oaep::Oaep, traits::PaddingScheme, traits::PublicKeyParts};
    use aes_kw::cipher::KeyInit;
    use aes_kw::KwpAes256;
    use sha2::Sha256;

    let client = crate::get_hsm_client();
    clear_key_slots(&client);
    let _ = client.delete_object(TARGET_KEY_ID, object::Type::SymmetricKey);

    // Keypair generated here, so the test holds the private half.
    let mut rng = rand::rng();
    let private_key =
        ::rsa::RsaPrivateKey::new(&mut rng, 2048).expect("generating an RSA-2048 key");
    let modulus = private_key.n().to_be_bytes().to_vec();

    client
        .put_public_wrap_key(
            WRAP_KEY_ID,
            "roundtrip_wrap".parse().unwrap(),
            TEST_DOMAINS,
            Capability::EXPORT_WRAPPED,
            Capability::all(),
            asymmetric::Algorithm::Rsa2048,
            modulus,
        )
        .unwrap_or_else(|err| panic!("error importing public wrap key: {err}"));

    // A target whose bytes we know exactly.
    let target_material: Vec<u8> = (0u8..32).collect();
    client
        .put_symmetric_key(
            TARGET_KEY_ID,
            "roundtrip_target".parse().unwrap(),
            TEST_DOMAINS,
            Capability::EXPORTABLE_UNDER_WRAP,
            symmetric::Algorithm::Aes256,
            target_material.clone(),
        )
        .unwrap_or_else(|err| panic!("error putting target symmetric key: {err}"));

    let wrapped = client
        .get_rsa_wrapped_key(
            yubihsm::client::RsaWrappedKeyParams {
                wrap_key_id: WRAP_KEY_ID,
                target_type: object::Type::SymmetricKey,
                target_id: TARGET_KEY_ID,
                aes_algorithm: symmetric::Algorithm::Aes256,
                oaep_algorithm: rsa::oaep::Algorithm::Sha256,
                mgf1_algorithm: rsa::mgf::Algorithm::Sha256,
            },
            sha256_empty_label(),
        )
        .unwrap_or_else(|err| panic!("error wrapping symmetric key: {err}"));

    // RSA-OAEP(ephemeral AES key) || AES-KWP(target key material)
    let rsa_len = private_key.size();
    assert!(
        wrapped.len() > rsa_len,
        "response is too short to contain both parts"
    );
    let (encrypted_ephemeral, wrapped_target) = wrapped.split_at(rsa_len);

    let ephemeral = Oaep::<Sha256>::new()
        .decrypt(Some(&mut rng), &private_key, encrypted_ephemeral)
        .expect("decrypting the ephemeral AES key");
    assert_eq!(ephemeral.len(), 32, "expected an AES-256 ephemeral key");

    let mut recovered = vec![0u8; wrapped_target.len()];
    let recovered = KwpAes256::new_from_slice(&ephemeral)
        .expect("ephemeral key size")
        .unwrap_key(wrapped_target, &mut recovered)
        .expect("AES-KWP unwrap");

    assert_eq!(
        recovered, target_material,
        "the unwrapped material must equal the key that was exported"
    );

    clear_key_slots(&client);
    let _ = client.delete_object(TARGET_KEY_ID, object::Type::SymmetricKey);
}
