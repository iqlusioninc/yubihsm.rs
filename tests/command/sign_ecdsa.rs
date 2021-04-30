//! ECDSA signing test

use crate::{generate_asymmetric_key, TEST_KEY_ID, TEST_MESSAGE};
use p256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    NistP256,
};
use sha2::{Digest, Sha256};
use yubihsm::{asymmetric, Capability};

/// Test ECDSA signatures (using NIST P-256)
#[test]
fn generated_nistp256_key_test() {
    let client = crate::get_hsm_client();

    generate_asymmetric_key(
        &client,
        asymmetric::Algorithm::EcP256,
        Capability::SIGN_ECDSA,
    );

    let raw_public_key = client
        .get_public_key(TEST_KEY_ID)
        .unwrap_or_else(|err| panic!("error getting public key: {}", err));

    assert_eq!(raw_public_key.algorithm, asymmetric::Algorithm::EcP256);
    assert_eq!(raw_public_key.bytes.len(), 64);

    let public_key = raw_public_key.ecdsa::<NistP256>().unwrap();
    let test_digest = Sha256::digest(TEST_MESSAGE);

    let signature = Signature::from_der(
        &client
            .sign_ecdsa_prehash_raw(TEST_KEY_ID, test_digest.as_slice())
            .unwrap_or_else(|err| panic!("error performing ECDSA signature: {}", err)),
    )
    .unwrap();

    let verify_key = VerifyingKey::from_encoded_point(&public_key).unwrap();
    assert!(verify_key.verify(TEST_MESSAGE, &signature).is_ok());
}
