//! Ed25519 signing test

use crate::{
    generate_asymmetric_key, put_asymmetric_key, test_vectors::ED25519_TEST_VECTORS, TEST_KEY_ID,
    TEST_MESSAGE,
};
use ed25519_dalek::Verifier;
use yubihsm::{asymmetric, Capability};

/// Test Ed25519 against RFC 8032 test vectors
#[test]
fn test_vectors() {
    let client = crate::get_hsm_client();

    for vector in ED25519_TEST_VECTORS {
        put_asymmetric_key(
            &client,
            asymmetric::Algorithm::Ed25519,
            Capability::SIGN_EDDSA,
            vector.sk,
        );

        let pubkey_response = client
            .get_public_key(TEST_KEY_ID)
            .unwrap_or_else(|err| panic!("error getting public key: {}", err));

        assert_eq!(pubkey_response.algorithm, asymmetric::Algorithm::Ed25519);
        assert_eq!(pubkey_response.bytes, vector.pk);

        let signature = client
            .sign_ed25519(TEST_KEY_ID, vector.msg)
            .unwrap_or_else(|err| panic!("error performing Ed25519 signature: {}", err));

        assert_eq!(vector.sig, &signature.to_bytes());
    }
}

/// Test Ed25519 signing using a randomly generated HSM key
#[test]
fn generated_key_test() {
    let client = crate::get_hsm_client();

    generate_asymmetric_key(
        &client,
        asymmetric::Algorithm::Ed25519,
        Capability::SIGN_EDDSA,
    );

    let public_key = client
        .get_public_key(TEST_KEY_ID)
        .unwrap_or_else(|err| panic!("error getting public key: {}", err));

    assert_eq!(public_key.algorithm, asymmetric::Algorithm::Ed25519);

    let signature = client
        .sign_ed25519(TEST_KEY_ID, TEST_MESSAGE)
        .unwrap_or_else(|err| panic!("error performing Ed25519 signature: {}", err));

    assert!(
        ed25519_dalek::VerifyingKey::try_from(public_key.ed25519().unwrap().as_ref())
            .unwrap()
            .verify(TEST_MESSAGE, &signature)
            .is_ok()
    );
}
