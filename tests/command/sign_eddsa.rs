//! Tests for producing Ed25519 signatures

use crate::{
    generate_asymmetric_key, put_asymmetric_key, test_vectors::ED25519_TEST_VECTORS, TEST_KEY_ID,
    TEST_MESSAGE,
};
use ring::signature::UnparsedPublicKey;
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

        assert_eq!(signature.as_ref(), vector.sig);
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

    let pubkey = client
        .get_public_key(TEST_KEY_ID)
        .unwrap_or_else(|err| panic!("error getting public key: {}", err));

    assert_eq!(pubkey.algorithm, asymmetric::Algorithm::Ed25519);

    let signature = client
        .sign_ed25519(TEST_KEY_ID, TEST_MESSAGE)
        .unwrap_or_else(|err| panic!("error performing Ed25519 signature: {}", err));

    UnparsedPublicKey::new(&ring::signature::ED25519, &pubkey.bytes)
        .verify(TEST_MESSAGE, signature.as_ref())
        .unwrap();
}
