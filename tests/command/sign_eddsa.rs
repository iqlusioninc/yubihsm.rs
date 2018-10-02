use ring;
use untrusted;
use yubihsm::{AsymmetricAlg, Capability};

use test_vectors::ED25519_TEST_VECTORS;
use {generate_asymmetric_key, put_asymmetric_key, TEST_KEY_ID, TEST_MESSAGE};

/// Test Ed25519 against RFC 8032 test vectors
#[test]
fn test_vectors() {
    let mut client = ::get_hsm_client();

    for vector in ED25519_TEST_VECTORS {
        put_asymmetric_key(
            &mut client,
            AsymmetricAlg::Ed25519,
            Capability::ASYMMETRIC_SIGN_EDDSA,
            vector.sk,
        );

        let pubkey_response = client
            .get_pubkey(TEST_KEY_ID)
            .unwrap_or_else(|err| panic!("error getting public key: {}", err));

        assert_eq!(pubkey_response.algorithm, AsymmetricAlg::Ed25519);
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
    let mut client = ::get_hsm_client();

    generate_asymmetric_key(
        &mut client,
        AsymmetricAlg::Ed25519,
        Capability::ASYMMETRIC_SIGN_EDDSA,
    );

    let pubkey = client
        .get_pubkey(TEST_KEY_ID)
        .unwrap_or_else(|err| panic!("error getting public key: {}", err));

    assert_eq!(pubkey.algorithm, AsymmetricAlg::Ed25519);

    let signature = client
        .sign_ed25519(TEST_KEY_ID, TEST_MESSAGE)
        .unwrap_or_else(|err| panic!("error performing Ed25519 signature: {}", err));

    ring::signature::verify(
        &ring::signature::ED25519,
        untrusted::Input::from(pubkey.bytes.as_ref()),
        untrusted::Input::from(TEST_MESSAGE),
        untrusted::Input::from(signature.as_ref()),
    ).unwrap();
}
