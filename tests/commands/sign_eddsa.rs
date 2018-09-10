use ring;
use untrusted;
use yubihsm::{self, AsymmetricAlgorithm, Capability};

use test_vectors::ED25519_TEST_VECTORS;
use {generate_asymmetric_key, put_asymmetric_key, TEST_KEY_ID, TEST_MESSAGE};

/// Test Ed25519 against RFC 8032 test vectors
#[test]
fn test_vectors() {
    let mut session = create_session!();

    for vector in ED25519_TEST_VECTORS {
        put_asymmetric_key(
            &mut session,
            AsymmetricAlgorithm::EC_ED25519,
            Capability::ASYMMETRIC_SIGN_EDDSA,
            vector.sk,
        );

        let pubkey_response = yubihsm::get_pubkey(&mut session, TEST_KEY_ID)
            .unwrap_or_else(|err| panic!("error getting public key: {}", err));

        assert_eq!(pubkey_response.algorithm, AsymmetricAlgorithm::EC_ED25519);
        assert_eq!(pubkey_response.bytes, vector.pk);

        let signature = yubihsm::sign_ed25519(&mut session, TEST_KEY_ID, vector.msg)
            .unwrap_or_else(|err| panic!("error performing Ed25519 signature: {}", err));

        assert_eq!(signature.as_ref(), vector.sig);
    }
}

/// Test Ed25519 signing using a randomly generated HSM key
#[test]
fn generated_key_test() {
    let mut session = create_session!();

    generate_asymmetric_key(
        &mut session,
        AsymmetricAlgorithm::EC_ED25519,
        Capability::ASYMMETRIC_SIGN_EDDSA,
    );

    let pubkey = yubihsm::get_pubkey(&mut session, TEST_KEY_ID)
        .unwrap_or_else(|err| panic!("error getting public key: {}", err));

    assert_eq!(pubkey.algorithm, AsymmetricAlgorithm::EC_ED25519);

    let signature = yubihsm::sign_ed25519(&mut session, TEST_KEY_ID, TEST_MESSAGE)
        .unwrap_or_else(|err| panic!("error performing Ed25519 signature: {}", err));

    ring::signature::verify(
        &ring::signature::ED25519,
        untrusted::Input::from(pubkey.bytes.as_ref()),
        untrusted::Input::from(TEST_MESSAGE),
        untrusted::Input::from(signature.as_ref()),
    ).unwrap();
}
