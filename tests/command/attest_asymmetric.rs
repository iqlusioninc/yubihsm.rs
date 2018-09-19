use yubihsm::{self, AsymmetricAlg, Capability};

use {generate_asymmetric_key, EC_P256_PUBLIC_KEY_SIZE, TEST_KEY_ID};

/// Generate an attestation about a key in the HSM
#[test]
fn attest_asymmetric_test() {
    let mut session = create_session!();

    generate_asymmetric_key(
        &mut session,
        AsymmetricAlg::EC_P256,
        Capability::ASYMMETRIC_SIGN_ECDSA,
    );

    let certificate = yubihsm::attest_asymmetric(&mut session, TEST_KEY_ID, None)
        .unwrap_or_else(|err| panic!("error getting attestation certificate: {}", err));

    // TODO: more tests, e.g. test that the certificate validates
    assert!(certificate.len() > EC_P256_PUBLIC_KEY_SIZE);
}
