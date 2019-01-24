use yubihsm::{AsymmetricAlg, Capability};

use crate::{generate_asymmetric_key, EC_P256_PUBLIC_KEY_SIZE, TEST_KEY_ID};

/// Generate an attestation about a key in the HSM
#[test]
fn attest_asymmetric_test() {
    let mut client = crate::get_hsm_client();

    generate_asymmetric_key(
        &mut client,
        AsymmetricAlg::EC_P256,
        Capability::ASYMMETRIC_SIGN_ECDSA,
    );

    let certificate = client
        .attest_asymmetric(TEST_KEY_ID, None)
        .unwrap_or_else(|err| panic!("error getting attestation certificate: {}", err));

    // TODO: more tests, e.g. test that the certificate validates
    assert!(certificate.len() > EC_P256_PUBLIC_KEY_SIZE);
}
