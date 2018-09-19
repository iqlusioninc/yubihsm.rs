use ring;
use untrusted;
use yubihsm::{self, AsymmetricAlg, Capability};

use {generate_asymmetric_key, TEST_KEY_ID, TEST_MESSAGE};

/// Test ECDSA signatures (using NIST P-256)
#[test]
fn generated_nistp256_key_test() {
    let mut session = create_session!();

    generate_asymmetric_key(
        &mut session,
        AsymmetricAlg::EC_P256,
        Capability::ASYMMETRIC_SIGN_ECDSA,
    );

    let pubkey_response = yubihsm::get_pubkey(&mut session, TEST_KEY_ID)
        .unwrap_or_else(|err| panic!("error getting public key: {}", err));

    assert_eq!(pubkey_response.algorithm, AsymmetricAlg::EC_P256);
    assert_eq!(pubkey_response.bytes.len(), 64);

    let mut pubkey = [0u8; 65];
    pubkey[0] = 0x04; // DER OCTET STRING tag
    pubkey[1..].copy_from_slice(pubkey_response.bytes.as_slice());

    let signature = yubihsm::sign_ecdsa_sha256(&mut session, TEST_KEY_ID, TEST_MESSAGE)
        .unwrap_or_else(|err| panic!("error performing ECDSA signature: {}", err));

    ring::signature::verify(
        &ring::signature::ECDSA_P256_SHA256_ASN1,
        untrusted::Input::from(&pubkey),
        untrusted::Input::from(TEST_MESSAGE),
        untrusted::Input::from(signature.as_ref()),
    ).unwrap();
}
