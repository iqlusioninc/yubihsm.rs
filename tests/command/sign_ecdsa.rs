use crate::{generate_asymmetric_key, TEST_KEY_ID, TEST_MESSAGE};
use ring;
use sha2::{Digest, Sha256};
use untrusted;
use yubihsm::{AsymmetricAlg, Capability};

/// Test ECDSA signatures (using NIST P-256)
#[test]
fn generated_nistp256_key_test() {
    let mut client = crate::get_hsm_client();

    generate_asymmetric_key(&mut client, AsymmetricAlg::EC_P256, Capability::SIGN_ECDSA);

    let pubkey_response = client
        .get_public_key(TEST_KEY_ID)
        .unwrap_or_else(|err| panic!("error getting public key: {}", err));

    assert_eq!(pubkey_response.algorithm, AsymmetricAlg::EC_P256);
    assert_eq!(pubkey_response.bytes.len(), 64);

    let mut pubkey = [0u8; 65];
    pubkey[0] = 0x04; // DER OCTET STRING tag
    pubkey[1..].copy_from_slice(pubkey_response.bytes.as_slice());

    let test_digest = Vec::from(Sha256::digest(TEST_MESSAGE).as_ref());

    let signature = client
        .sign_ecdsa(TEST_KEY_ID, test_digest)
        .unwrap_or_else(|err| panic!("error performing ECDSA signature: {}", err));

    ring::signature::verify(
        &ring::signature::ECDSA_P256_SHA256_ASN1,
        untrusted::Input::from(&pubkey),
        untrusted::Input::from(TEST_MESSAGE),
        untrusted::Input::from(signature.as_ref()),
    )
    .unwrap();
}
