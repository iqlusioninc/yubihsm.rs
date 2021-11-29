use crate::{generate_asymmetric_key, TEST_KEY_ID};
use rand::rngs::OsRng;
use rsa::{self, PublicKey};
use sha2::{self, Digest};

use yubihsm::{asymmetric, Capability};

/// Test RSA OAEP decryption
#[test]
fn rsa_decrypt_oaep_test() {
    let client = crate::get_hsm_client();

    generate_asymmetric_key(
        &client,
        asymmetric::Algorithm::Rsa2048,
        Capability::DECRYPT_OAEP,
    );

    let raw_public_key = client
        .get_public_key(TEST_KEY_ID)
        .unwrap_or_else(|err| panic!("error getting public key: {}", err));

    assert_eq!(raw_public_key.algorithm, asymmetric::Algorithm::Rsa2048);
    assert_eq!(raw_public_key.bytes.len(), 256);

    let plaintext = b"Secret message!";

    let rsa_modulus = rsa::BigUint::from_bytes_be(raw_public_key.as_slice());
    let rsa_exponent = rsa::BigUint::parse_bytes(b"65537", 10).unwrap();
    let rsa_public_key = rsa::RsaPublicKey::new(rsa_modulus, rsa_exponent).unwrap();

    let mut rng = OsRng;
    let ciphertext = rsa_public_key
        .encrypt(
            &mut rng,
            rsa::PaddingScheme::new_oaep::<sha2::Sha256>(),
            plaintext,
        )
        .expect("Failed to encrypt");

    let mut hasher = sha2::Sha256::new();
    hasher.update(b"");
    let label_hash = hasher.finalize();

    let decrypted_data = client
        .decrypt_oaep(
            TEST_KEY_ID,
            yubihsm::rsa::mgf::Algorithm::Sha256,
            ciphertext,
            label_hash.to_vec(),
        )
        .unwrap();

    assert_eq!(decrypted_data.as_slice(), plaintext);
}
