//! RSA (Rivest–Shamir–Adleman) asymmetric cryptosystem tests

use ::rsa::{pkcs8::DecodePrivateKey, traits::PrivateKeyParts, RsaPrivateKey};
use yubihsm::object;

/// Domain IDs for test key
const TEST_SIGNING_KEY_DOMAINS: yubihsm::Domain = yubihsm::Domain::DOM1;

/// Label for test key
const TEST_SIGNING_KEY_LABEL: &str = "Signatory test key";

/// RSA-2048 PKCS#8 private key encoded as ASN.1 DER
const RSA_2048_PRIV_DER: &[u8] = include_bytes!("./rsa2048-priv.der");

#[test]
fn rsa_put_asymmetric_key() {
    let key = RsaPrivateKey::from_pkcs8_der(RSA_2048_PRIV_DER).unwrap();
    let primes = key.primes();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(&primes[0].to_bytes_be());
    bytes.extend_from_slice(&primes[1].to_bytes_be());

    let client = crate::get_hsm_client();
    let _ = client.delete_object(223, object::Type::AsymmetricKey);
    let id = client
        .put_asymmetric_key(
            223,
            TEST_SIGNING_KEY_LABEL.into(),
            TEST_SIGNING_KEY_DOMAINS,
            yubihsm::Capability::SIGN_PSS,
            yubihsm::asymmetric::Algorithm::Rsa2048,
            bytes,
        )
        .expect("impot asymmetric key");

    let public = client.get_public_key(id).expect("read public key");
    let public = public.rsa().expect("rsa public key expected");

    assert_eq!(public, key.as_ref().clone());
}
