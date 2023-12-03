//! RSA (Rivest–Shamir–Adleman) asymmetric cryptosystem tests

use crate::{
    clear_test_key_slot, test_vectors::AESCCM_TEST_VECTORS, TEST_DOMAINS, TEST_KEY_ID,
    TEST_KEY_LABEL,
};
use ::rsa::{pkcs8::DecodePrivateKey, traits::PrivateKeyParts, RsaPrivateKey};
use yubihsm::{object, wrap, Capability};

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

#[test]
fn rsa_import_wrapped_key() {
    let key = RsaPrivateKey::from_pkcs8_der(RSA_2048_PRIV_DER).unwrap();
    let algorithm = wrap::Algorithm::Aes128Ccm;
    let capabilities = Capability::EXPORT_WRAPPED | Capability::IMPORT_WRAPPED;
    let delegated_capabilities = Capability::all();
    let asymmetric_key_id = 224;

    let plaintext = wrap::Plaintext::from_rsa(
        algorithm,
        asymmetric_key_id,
        Capability::empty(),
        TEST_DOMAINS,
        TEST_KEY_LABEL.into(),
        key.clone(),
    )
    .expect("build message with RSA key");

    let wrap_key = wrap::Key::from_bytes(TEST_KEY_ID, AESCCM_TEST_VECTORS[0].key).unwrap();
    let message = plaintext
        .encrypt(&wrap_key)
        .expect("failed to encrypt the wrapped key");

    let client = crate::get_hsm_client();
    clear_test_key_slot(&client, object::Type::WrapKey);
    let _ = client.delete_object(asymmetric_key_id, object::Type::AsymmetricKey);

    let _key_id = client
        .put_wrap_key(
            TEST_KEY_ID,
            TEST_KEY_LABEL.into(),
            TEST_DOMAINS,
            capabilities,
            delegated_capabilities,
            algorithm,
            AESCCM_TEST_VECTORS[0].key,
        )
        .unwrap_or_else(|err| panic!("error generating wrap key: {err}"));

    let handle = client
        .import_wrapped(TEST_KEY_ID, message)
        .expect("impot asymmetric key");

    assert_eq!(handle.object_id, asymmetric_key_id);
    let public = client
        .get_public_key(handle.object_id)
        .expect("read public key");
    let public = public.rsa().expect("rsa public key expected");

    assert_eq!(public, key.as_ref().clone());
}
