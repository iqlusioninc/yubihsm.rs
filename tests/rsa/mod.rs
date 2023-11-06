//! RSA (Rivest–Shamir–Adleman) asymmetric cryptosystem tests

use crate::{
    clear_test_key_slot, test_vectors::AESCCM_TEST_VECTORS, TEST_DOMAINS, TEST_KEY_ID,
    TEST_KEY_LABEL,
};
use ::rsa::{pkcs8::DecodePrivateKey, traits::PrivateKeyParts, RsaPrivateKey};
use signature::{Keypair, Verifier};
use spki::SubjectPublicKeyInfoOwned;
use std::{str::FromStr, time::Duration};
use x509_cert::{
    builder::{Builder, CertificateBuilder, Profile},
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};
use yubihsm::{
    asymmetric::signature::Signer as _,
    object,
    rsa::{pkcs1, pss, SignatureAlgorithm},
    wrap, Capability, Client,
};

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

/// Example message to sign
const TEST_MESSAGE: &[u8] =
    b"RSA (Rivest-Shamir-Adleman) is a public-key cryptosystem, one of the oldest, \
      that is widely used for secure data transmission.";

fn create_pss_signer<S>(key_id: object::Id) -> pss::Signer<S>
where
    S: SignatureAlgorithm,
{
    let client = crate::get_hsm_client();
    create_yubihsm_key(&client, key_id, yubihsm::asymmetric::Algorithm::Rsa2048);
    pss::Signer::create(client.clone(), key_id).unwrap()
}

fn create_pkcs_signer<S>(key_id: object::Id) -> pkcs1::Signer<S>
where
    S: SignatureAlgorithm,
{
    let client = crate::get_hsm_client();
    create_yubihsm_key(&client, key_id, yubihsm::asymmetric::Algorithm::Rsa2048);
    pkcs1::Signer::create(client.clone(), key_id).unwrap()
}

/// Create the key on the YubiHSM to use for this test
// TODO(baloo): this is a duplicate from ecdsa tests
fn create_yubihsm_key(client: &Client, key_id: object::Id, alg: yubihsm::asymmetric::Algorithm) {
    // Delete the key in TEST_KEY_ID slot it exists
    // Ignore errors since the object may not exist yet
    let _ = client.delete_object(key_id, yubihsm::object::Type::AsymmetricKey);

    // Create a new key for testing
    let _key = client
        .generate_asymmetric_key(
            key_id,
            TEST_SIGNING_KEY_LABEL.into(),
            TEST_SIGNING_KEY_DOMAINS,
            yubihsm::Capability::SIGN_PSS
                | yubihsm::Capability::SIGN_PKCS
                | Capability::EXPORTABLE_UNDER_WRAP,
            alg,
        )
        .unwrap();
}

#[test]
fn rsa_pss_sha256_sign_test() {
    let signer = create_pss_signer::<sha2::Sha256>(221);
    let verifying_key = signer.verifying_key();
    let verifying_key_from_public =
        ::rsa::pss::VerifyingKey::<sha2::Sha256>::new(signer.public_key());

    let signature = signer.sign(TEST_MESSAGE);

    assert!(verifying_key.verify(TEST_MESSAGE, &signature).is_ok());
    assert!(verifying_key_from_public
        .verify(TEST_MESSAGE, &signature)
        .is_ok());
}

#[test]
fn rsa_pkcs1_sha256_sign_test() {
    let signer = create_pkcs_signer::<sha2::Sha256>(222);
    let verifying_key = signer.verifying_key();
    let verifying_key_from_public =
        ::rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(signer.public_key());

    let signature = signer.sign(TEST_MESSAGE);

    assert!(verifying_key.verify(TEST_MESSAGE, &signature).is_ok());
    assert!(verifying_key_from_public
        .verify(TEST_MESSAGE, &signature)
        .is_ok());
}

#[test]
fn rsa_pss_sha1_ca() {
    let signer = create_pss_signer::<sha1::Sha1>(223);

    let serial_number = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();
    let profile = Profile::Root;
    let subject =
        Name::from_str("CN=World domination corporation,O=World domination Inc,C=US").unwrap();
    let pub_key = SubjectPublicKeyInfoOwned::from_key(signer.verifying_key()).unwrap();

    let builder =
        CertificateBuilder::new(profile, serial_number, validity, subject, pub_key, &signer)
            .expect("Create certificate");

    builder.build().unwrap();
}

#[test]
fn rsa_pss_sha256_ca() {
    let signer = create_pss_signer::<sha2::Sha256>(224);

    let serial_number = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();
    let profile = Profile::Root;
    let subject =
        Name::from_str("CN=World domination corporation,O=World domination Inc,C=US").unwrap();
    let pub_key = SubjectPublicKeyInfoOwned::from_key(signer.verifying_key()).unwrap();

    let builder =
        CertificateBuilder::new(profile, serial_number, validity, subject, pub_key, &signer)
            .expect("Create certificate");

    builder.build().unwrap();
}

#[test]
fn rsa_pkcs1_sha256_ca() {
    let signer = create_pkcs_signer::<sha2::Sha256>(225);

    let serial_number = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();
    let profile = Profile::Root;
    let subject =
        Name::from_str("CN=World domination corporation,O=World domination Inc,C=US").unwrap();
    let pub_key = SubjectPublicKeyInfoOwned::from_key(signer.verifying_key()).unwrap();

    let builder =
        CertificateBuilder::new(profile, serial_number, validity, subject, pub_key, &signer)
            .expect("Create certificate");

    builder.build().unwrap();
}

#[test]
fn rsa_raw_pkcs1_sha256_sign_test() {
    let client = crate::get_hsm_client();
    create_yubihsm_key(&client, 226, yubihsm::asymmetric::Algorithm::Rsa2048);

    let signature = client
        .sign_rsa_pkcs1v15_sha256(226, TEST_MESSAGE)
        .expect("sign message");
    let public_key = client.get_public_key(226).unwrap().rsa().unwrap();
    let verifying_key = ::rsa::pkcs1v15::VerifyingKey::<sha2::Sha256>::new(public_key);
    assert!(verifying_key
        .verify(
            TEST_MESSAGE,
            &::rsa::pkcs1v15::Signature::try_from(signature.as_slice()).unwrap()
        )
        .is_ok());
}

#[test]
fn rsa_raw_pss_sha256_sign_test() {
    let client = crate::get_hsm_client();
    create_yubihsm_key(&client, 227, yubihsm::asymmetric::Algorithm::Rsa2048);

    let signature = client
        .sign_rsa_pss_sha256(227, TEST_MESSAGE)
        .expect("sign message");
    let public_key = client.get_public_key(227).unwrap().rsa().unwrap();
    let verifying_key = ::rsa::pss::VerifyingKey::<sha2::Sha256>::new(public_key);
    assert!(verifying_key
        .verify(
            TEST_MESSAGE,
            &::rsa::pss::Signature::try_from(signature.as_slice()).unwrap()
        )
        .is_ok());
}
