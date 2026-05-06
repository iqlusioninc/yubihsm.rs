//! Elliptic Curve Digital Signature Algorithm (ECDSA) tests

use ::ecdsa::{
    der,
    elliptic_curve::{
        point::PointCompression,
        sec1::{self, FromSec1Point, ToSec1Point},
        AffinePoint, CurveArithmetic, FieldBytesSize,
    },
    signature::{Keypair, Verifier},
    EcdsaCurve,
};
use hex_literal::hex;
use spki::SubjectPublicKeyInfoOwned;
use std::{str::FromStr, time::Duration};
use x509_cert::{
    builder::{profile::cabf, Builder, CertificateBuilder},
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};
use yubihsm::{
    asymmetric::{self, signature::Signer as _},
    ecdsa::{self, algorithm::CurveAlgorithm, NistP256, NistP384},
    object, wrap, Capability, Client,
};

#[cfg(feature = "secp256k1")]
use {
    ::ecdsa::signature::{digest::Digest, DigestSigner, DigestVerifier},
    yubihsm::ecdsa::Secp256k1,
};

use crate::{clear_test_key_slot, TEST_DOMAINS, TEST_KEY_ID, TEST_KEY_LABEL};

/// Domain IDs for test key
const TEST_SIGNING_KEY_DOMAINS: yubihsm::Domain = yubihsm::Domain::DOM1;

/// Capability for test key
const TEST_SIGNING_KEY_CAPABILITIES: yubihsm::Capability = yubihsm::Capability::SIGN_ECDSA;

/// Label for test key
const TEST_SIGNING_KEY_LABEL: &str = "Signatory test key";

/// Example message to sign
const TEST_MESSAGE: &[u8] =
    b"The Elliptic Curve Digital Signature Algorithm (ECDSA) is a variant of the \
      Digital Signature Algorithm (DSA) which uses elliptic curve cryptography.";

/// Create the signer for this test
fn create_signer<C>(key_id: object::Id) -> ecdsa::Signer<C>
where
    C: CurveAlgorithm + CurveArithmetic + PointCompression + EcdsaCurve,
    AffinePoint<C>: FromSec1Point<C> + ToSec1Point<C>,
    FieldBytesSize<C>: sec1::ModulusSize,
{
    let client = crate::get_hsm_client();
    create_yubihsm_key(&client, key_id, C::asymmetric_algorithm());
    ecdsa::Signer::create(client.clone(), key_id).unwrap()
}

/// Create the key on the YubiHSM to use for this test
fn create_yubihsm_key(client: &Client, key_id: object::Id, alg: yubihsm::asymmetric::Algorithm) {
    // Delete the key in TEST_KEY_ID slot it exists
    // Ignore errors since the object may not exist yet
    let _ = client.delete_object(key_id, yubihsm::object::Type::AsymmetricKey);

    // Create a new key for testing
    client
        .generate_asymmetric_key(
            key_id,
            TEST_SIGNING_KEY_LABEL.into(),
            TEST_SIGNING_KEY_DOMAINS,
            TEST_SIGNING_KEY_CAPABILITIES,
            alg,
        )
        .unwrap();
}

#[test]
fn ecdsa_nistp256_sign_test() {
    let signer = create_signer::<NistP256>(201);
    let verify_key = p256::ecdsa::VerifyingKey::from_sec1_point(signer.public_key()).unwrap();

    let signature: ecdsa::Signature<NistP256> = signer.sign(TEST_MESSAGE);
    assert!(verify_key.verify(TEST_MESSAGE, &signature).is_ok());
}

#[cfg(feature = "secp256k1")]
#[test]
fn ecdsa_secp256k1_sign_test() {
    let signer = create_signer::<Secp256k1>(202);
    let verify_key = k256::ecdsa::VerifyingKey::from_sec1_point(signer.public_key()).unwrap();

    let signature: ecdsa::Signature<Secp256k1> = signer.sign(TEST_MESSAGE);
    assert!(verify_key.verify(TEST_MESSAGE, &signature).is_ok());
}

#[cfg(feature = "secp256k1")]
#[test]
fn ecdsa_secp256k1_sign_recover_test() {
    use k256::{ecdsa::VerifyingKey, PublicKey};

    let signer = create_signer::<Secp256k1>(203);
    let verify_key = VerifyingKey::from_sec1_point(signer.public_key()).unwrap();

    let (signature, recovery_id) = signer
        .try_sign_digest(|d: &mut sha2::Sha256| {
            d.update(TEST_MESSAGE);
            Ok(())
        })
        .unwrap();

    assert!(verify_key.verify(TEST_MESSAGE, &signature).is_ok());

    let recovered_key = VerifyingKey::recover_from_digest(
        sha2::Sha256::new_with_prefix(TEST_MESSAGE),
        &signature,
        recovery_id,
    )
    .unwrap();
    recovered_key
        .verify_digest(
            |d: &mut sha2::Sha256| {
                d.update(TEST_MESSAGE);
                Ok(())
            },
            &signature,
        )
        .unwrap();

    let recovered_pk = PublicKey::from(recovered_key);
    let signer_pk = PublicKey::from_sec1_point(signer.public_key()).unwrap();
    assert_eq!(&recovered_pk, &signer_pk);
}

#[test]
fn ecdsa_nistp256_ca() {
    let signer = create_signer::<NistP256>(204);

    let serial_number = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();
    let subject =
        Name::from_str("CN=World domination corporation,O=World domination Inc,C=US").unwrap();
    let pub_key = SubjectPublicKeyInfoOwned::from_key(&signer.verifying_key()).unwrap();
    let profile = cabf::Root::new(false, subject).unwrap();

    let builder = CertificateBuilder::new(profile, serial_number, validity, pub_key)
        .expect("Create certificate");

    builder
        .build::<_, der::Signature<NistP256>>(&signer)
        .unwrap();
}

#[test]
fn ecdsa_nistp384_ca() {
    let signer = create_signer::<NistP384>(205);

    let serial_number = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::new(5, 0)).unwrap();
    let subject =
        Name::from_str("CN=World domination corporation,O=World domination Inc,C=US").unwrap();
    let pub_key = SubjectPublicKeyInfoOwned::from_key(&signer.verifying_key()).unwrap();
    let profile = cabf::Root::new(false, subject).unwrap();

    let builder = CertificateBuilder::new(profile, serial_number, validity, pub_key)
        .expect("Create certificate");

    builder
        .build::<_, der::Signature<NistP384>>(&signer)
        .unwrap();
}

#[test]
fn ecdsa_nistp384_import_wrapped() {
    let secret_key = p384::SecretKey::generate();
    let public_key = secret_key.public_key();

    let algorithm = wrap::Algorithm::Aes256Ccm;
    let capabilities =
        Capability::SIGN_ECDSA | Capability::EXPORT_WRAPPED | Capability::IMPORT_WRAPPED;
    let delegated_capabilities = Capability::all();
    let asymmetric_key_id = 206;

    let plaintext = wrap::Plaintext::from_ecdsa(
        algorithm,
        asymmetric_key_id,
        capabilities,
        TEST_DOMAINS,
        TEST_SIGNING_KEY_LABEL.into(),
        //delegated_capabilities,
        secret_key,
    )
    .expect("build message with ecdsa key");

    let wrap_key = wrap::Key::from_bytes(
        TEST_KEY_ID,
        &hex!("0000000000000000000000000000000000000000000000000000000000000000"),
    )
    .unwrap();
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
            &hex!("0000000000000000000000000000000000000000000000000000000000000000"),
        )
        .unwrap_or_else(|err| panic!("error generating wrap key: {err}"));

    let handle = client
        .import_wrapped(TEST_KEY_ID, message)
        .expect("import asymmetric key");

    assert_eq!(handle.object_id, asymmetric_key_id);
    let public = client
        .get_public_key(handle.object_id)
        .expect("read public key");
    let public = public
        .ecdsa::<p384::NistP384>()
        .expect("ecdsa public key expected");

    assert_eq!(
        p384::PublicKey::try_from(&public).expect("valid point"),
        public_key
    );
}

#[test]
fn ecdsa_nistp384_put_key() {
    let secret_key = p384::SecretKey::from_slice(&[
        0xe7, 0xf8, 0xff, 0xaf, 0xd8, 0xf2, 0xe9, 0xd9, 0x5c, 0x62, 0xd, 0x44, 0x6b, 0x80, 0xb4,
        0xa0, 0xb8, 0xa9, 0x64, 0xc9, 0x8d, 0xc, 0xf6, 0xb2, 0x2f, 0x2d, 0x5b, 0x88, 0xed, 0x39,
        0xd4, 0x99, 0x89, 0xfb, 0xa7, 0xf3, 0x71, 0xeb, 0x3d, 0x13, 0x2d, 0x22, 0x22, 0xcd, 0x11,
        0xbf, 0xb0, 0xd,
    ])
    .expect("parse static key");
    let public_key = secret_key.public_key();

    let capabilities = Capability::SIGN_ECDSA
        | Capability::EXPORT_WRAPPED
        | Capability::IMPORT_WRAPPED
        | Capability::EXPORTABLE_UNDER_WRAP;
    let delegated_capabilities = Capability::all();
    let asymmetric_key_id = 207;
    let algorithm = wrap::Algorithm::Aes256Ccm;

    let client = crate::get_hsm_client();
    let _ = client.delete_object(asymmetric_key_id, object::Type::AsymmetricKey);

    let _key_id = client
        .put_asymmetric_key(
            asymmetric_key_id,
            TEST_KEY_LABEL.into(),
            TEST_DOMAINS,
            capabilities,
            asymmetric::Algorithm::EcP384,
            secret_key.to_bytes(),
        )
        .unwrap_or_else(|err| panic!("error putting asymmetric key: {err}"));

    let public = client
        .get_public_key(asymmetric_key_id)
        .expect("read public key");
    let public = public
        .ecdsa::<p384::NistP384>()
        .expect("ecdsa public key expected");

    assert_eq!(
        p384::PublicKey::try_from(&public).expect("valid point"),
        public_key
    );

    clear_test_key_slot(&client, object::Type::WrapKey);
    let wrap_key = wrap::Key::from_bytes(
        TEST_KEY_ID,
        &hex!("0000000000000000000000000000000000000000000000000000000000000000"),
    )
    .unwrap();
    let _key_id = client
        .put_wrap_key(
            TEST_KEY_ID,
            TEST_KEY_LABEL.into(),
            TEST_DOMAINS,
            capabilities,
            delegated_capabilities,
            algorithm,
            &hex!("0000000000000000000000000000000000000000000000000000000000000000"),
        )
        .unwrap_or_else(|err| panic!("error generating wrap key: {err}"));

    let message = client
        .export_wrapped(TEST_KEY_ID, object::Type::AsymmetricKey, asymmetric_key_id)
        .expect("Export key");

    let plaintext = message
        .decrypt(&wrap_key)
        .expect("failed to decrypt the wrapped key");

    assert_eq!(plaintext.object_info.length, 144);
}
