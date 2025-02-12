//! Elliptic Curve Digital Signature Algorithm (ECDSA) tests

use ::ecdsa::{
    der,
    elliptic_curve::{
        point::PointCompression,
        sec1::{self, FromEncodedPoint, ToEncodedPoint},
        AffinePoint, CurveArithmetic, FieldBytesSize,
    },
    signature::{Keypair, Verifier},
    EcdsaCurve,
};
use spki::SubjectPublicKeyInfoOwned;
use std::{str::FromStr, time::Duration};
use x509_cert::{
    builder::{profile::cabf, Builder, CertificateBuilder},
    name::Name,
    serial_number::SerialNumber,
    time::Validity,
};
use yubihsm::{
    asymmetric::signature::Signer as _,
    ecdsa::{self, algorithm::CurveAlgorithm, NistP256},
    object, Client,
};

#[cfg(feature = "secp256k1")]
use {
    ::ecdsa::signature::{digest::Digest, DigestSigner, DigestVerifier},
    yubihsm::ecdsa::Secp256k1,
};

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
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
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
    let verify_key = p256::ecdsa::VerifyingKey::from_encoded_point(signer.public_key()).unwrap();

    let signature: ecdsa::Signature<NistP256> = signer.sign(TEST_MESSAGE);
    assert!(verify_key.verify(TEST_MESSAGE, &signature).is_ok());
}

#[cfg(feature = "secp256k1")]
#[test]
fn ecdsa_secp256k1_sign_test() {
    let signer = create_signer::<Secp256k1>(202);
    let verify_key = k256::ecdsa::VerifyingKey::from_encoded_point(signer.public_key()).unwrap();

    let signature: ecdsa::Signature<Secp256k1> = signer.sign(TEST_MESSAGE);
    assert!(verify_key.verify(TEST_MESSAGE, &signature).is_ok());
}

#[cfg(feature = "secp256k1")]
#[test]
fn ecdsa_secp256k1_sign_recover_test() {
    use k256::{ecdsa::VerifyingKey, PublicKey};

    let signer = create_signer::<Secp256k1>(203);
    let verify_key = VerifyingKey::from_encoded_point(signer.public_key()).unwrap();

    let digest = sha2::Sha256::new_with_prefix(TEST_MESSAGE);

    let (signature, recovery_id) = signer.try_sign_digest(digest.clone()).unwrap();

    assert!(verify_key.verify(TEST_MESSAGE, &signature).is_ok());

    let recovered_key =
        VerifyingKey::recover_from_digest(digest.clone(), &signature, recovery_id).unwrap();
    recovered_key.verify_digest(digest, &signature).unwrap();

    let recovered_pk = PublicKey::from(recovered_key);
    let signer_pk = PublicKey::from_encoded_point(signer.public_key()).unwrap();
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
