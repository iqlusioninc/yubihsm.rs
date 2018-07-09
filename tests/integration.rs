/// Integration tests (using live YubiHSM2 or MockHSM)

#[cfg(not(feature = "mockhsm"))]
#[macro_use]
extern crate lazy_static;
extern crate sha2;
extern crate yubihsm;
use yubihsm::{
    AsymmetricAlgorithm, Capability, Domain, ObjectId, ObjectOrigin, ObjectType, Session,
};

#[cfg(not(feature = "mockhsm"))]
use yubihsm::HttpConnector;

#[cfg(feature = "mockhsm")]
use yubihsm::mockhsm::MockHSM;

#[cfg(feature = "ring")]
extern crate ring;
#[cfg(feature = "ring")]
extern crate untrusted;

/// Default auth key ID slot
const DEFAULT_AUTH_KEY_ID: ObjectId = 1;

/// Default password
const DEFAULT_PASSWORD: &str = "password";

/// Key ID to use for testing keygen/signing
const TEST_KEY_ID: ObjectId = 100;

/// Label to use for the test key
const TEST_KEY_LABEL: &str = "yubihsm.rs test key";

/// Domain to use for all tests
const TEST_DOMAINS: Domain = Domain::DOM1;

/// Message to sign when performing tests
const TEST_MESSAGE: &[u8] = b"The YubiHSM2 is a simple, affordable, and secure HSM solution";

/// Size of a NIST P-256 public key
pub const EC_P256_PUBLIC_KEY_SIZE: usize = 64;

/// Signature test vector
struct SignatureTestVector {
    /// Secret key (i.e. seed)
    pub sk: &'static [u8],

    /// Public key in compressed Edwards-y form
    pub pk: &'static [u8],

    /// Message to be signed
    pub msg: &'static [u8],

    /// Expected signature
    pub sig: &'static [u8],
}

/// Ed25519 test vectors (from RFC 8032, converted to Rust bytestring literals)
const ED25519_TEST_VECTORS: &[SignatureTestVector] = &[
    SignatureTestVector {
        sk: b"\x9D\x61\xB1\x9D\xEF\xFD\x5A\x60\xBA\x84\x4A\xF4\x92\xEC\x2C\xC4\x44\x49\xC5\x69\x7B\x32\x69\x19\x70\x3B\xAC\x03\x1C\xAE\x7F\x60",
        pk: b"\xD7\x5A\x98\x01\x82\xB1\x0A\xB7\xD5\x4B\xFE\xD3\xC9\x64\x07\x3A\x0E\xE1\x72\xF3\xDA\xA6\x23\x25\xAF\x02\x1A\x68\xF7\x07\x51\x1A",
        msg: b"",
        sig: b"\xE5\x56\x43\x00\xC3\x60\xAC\x72\x90\x86\xE2\xCC\x80\x6E\x82\x8A\x84\x87\x7F\x1E\xB8\xE5\xD9\x74\xD8\x73\xE0\x65\x22\x49\x01\x55\x5F\xB8\x82\x15\x90\xA3\x3B\xAC\xC6\x1E\x39\x70\x1C\xF9\xB4\x6B\xD2\x5B\xF5\xF0\x59\x5B\xBE\x24\x65\x51\x41\x43\x8E\x7A\x10\x0B",
    },
    SignatureTestVector {
        sk: b"\x4C\xCD\x08\x9B\x28\xFF\x96\xDA\x9D\xB6\xC3\x46\xEC\x11\x4E\x0F\x5B\x8A\x31\x9F\x35\xAB\xA6\x24\xDA\x8C\xF6\xED\x4F\xB8\xA6\xFB",
        pk: b"\x3D\x40\x17\xC3\xE8\x43\x89\x5A\x92\xB7\x0A\xA7\x4D\x1B\x7E\xBC\x9C\x98\x2C\xCF\x2E\xC4\x96\x8C\xC0\xCD\x55\xF1\x2A\xF4\x66\x0C",
        msg: b"\x72",
        sig: b"\x92\xA0\x09\xA9\xF0\xD4\xCA\xB8\x72\x0E\x82\x0B\x5F\x64\x25\x40\xA2\xB2\x7B\x54\x16\x50\x3F\x8F\xB3\x76\x22\x23\xEB\xDB\x69\xDA\x08\x5A\xC1\xE4\x3E\x15\x99\x6E\x45\x8F\x36\x13\xD0\xF1\x1D\x8C\x38\x7B\x2E\xAE\xB4\x30\x2A\xEE\xB0\x0D\x29\x16\x12\xBB\x0C\x00",
    },
    SignatureTestVector {
        sk: b"\xC5\xAA\x8D\xF4\x3F\x9F\x83\x7B\xED\xB7\x44\x2F\x31\xDC\xB7\xB1\x66\xD3\x85\x35\x07\x6F\x09\x4B\x85\xCE\x3A\x2E\x0B\x44\x58\xF7",
        pk: b"\xFC\x51\xCD\x8E\x62\x18\xA1\xA3\x8D\xA4\x7E\xD0\x02\x30\xF0\x58\x08\x16\xED\x13\xBA\x33\x03\xAC\x5D\xEB\x91\x15\x48\x90\x80\x25",
        msg: b"\xAF\x82",
        sig: b"\x62\x91\xD6\x57\xDE\xEC\x24\x02\x48\x27\xE6\x9C\x3A\xBE\x01\xA3\x0C\xE5\x48\xA2\x84\x74\x3A\x44\x5E\x36\x80\xD7\xDB\x5A\xC3\xAC\x18\xFF\x9B\x53\x8D\x16\xF2\x90\xAE\x67\xF7\x60\x98\x4D\xC6\x59\x4A\x7C\x15\xE9\x71\x6E\xD2\x8D\xC0\x27\xBE\xCE\xEA\x1E\xC4\x0A",
    }
];

#[cfg(not(feature = "mockhsm"))]
type TestSession = Session<HttpConnector>;

#[cfg(feature = "mockhsm")]
type TestSession = Session<MockHSM>;

#[cfg(not(feature = "mockhsm"))]
lazy_static! {
    static ref SESSION: ::std::sync::Mutex<TestSession> = {
        let session = Session::create_from_password(
            Default::default(),
            DEFAULT_AUTH_KEY_ID,
            DEFAULT_PASSWORD,
            true,
        ).unwrap_or_else(|err| panic!("error creating session: {}", err));

        ::std::sync::Mutex::new(session)
    };
}

/// Perform a live integration test against yubihsm-connector and a real `YubiHSM2`
#[cfg(not(feature = "mockhsm"))]
macro_rules! create_session {
    () => {
        SESSION.lock().unwrap()
    };
}

/// Perform an integration test against the MockHSM (useful for CI)
#[cfg(feature = "mockhsm")]
macro_rules! create_session {
    () => {
        MockHSM::create_session(DEFAULT_AUTH_KEY_ID, DEFAULT_PASSWORD)
            .unwrap_or_else(|err| panic!("error creating MockHSM session: {}", err))
    };
}

/// Delete the key in the test key slot (if it exists, otherwise do nothing)
fn clear_test_key_slot(session: &mut TestSession) {
    // Delete the key in TEST_KEY_ID slot it exists (we use it for testing)
    // Ignore errors since the object may not exist yet
    let _ = yubihsm::delete_object(session, TEST_KEY_ID, ObjectType::Asymmetric);

    // Ensure the object does not already exist
    assert!(yubihsm::get_object_info(session, TEST_KEY_ID, ObjectType::Asymmetric).is_err());
}

/// Create a public key for use in a test
fn generate_asymmetric_key(
    session: &mut TestSession,
    algorithm: AsymmetricAlgorithm,
    capabilities: Capability,
) {
    clear_test_key_slot(session);

    let response = yubihsm::generate_asymmetric_key(
        session,
        TEST_KEY_ID,
        TEST_KEY_LABEL.into(),
        TEST_DOMAINS,
        capabilities,
        algorithm,
    ).unwrap_or_else(|err| panic!("error generating asymmetric key: {}", err));

    assert_eq!(response.key_id, TEST_KEY_ID);
}

/// Put an asymmetric private key into the HSM
fn put_asymmetric_key<T: Into<Vec<u8>>>(
    session: &mut TestSession,
    algorithm: AsymmetricAlgorithm,
    capabilities: Capability,
    data: T,
) {
    clear_test_key_slot(session);

    let response = yubihsm::put_asymmetric_key(
        session,
        TEST_KEY_ID,
        TEST_KEY_LABEL.into(),
        TEST_DOMAINS,
        capabilities,
        algorithm,
        data,
    ).unwrap_or_else(|err| panic!("error putting asymmetric key: {}", err));

    assert_eq!(response.key_id, TEST_KEY_ID);
}

/// Generate an attestation about a key in the HSM
#[cfg(not(feature = "mockhsm"))]
#[test]
fn attest_asymmetric_test() {
    let mut session = create_session!();

    generate_asymmetric_key(
        &mut session,
        AsymmetricAlgorithm::EC_P256,
        Capability::ASYMMETRIC_SIGN_ECDSA,
    );

    let certificate = yubihsm::attest_asymmetric(&mut session, TEST_KEY_ID, None)
        .unwrap_or_else(|err| panic!("error getting attestation certificate: {}", err));

    // TODO: more tests, e.g. test that the certificate validates
    assert!(certificate.len() > EC_P256_PUBLIC_KEY_SIZE);
}

/// Blink the LED on the YubiHSM for 2 seconds
#[test]
fn blink_test() {
    let mut session = create_session!();
    yubihsm::blink(&mut session, 2).unwrap();
}

/// Delete an object in the YubiHSM2
#[test]
fn delete_object_test() {
    let mut session = create_session!();

    generate_asymmetric_key(
        &mut session,
        AsymmetricAlgorithm::EC_ED25519,
        Capability::ASYMMETRIC_SIGN_EDDSA,
    );

    // The first request to delete should succeed because the object exists
    assert!(yubihsm::delete_object(&mut session, TEST_KEY_ID, ObjectType::Asymmetric).is_ok());

    // The second request to delete should fail because it's already deleted
    assert!(yubihsm::delete_object(&mut session, TEST_KEY_ID, ObjectType::Asymmetric).is_err());
}

/// Get device information
#[test]
fn device_info_test() {
    let mut session = create_session!();

    let device_info = yubihsm::device_info(&mut session)
        .unwrap_or_else(|err| panic!("error getting device info: {}", err));

    assert_eq!(device_info.major_version, 2);
    assert_eq!(device_info.minor_version, 0);
    assert_eq!(device_info.build_version, 0);
}

/// Send a simple echo request
#[test]
fn echo_test() {
    let mut session = create_session!();

    let echo_response = yubihsm::echo(&mut session, TEST_MESSAGE)
        .unwrap_or_else(|err| panic!("error sending echo: {}", err));

    assert_eq!(TEST_MESSAGE, echo_response.as_ref());
}

/// Generate an Ed25519 key
#[test]
fn generate_asymmetric_key_test() {
    let mut session = create_session!();
    let algorithm = AsymmetricAlgorithm::EC_ED25519;
    let capabilities = Capability::ASYMMETRIC_SIGN_EDDSA;

    generate_asymmetric_key(&mut session, algorithm, capabilities);

    let object_info = yubihsm::get_object_info(&mut session, TEST_KEY_ID, ObjectType::Asymmetric)
        .unwrap_or_else(|err| panic!("error getting object info: {}", err));

    assert_eq!(object_info.capabilities, capabilities);
    assert_eq!(object_info.id, TEST_KEY_ID);
    assert_eq!(object_info.domains, TEST_DOMAINS);
    assert_eq!(object_info.object_type, ObjectType::Asymmetric);
    assert_eq!(object_info.algorithm, algorithm.into());
    assert_eq!(object_info.origin, ObjectOrigin::Generated);
    assert_eq!(&object_info.label.to_string().unwrap(), TEST_KEY_LABEL);
}

/// Get audit log
#[test]
fn get_logs_test() {
    let mut session = create_session!();

    let response =
        yubihsm::get_logs(&mut session).unwrap_or_else(|err| panic!("error getting logs: {}", err));

    assert_eq!(response.num_entries as usize, response.entries.len());
}

/// List the objects in the YubiHSM2
#[test]
fn list_objects_test() {
    let mut session = create_session!();

    generate_asymmetric_key(
        &mut session,
        AsymmetricAlgorithm::EC_ED25519,
        Capability::ASYMMETRIC_SIGN_EDDSA,
    );

    let objects = yubihsm::list_objects(&mut session)
        .unwrap_or_else(|err| panic!("error listing objects: {}", err));

    // Check type of the Ed25519 we created in generate_asymmetric_key_test()
    let object = objects.iter().find(|i| i.id == TEST_KEY_ID).unwrap();

    assert_eq!(object.object_type, ObjectType::Asymmetric)
}

/// Put an Ed25519 key
#[test]
fn put_asymmetric_key_test() {
    let mut session = create_session!();
    let algorithm = AsymmetricAlgorithm::EC_ED25519;
    let capabilities = Capability::ASYMMETRIC_SIGN_EDDSA;
    let example_private_key = ED25519_TEST_VECTORS[0].sk;

    put_asymmetric_key(&mut session, algorithm, capabilities, example_private_key);

    let object_info = yubihsm::get_object_info(&mut session, TEST_KEY_ID, ObjectType::Asymmetric)
        .unwrap_or_else(|err| panic!("error getting object info: {}", err));

    assert_eq!(object_info.capabilities, capabilities);
    assert_eq!(object_info.id, TEST_KEY_ID);
    assert_eq!(object_info.domains, TEST_DOMAINS);
    assert_eq!(object_info.object_type, ObjectType::Asymmetric);
    assert_eq!(object_info.algorithm, algorithm.into());
    assert_eq!(object_info.origin, ObjectOrigin::Imported);
    assert_eq!(&object_info.label.to_string().unwrap(), TEST_KEY_LABEL);
}

/// Test ECDSA signatures (using NIST P-256)
#[cfg(feature = "ring")]
#[test]
fn sign_ecdsa_test() {
    let mut session = create_session!();

    generate_asymmetric_key(
        &mut session,
        AsymmetricAlgorithm::EC_P256,
        Capability::ASYMMETRIC_SIGN_ECDSA,
    );

    let pubkey_response = yubihsm::get_pubkey(&mut session, TEST_KEY_ID)
        .unwrap_or_else(|err| panic!("error getting public key: {}", err));

    assert_eq!(pubkey_response.algorithm, AsymmetricAlgorithm::EC_P256);
    assert_eq!(pubkey_response.bytes.len(), 64);

    let mut pubkey = [0u8; 65];
    pubkey[0] = 0x04; // DER OCTET STRING tag
    pubkey[1..].copy_from_slice(pubkey_response.bytes.as_slice());

    let signature = yubihsm::sign_ecdsa_sha2(&mut session, TEST_KEY_ID, TEST_MESSAGE)
        .unwrap_or_else(|err| panic!("error performing ECDSA signature: {}", err));

    ring::signature::verify(
        &ring::signature::ECDSA_P256_SHA256_ASN1,
        untrusted::Input::from(&pubkey),
        untrusted::Input::from(TEST_MESSAGE),
        untrusted::Input::from(signature.as_ref()),
    ).unwrap();
}

/// Test Ed25519 against RFC 8032 test vectors
#[test]
fn sign_ed25519_test_vectors() {
    let mut session = create_session!();

    for vector in ED25519_TEST_VECTORS {
        put_asymmetric_key(
            &mut session,
            AsymmetricAlgorithm::EC_ED25519,
            Capability::ASYMMETRIC_SIGN_EDDSA,
            vector.sk,
        );

        let pubkey_response = yubihsm::get_pubkey(&mut session, TEST_KEY_ID)
            .unwrap_or_else(|err| panic!("error getting public key: {}", err));

        assert_eq!(pubkey_response.algorithm, AsymmetricAlgorithm::EC_ED25519);
        assert_eq!(pubkey_response.bytes, vector.pk);

        let signature = yubihsm::sign_ed25519(&mut session, TEST_KEY_ID, vector.msg)
            .unwrap_or_else(|err| panic!("error performing Ed25519 signature: {}", err));

        assert_eq!(signature.as_ref(), vector.sig);
    }
}

/// Test Ed25519 signing using a randomly generated HSM key
#[cfg(feature = "ring")]
#[test]
fn sign_ed25519_with_generated_key_test() {
    let mut session = create_session!();

    generate_asymmetric_key(
        &mut session,
        AsymmetricAlgorithm::EC_ED25519,
        Capability::ASYMMETRIC_SIGN_EDDSA,
    );

    let pubkey = yubihsm::get_pubkey(&mut session, TEST_KEY_ID)
        .unwrap_or_else(|err| panic!("error getting public key: {}", err));

    assert_eq!(pubkey.algorithm, AsymmetricAlgorithm::EC_ED25519);

    let signature = yubihsm::sign_ed25519(&mut session, TEST_KEY_ID, TEST_MESSAGE)
        .unwrap_or_else(|err| panic!("error performing Ed25519 signature: {}", err));

    ring::signature::verify(
        &ring::signature::ED25519,
        untrusted::Input::from(pubkey.bytes.as_ref()),
        untrusted::Input::from(TEST_MESSAGE),
        untrusted::Input::from(signature.as_ref()),
    ).unwrap();
}
