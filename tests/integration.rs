//! Integration tests (using live YubiHSM 2 or MockHsm)

use lazy_static::lazy_static;
use std::sync::{Mutex, MutexGuard};
use yubihsm::{asymmetric, device, object, Capability, Client, Connector, Domain};

/// Integration tests for individual YubiHSM 2 commands
mod command;

/// ECDSA tests
mod ecdsa;

/// Ed25519 tests
mod ed25519;

/// Cryptographic test vectors taken from standards documents
mod test_vectors;

/// Key ID to use for testing keygen/signing
const TEST_KEY_ID: object::Id = 100;

/// Key ID to use as a keywrapping subject
const TEST_EXPORTED_KEY_ID: object::Id = 101;

/// Label to use for the test key
const TEST_KEY_LABEL: &str = "yubihsm.rs test key";

/// Label for the default auth key
const DEFAULT_AUTHENTICATION_KEY_LABEL: &str = "DEFAULT AUTHKEY CHANGE THIS ASAP";

/// Label to use for the exported test
const TEST_EXPORTED_KEY_LABEL: &str = "yubihsm.rs exported test key";

/// Domain to use for all tests
const TEST_DOMAINS: Domain = Domain::DOM1;

/// Message to sign when performing tests
const TEST_MESSAGE: &[u8] = b"The YubiHSM 2 is a simple, affordable, and secure HSM solution";

/// Size of a NIST P-256 public key
pub const EC_P256_PUBLIC_KEY_SIZE: usize = 64;

lazy_static! {
    static ref HSM_CONNECTOR: Connector = create_hsm_connector();
}

lazy_static! {
    static ref HSM_CLIENT: Mutex<Client> =
        { Mutex::new(Client::open(HSM_CONNECTOR.clone(), Default::default(), true).unwrap()) };
}

/// Create a `yubihsm::Client` to run the test suite against
pub fn get_hsm_client() -> MutexGuard<'static, Client> {
    HSM_CLIENT.lock().unwrap()
}

/// Create a `yubihsm::Connector` for accessing the HSM
///
/// Connector is selected by preference based on cargo features.
/// The preference order is:
///
/// 1. `mockhsm`
/// 2. `usb`
/// 3. `http`
///
/// Panics if none of the above features are enabled
#[allow(unreachable_code)]
pub fn create_hsm_connector() -> Connector {
    // MockHSM has highest priority when testing
    #[cfg(feature = "mockhsm")]
    return create_mockhsm_connector();

    // USB has second highest priority when testing
    #[cfg(feature = "usb")]
    return create_usb_connector();

    // HTTP has lowest priority when testing
    #[cfg(feature = "http")]
    return create_http_connector();

    panic!(
        "No connector features enabled! Enable one of these cargo features: \
         http, usb, mockhsm"
    );
}

/// Connect to the HSM via HTTP using `yubihsm-connector`
#[cfg(feature = "http")]
pub fn create_http_connector() -> Connector {
    Connector::http(&Default::default())
}

/// Connect to the HSM via USB
#[cfg(feature = "usb")]
pub fn create_usb_connector() -> Connector {
    Connector::usb(&Default::default())
}

/// Create a mock HSM for testing in situations where a hardware device is
/// unavailable/impractical (e.g. CI)
#[cfg(feature = "mockhsm")]
pub fn create_mockhsm_connector() -> Connector {
    Connector::mockhsm()
}

/// Delete the key in the test key slot (if it exists, otherwise do nothing)
pub fn clear_test_key_slot(client: &Client, object_type: object::Type) {
    println!("clearing test key slot: {:?} {}", object_type, TEST_KEY_ID);

    // Delete the key in TEST_KEY_ID slot it exists (we use it for testing)
    if let Err(e) = client.delete_object(TEST_KEY_ID, object_type) {
        // Ignore errors for nonexistent objects. We're here to make sure the
        // slot is clear, so it's irrelevant if there was no obj to begin with
        if e.device_error() != Some(device::ErrorKind::ObjectNotFound) {
            panic!("error clearing test key: {}", e);
        }
    }

    // Ensure the object does not exist
    match client.get_object_info(TEST_KEY_ID, object_type) {
        Ok(obj) => panic!("expected test key to be deleted! {:?}", obj),
        Err(e) => {
            if e.device_error() != Some(device::ErrorKind::ObjectNotFound) {
                panic!("error ensuring test key slot is clear: {}", e);
            }
        }
    }
}

/// Create a public key for use in a test
pub fn generate_asymmetric_key(
    client: &Client,
    algorithm: asymmetric::Algorithm,
    capabilities: Capability,
) {
    clear_test_key_slot(client, object::Type::AsymmetricKey);

    match client.generate_asymmetric_key(
        TEST_KEY_ID,
        TEST_KEY_LABEL.into(),
        TEST_DOMAINS,
        capabilities,
        algorithm,
    ) {
        Ok(key_id) => assert_eq!(key_id, TEST_KEY_ID),
        Err(e) => panic!("error generating asymmetric key: {}", e),
    }
}

/// Put an asymmetric private key into the HSM
pub fn put_asymmetric_key<T: Into<Vec<u8>>>(
    client: &Client,
    algorithm: asymmetric::Algorithm,
    capabilities: Capability,
    data: T,
) {
    clear_test_key_slot(client, object::Type::AsymmetricKey);

    let key_id = client
        .put_asymmetric_key(
            TEST_KEY_ID,
            TEST_KEY_LABEL.into(),
            TEST_DOMAINS,
            capabilities,
            algorithm,
            data,
        )
        .unwrap_or_else(|err| panic!("error putting asymmetric key: {}", err));

    assert_eq!(key_id, TEST_KEY_ID);
}
