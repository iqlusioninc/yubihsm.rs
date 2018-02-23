extern crate yubihsm_client;

use std::thread;

use yubihsm_client::{Connector, KeyId, SessionId};
#[cfg(feature = "mockhsm")]
use yubihsm_client::mockhsm::MockHSM;

// TODO: pick an open port automatically
const MOCKHSM_ADDR: &str = "127.0.0.1:54321";

/// Default auth key ID slot
const DEFAULT_AUTH_KEY_ID: KeyId = 1;

/// Default password
const DEFAULT_PASSWORD: &str = "password";

#[cfg(feature = "mockhsm")]
fn start_mockhsm(num_requests: usize) -> thread::JoinHandle<()> {
    thread::spawn(move || MockHSM::new(MOCKHSM_ADDR).unwrap().run(num_requests))
}

#[cfg(feature = "mockhsm")]
#[test]
fn mockhsm_integration_test() {
    let num_requests = 3;
    let mockhsm_thread = start_mockhsm(num_requests);

    let conn = Connector::open(&format!("http://{}", MOCKHSM_ADDR))
        .unwrap_or_else(|err| panic!("cannot open connection to yubihsm-connector: {:?}", err));

    let session = conn.create_session_from_password(DEFAULT_AUTH_KEY_ID, DEFAULT_PASSWORD)
        .unwrap_or_else(|err| panic!("error creating session: {:?}", err));

    assert_eq!(session.id(), SessionId::new(0).unwrap());

    mockhsm_thread.join().unwrap();
}

#[cfg(not(feature = "mockhsm"))]
#[test]
fn panic_unless_mockhsm_is_available() {
    panic!("run tests with 'cargo test --features=mockhsm'")
}
