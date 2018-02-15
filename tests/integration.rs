extern crate yubihsm_client;

use std::thread;

use yubihsm_client::{Connector, KeyID};
use yubihsm_client::mockhsm::MockHSM;

// TODO: pick an open port automatically
const MOCKHSM_ADDR: &str = "127.0.0.1:54321";

/// Default auth key ID slot
const DEFAULT_AUTH_KEY_ID: KeyID = 1;

/// Default password
const DEFAULT_PASSWORD: &str = "password";

fn start_mockhsm(num_requests: usize) -> thread::JoinHandle<()> {
    thread::spawn(move || MockHSM::new(MOCKHSM_ADDR).unwrap().run(num_requests))
}

#[test]
fn mockhsm_integration_test() {
    let mockhsm_thread = start_mockhsm(2);

    let conn = Connector::open(&format!("http://{}", MOCKHSM_ADDR))
        .unwrap_or_else(|err| panic!("cannot open connection to yubihsm-connector: {:?}", err));

    let session = conn.create_session_from_password(DEFAULT_AUTH_KEY_ID, DEFAULT_PASSWORD)
        .unwrap_or_else(|err| panic!("error creating session: {:?}", err));

    assert_eq!(session.id().0, 0);

    mockhsm_thread.join().unwrap();
}
