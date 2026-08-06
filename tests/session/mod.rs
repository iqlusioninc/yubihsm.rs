//! Session lifecycle tests

/// Sessions must be released back to the HSM when dropped.
///
/// The device supports a limited number of concurrent sessions (16). Before
/// sessions were closed on `Drop`, repeatedly creating and dropping clients
/// exhausted that pool and further opens failed with `SessionsFull` — see
/// <https://github.com/iqlusioninc/yubihsm.rs/issues/495>.
///
/// The connector is cloned rather than recreated so that every client talks to
/// the *same* HSM and its session pool actually accumulates; with a fresh HSM
/// per iteration this test would pass even with no `Drop` handler at all.
#[test]
fn sessions_are_released_on_drop() {
    let connector = crate::create_hsm_connector();

    for i in 0..40 {
        let client = yubihsm::Client::open(connector.clone(), Default::default(), true)
            .unwrap_or_else(|err| panic!("failed opening client #{i}: {err}"));

        // Exercise the session so it is genuinely established, not just created.
        client
            .device_info()
            .unwrap_or_else(|err| panic!("failed talking to HSM on client #{i}: {err}"));

        drop(client);
    }
}
