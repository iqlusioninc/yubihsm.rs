use yubihsm::Client;

/// Reset the YubiHSM 2 to a factory default state
#[test]
fn reset_test() {
    let client = crate::get_hsm_client();
    client.reset_device().unwrap();
}

#[test]
#[cfg(feature = "mockhsm")]
fn reset_no_auth() {
    use yubihsm::{authentication, Capability, Credentials, Domain};

    use crate::create_mockhsm_connector;

    let authentication_key = authentication::Key::random();

    let client = Client::open(create_mockhsm_connector(), Default::default(), true).unwrap();
    client
        .put_authentication_key(
            2,
            Default::default(),
            Domain::DOM1,
            // this key does NOT have RESET_DEVICE capability
            Capability::empty(),
            Capability::empty(),
            yubihsm::authentication::Algorithm::YubicoAes,
            authentication_key.clone(),
        )
        .unwrap();

    let client = Client::open(
        // reuse the same mock hsm so that the previous key stays in memory
        client.connector().clone(),
        Credentials::new(2, authentication_key),
        true,
    )
    .unwrap();
    assert!(
        client.reset_device().is_err(),
        "resetting device should fail if authentication key doesn't have correct permissions"
    );
}

#[test]
#[cfg(feature = "mockhsm")]
fn reset_with_auth() {
    use yubihsm::{authentication, Capability, Credentials, Domain};

    use crate::create_mockhsm_connector;

    let authentication_key = authentication::Key::random();

    let client = Client::open(create_mockhsm_connector(), Default::default(), true).unwrap();
    client
        .put_authentication_key(
            2,
            Default::default(),
            Domain::DOM1,
            // this key has RESET_DEVICE capability
            Capability::RESET_DEVICE,
            Capability::empty(),
            yubihsm::authentication::Algorithm::YubicoAes,
            authentication_key.clone(),
        )
        .unwrap();

    let client = Client::open(
        // reuse the same mock hsm so that the previous key stays in memory
        client.connector().clone(),
        Credentials::new(2, authentication_key),
        true,
    )
    .unwrap();
    assert!(
        client.reset_device().is_ok(),
        "resetting device should succeed with correct capabilities"
    );
}
