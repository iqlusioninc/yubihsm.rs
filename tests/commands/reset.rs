use yubihsm;

/// Reset the YubiHSM2 to a factory default state
#[test]
fn reset_test() {
    let session = create_session!();
    yubihsm::reset(session).unwrap();
}
