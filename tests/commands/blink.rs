use yubihsm;

/// Blink the LED on the YubiHSM for 2 seconds
#[test]
fn blink_test() {
    let mut session = create_session!();
    yubihsm::blink(&mut session, 2).unwrap();
}
