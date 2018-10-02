/// Blink the LED on the YubiHSM for 2 seconds
#[test]
fn blink_test() {
    let mut client = ::get_hsm_client();
    client.blink(2).unwrap();
}
