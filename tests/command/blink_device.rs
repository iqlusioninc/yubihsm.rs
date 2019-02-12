/// Blink the LED on the YubiHSM for 2 seconds
#[test]
fn blink_device_test() {
    let mut client = crate::get_hsm_client();
    client.blink_device(2).unwrap();
}
