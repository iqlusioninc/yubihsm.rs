/// Get device information
#[test]
fn device_info_test() {
    let mut client = crate::get_hsm_client();

    let device_info = client
        .device_info()
        .unwrap_or_else(|err| panic!("error getting device info: {}", err));

    assert_eq!(device_info.major_version, 2);
    assert_eq!(device_info.minor_version, 0);
    assert_eq!(device_info.build_version, 0);
}
