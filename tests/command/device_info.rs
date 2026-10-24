/// Get device information
#[test]
fn device_info_test() {
    let client = crate::get_hsm_client();

    let device_info = client
        .device_info()
        .unwrap_or_else(|err| panic!("error getting device info: {err}"));

    // This should always be 2. The minor and patch versions will vary
    // depending on the specific YubiHSM 2 model.
    assert_eq!(device_info.major_version, 2);

    #[cfg(feature = "mockhsm")]
    assert_eq!(
        device_info.algorithms.iter().any(|algorithm| matches!(
            algorithm,
            yubihsm::algorithm::Algorithm::Asymmetric(algorithm) if algorithm.is_rsa()
        )),
        cfg!(feature = "rsa"),
        "MockHSM should only advertise RSA when software RSA support is enabled"
    );
}
