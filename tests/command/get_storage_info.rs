/// Get stats about currently free storage
#[test]
fn get_storage_info_test() {
    let client = crate::get_hsm_client();

    let response = client
        .get_storage_info()
        .unwrap_or_else(|err| panic!("error getting storage status: {}", err));

    // TODO: these will probably have to change if Yubico releases new models
    assert_eq!(response.total_records, 256);
    assert_eq!(response.total_pages, 1024);
    assert_eq!(response.page_size, 126);
}
