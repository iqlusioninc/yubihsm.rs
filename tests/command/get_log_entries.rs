/// Get audit log
#[test]
fn get_audit_logs_test() {
    let client = crate::get_hsm_client();

    // TODO: test audit logging functionality
    client
        .get_log_entries()
        .unwrap_or_else(|err| panic!("error getting logs: {}", err));
}
