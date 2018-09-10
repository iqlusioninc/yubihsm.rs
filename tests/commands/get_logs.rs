use yubihsm;

/// Get audit log
#[test]
fn get_audit_logs_test() {
    let mut session = create_session!();

    // TODO: test audit logging functionality
    yubihsm::get_audit_logs(&mut session)
        .unwrap_or_else(|err| panic!("error getting logs: {}", err));
}
