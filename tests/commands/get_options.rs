use yubihsm;

/// Get the auditing options for all commands
#[test]
fn command_audit_options_test() {
    let mut session = create_session!();

    let results = yubihsm::get_all_command_audit_options(&mut session)
        .unwrap_or_else(|err| panic!("error getting force option: {}", err));

    assert!(results.len() > 1);
}

/// Get the "force audit" option setting
#[test]
fn force_audit_option_test() {
    let mut session = create_session!();

    yubihsm::get_force_audit_option(&mut session)
        .unwrap_or_else(|err| panic!("error getting force option: {}", err));
}
