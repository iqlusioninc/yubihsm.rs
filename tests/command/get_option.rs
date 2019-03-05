/// Get the auditing options for all commands
#[test]
fn command_audit_options_test() {
    let client = crate::get_hsm_client();

    let results = client
        .get_commands_audit_options()
        .unwrap_or_else(|err| panic!("error getting force option: {}", err));

    assert!(results.len() > 1);
}

/// Get the "force audit" option setting
#[test]
fn force_audit_option_test() {
    let client = crate::get_hsm_client();

    client
        .get_force_audit_option()
        .unwrap_or_else(|err| panic!("error getting force option: {}", err));
}
