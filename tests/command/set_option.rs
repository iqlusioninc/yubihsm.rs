use yubihsm::{command, AuditOption};

/// Set the auditing options for a particular command
#[test]
fn command_audit_options_test() {
    let client = crate::get_hsm_client();
    let command_type = command::Code::Echo;

    for audit_option in &[AuditOption::On, AuditOption::Off] {
        client
            .set_command_audit_option(command_type, *audit_option)
            .unwrap_or_else(|err| panic!("error setting {:?} audit option: {}", command_type, err));

        let hsm_option = client
            .get_command_audit_option(command_type)
            .unwrap_or_else(|err| panic!("error getting {:?} audit option: {}", command_type, err));

        assert_eq!(hsm_option, *audit_option);
    }
}

/// Configure the "force audit" option setting
// TODO(tarcieri): clear audit log when tests start. See notes on PR#185
#[test]
#[ignore]
fn force_audit_option_test() {
    let client = crate::get_hsm_client();

    // Make sure we've consumed the latest log data or else forced auditing
    // will prevent the tests from completing
    let audit_logs = client
        .get_log_entries()
        .unwrap_or_else(|err| panic!("error getting audit logs: {}", err));

    if let Some(last_entry) = audit_logs.entries.last() {
        client
            .set_log_index(last_entry.item)
            .unwrap_or_else(|err| panic!("error setting audit log position: {}", err));
    }

    for audit_option in &[AuditOption::On, AuditOption::Off] {
        client
            .set_force_audit_option(*audit_option)
            .unwrap_or_else(|err| panic!("error setting force option: {}", err));

        let hsm_option = client
            .get_force_audit_option()
            .unwrap_or_else(|err| panic!("error getting force option: {}", err));

        assert_eq!(hsm_option, *audit_option);
    }
}
