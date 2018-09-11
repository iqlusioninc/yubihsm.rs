use yubihsm::{self, AuditOption, CommandType};

/// Set the auditing options for a particular command
#[test]
fn command_audit_options_test() {
    let mut session = create_session!();
    let command_type = CommandType::Echo;

    for audit_option in &[AuditOption::On, AuditOption::Off] {
        yubihsm::put_command_audit_option(&mut session, command_type, *audit_option)
            .unwrap_or_else(|err| panic!("error setting {:?} audit option: {}", command_type, err));

        let hsm_option = yubihsm::get_command_audit_option(&mut session, command_type)
            .unwrap_or_else(|err| panic!("error getting {:?} audit option: {}", command_type, err));

        assert_eq!(hsm_option, *audit_option);
    }
}

/// Configure the "force audit" option setting
#[test]
fn force_audit_option_test() {
    let mut session = create_session!();

    // Make sure we've consumed the latest log data or else forced auditing
    // will prevent the tests from completing
    let audit_logs = yubihsm::get_audit_logs(&mut session)
        .unwrap_or_else(|err| panic!("error getting audit logs: {}", err));

    if let Some(last_entry) = audit_logs.entries.last() {
        yubihsm::set_log_index(&mut session, last_entry.item)
            .unwrap_or_else(|err| panic!("error setting audit log position: {}", err));
    }

    for audit_option in &[AuditOption::On, AuditOption::Off] {
        yubihsm::put_force_audit_option(&mut session, *audit_option)
            .unwrap_or_else(|err| panic!("error setting force option: {}", err));

        let hsm_option = yubihsm::get_force_audit_option(&mut session)
            .unwrap_or_else(|err| panic!("error getting force option: {}", err));

        assert_eq!(hsm_option, *audit_option);
    }
}
