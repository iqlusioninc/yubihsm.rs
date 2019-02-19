//! (Partial) support for audit logging within the MockHsm
//!
//! No logging is performed and these settings are not yet enforced

use crate::{audit::*, command, serialization::serialize};
use std::collections::BTreeMap;

/// Default per-command auditing options
pub const DEFAULT_COMMAND_AUDIT_OPTIONS: &[AuditCommand] = &[
    AuditCommand(command::Code::Echo, AuditOption::Off),
    AuditCommand(command::Code::CreateSession, AuditOption::On),
    AuditCommand(command::Code::AuthenticateSession, AuditOption::On),
    AuditCommand(command::Code::SessionMessage, AuditOption::Off),
    AuditCommand(command::Code::DeviceInfo, AuditOption::Off),
    AuditCommand(command::Code::Bsl, AuditOption::Off),
    AuditCommand(command::Code::Command9, AuditOption::Off),
    AuditCommand(command::Code::ResetDevice, AuditOption::On),
    AuditCommand(command::Code::CloseSession, AuditOption::On),
    AuditCommand(command::Code::GetStorageInfo, AuditOption::On),
    AuditCommand(command::Code::PutOpaqueObject, AuditOption::On),
    AuditCommand(command::Code::GetOpaqueObject, AuditOption::On),
    AuditCommand(command::Code::PutAuthenticationKey, AuditOption::On),
    AuditCommand(command::Code::PutAsymmetricKey, AuditOption::On),
    AuditCommand(command::Code::GenerateAsymmetricKey, AuditOption::On),
    AuditCommand(command::Code::SignPkcs1, AuditOption::On),
    AuditCommand(command::Code::SignPss, AuditOption::On),
    AuditCommand(command::Code::SignEcdsa, AuditOption::On),
    AuditCommand(command::Code::ListObjects, AuditOption::On),
    AuditCommand(command::Code::DecryptPkcs1, AuditOption::On),
    AuditCommand(command::Code::DeriveEcdh, AuditOption::On),
    AuditCommand(command::Code::ExportWrapped, AuditOption::On),
    AuditCommand(command::Code::ImportWrapped, AuditOption::On),
    AuditCommand(command::Code::PutWrapKey, AuditOption::On),
    AuditCommand(command::Code::GetLogEntries, AuditOption::Off),
    AuditCommand(command::Code::SetLogIndex, AuditOption::On),
    AuditCommand(command::Code::GetObjectInfo, AuditOption::On),
    AuditCommand(command::Code::SetOption, AuditOption::On),
    AuditCommand(command::Code::GetOption, AuditOption::On),
    AuditCommand(command::Code::GetPseudoRandom, AuditOption::On),
    AuditCommand(command::Code::PutHmacKey, AuditOption::On),
    AuditCommand(command::Code::SignHmac, AuditOption::On),
    AuditCommand(command::Code::GetPublicKey, AuditOption::On),
    AuditCommand(command::Code::DeleteObject, AuditOption::On),
    AuditCommand(command::Code::DecryptOaep, AuditOption::On),
    AuditCommand(command::Code::GenerateHmacKey, AuditOption::On),
    AuditCommand(command::Code::GenerateWrapKey, AuditOption::On),
    AuditCommand(command::Code::VerifyHmac, AuditOption::On),
    AuditCommand(command::Code::SignSshCertificate, AuditOption::On),
    AuditCommand(command::Code::PutTemplate, AuditOption::On),
    AuditCommand(command::Code::GetTemplate, AuditOption::On),
    AuditCommand(command::Code::DecryptOtp, AuditOption::On),
    AuditCommand(command::Code::CreateOtpAead, AuditOption::On),
    AuditCommand(command::Code::RandomizeOtpAead, AuditOption::On),
    AuditCommand(command::Code::RewrapOtpAead, AuditOption::On),
    AuditCommand(command::Code::SignAttestationCertificate, AuditOption::On),
    AuditCommand(command::Code::PutOtpAead, AuditOption::On),
    AuditCommand(command::Code::GenerateOtpAead, AuditOption::On),
    AuditCommand(command::Code::WrapData, AuditOption::On),
    AuditCommand(command::Code::UnwrapData, AuditOption::On),
    AuditCommand(command::Code::SignEddsa, AuditOption::On),
    AuditCommand(command::Code::BlinkDevice, AuditOption::On),
];

/// Per-command auditing settings
#[derive(Debug)]
pub struct CommandAuditOptions(BTreeMap<command::Code, AuditOption>);

impl CommandAuditOptions {
    /// Serialize these audit options for use as a `GetObjects` response
    pub fn serialize(&self) -> Vec<u8> {
        let audit_command: Vec<_> = self
            .0
            .iter()
            .map(|(cmd, opt)| AuditCommand(*cmd, *opt))
            .collect();

        serialize(&audit_command).unwrap()
    }

    /// Change a setting for a particular command
    pub fn put(&mut self, command_type: command::Code, audit_option: AuditOption) {
        self.0.insert(command_type, audit_option);
    }
}

impl Default for CommandAuditOptions {
    fn default() -> Self {
        let mut result = BTreeMap::new();

        for audit_command in DEFAULT_COMMAND_AUDIT_OPTIONS {
            result.insert(audit_command.command_type(), audit_command.audit_option());
        }

        CommandAuditOptions(result)
    }
}
