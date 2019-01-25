//! (Partial) support for audit logging within the MockHsm
//!
//! No logging is performed and these settings are not yet enforced

use std::collections::BTreeMap;

use crate::audit::*;
use crate::command::CommandCode;
use crate::serialization::serialize;

/// Default per-command auditing options
pub const DEFAULT_COMMAND_AUDIT_OPTIONS: &[AuditCommand] = &[
    AuditCommand(CommandCode::Echo, AuditOption::Off),
    AuditCommand(CommandCode::CreateSession, AuditOption::On),
    AuditCommand(CommandCode::AuthenticateSession, AuditOption::On),
    AuditCommand(CommandCode::SessionMessage, AuditOption::Off),
    AuditCommand(CommandCode::DeviceInfo, AuditOption::Off),
    AuditCommand(CommandCode::Bsl, AuditOption::Off),
    AuditCommand(CommandCode::Command9, AuditOption::Off),
    AuditCommand(CommandCode::ResetDevice, AuditOption::On),
    AuditCommand(CommandCode::CloseSession, AuditOption::On),
    AuditCommand(CommandCode::GetStorageInfo, AuditOption::On),
    AuditCommand(CommandCode::PutOpaqueObject, AuditOption::On),
    AuditCommand(CommandCode::GetOpaqueObject, AuditOption::On),
    AuditCommand(CommandCode::PutAuthenticationKey, AuditOption::On),
    AuditCommand(CommandCode::PutAsymmetricKey, AuditOption::On),
    AuditCommand(CommandCode::GenerateAsymmetricKey, AuditOption::On),
    AuditCommand(CommandCode::SignPkcs1, AuditOption::On),
    AuditCommand(CommandCode::SignPss, AuditOption::On),
    AuditCommand(CommandCode::SignEcdsa, AuditOption::On),
    AuditCommand(CommandCode::ListObjects, AuditOption::On),
    AuditCommand(CommandCode::DecryptPkcs1, AuditOption::On),
    AuditCommand(CommandCode::DeriveEcdh, AuditOption::On),
    AuditCommand(CommandCode::ExportWrapped, AuditOption::On),
    AuditCommand(CommandCode::ImportWrapped, AuditOption::On),
    AuditCommand(CommandCode::PutWrapKey, AuditOption::On),
    AuditCommand(CommandCode::GetLogEntries, AuditOption::Off),
    AuditCommand(CommandCode::SetLogIndex, AuditOption::On),
    AuditCommand(CommandCode::GetObjectInfo, AuditOption::On),
    AuditCommand(CommandCode::SetOption, AuditOption::On),
    AuditCommand(CommandCode::GetOption, AuditOption::On),
    AuditCommand(CommandCode::GetPseudoRandom, AuditOption::On),
    AuditCommand(CommandCode::PutHmacKey, AuditOption::On),
    AuditCommand(CommandCode::SignHmac, AuditOption::On),
    AuditCommand(CommandCode::GetPublicKey, AuditOption::On),
    AuditCommand(CommandCode::DeleteObject, AuditOption::On),
    AuditCommand(CommandCode::DecryptOaep, AuditOption::On),
    AuditCommand(CommandCode::GenerateHmacKey, AuditOption::On),
    AuditCommand(CommandCode::GenerateWrapKey, AuditOption::On),
    AuditCommand(CommandCode::VerifyHmac, AuditOption::On),
    AuditCommand(CommandCode::SignSshCertificate, AuditOption::On),
    AuditCommand(CommandCode::PutTemplate, AuditOption::On),
    AuditCommand(CommandCode::GetTemplate, AuditOption::On),
    AuditCommand(CommandCode::DecryptOtp, AuditOption::On),
    AuditCommand(CommandCode::CreateOtpAead, AuditOption::On),
    AuditCommand(CommandCode::RandomizeOtpAead, AuditOption::On),
    AuditCommand(CommandCode::RewrapOtpAead, AuditOption::On),
    AuditCommand(CommandCode::SignAttestationCertificate, AuditOption::On),
    AuditCommand(CommandCode::PutOtpAead, AuditOption::On),
    AuditCommand(CommandCode::GenerateOtpAead, AuditOption::On),
    AuditCommand(CommandCode::WrapData, AuditOption::On),
    AuditCommand(CommandCode::UnwrapData, AuditOption::On),
    AuditCommand(CommandCode::SignEddsa, AuditOption::On),
    AuditCommand(CommandCode::BlinkDevice, AuditOption::On),
];

/// Per-command auditing settings
#[derive(Debug)]
pub struct CommandAuditOptions(BTreeMap<CommandCode, AuditOption>);

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
    pub fn put(&mut self, command_type: CommandCode, audit_option: AuditOption) {
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
