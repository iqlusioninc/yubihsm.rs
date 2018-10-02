//! (Partial) support for audit logging within the MockHsm
//!
//! No logging is performed and these settings are not yet enforced

use std::collections::BTreeMap;

use audit::*;
use command::CommandCode;
use serialization::serialize;

/// Default per-command auditing options
pub const DEFAULT_COMMAND_AUDIT_OPTIONS: &[AuditCommand] = &[
    AuditCommand(CommandCode::Echo, AuditOption::Off),
    AuditCommand(CommandCode::CreateSession, AuditOption::On),
    AuditCommand(CommandCode::AuthSession, AuditOption::On),
    AuditCommand(CommandCode::SessionMessage, AuditOption::Off),
    AuditCommand(CommandCode::DeviceInfo, AuditOption::Off),
    AuditCommand(CommandCode::BSL, AuditOption::Off),
    AuditCommand(CommandCode::Command9, AuditOption::Off),
    AuditCommand(CommandCode::Reset, AuditOption::On),
    AuditCommand(CommandCode::CloseSession, AuditOption::On),
    AuditCommand(CommandCode::StorageStatus, AuditOption::On),
    AuditCommand(CommandCode::PutOpaqueObject, AuditOption::On),
    AuditCommand(CommandCode::GetOpaqueObject, AuditOption::On),
    AuditCommand(CommandCode::PutAuthKey, AuditOption::On),
    AuditCommand(CommandCode::PutAsymmetricKey, AuditOption::On),
    AuditCommand(CommandCode::GenerateAsymmetricKey, AuditOption::On),
    AuditCommand(CommandCode::SignDataPKCS1, AuditOption::On),
    AuditCommand(CommandCode::SignDataPSS, AuditOption::On),
    AuditCommand(CommandCode::SignDataECDSA, AuditOption::On),
    AuditCommand(CommandCode::ListObjects, AuditOption::On),
    AuditCommand(CommandCode::DecryptPKCS1, AuditOption::On),
    AuditCommand(CommandCode::DecryptECDH, AuditOption::On),
    AuditCommand(CommandCode::ExportWrapped, AuditOption::On),
    AuditCommand(CommandCode::ImportWrapped, AuditOption::On),
    AuditCommand(CommandCode::PutWrapKey, AuditOption::On),
    AuditCommand(CommandCode::GetLogs, AuditOption::Off),
    AuditCommand(CommandCode::SetLogIndex, AuditOption::On),
    AuditCommand(CommandCode::GetObjectInfo, AuditOption::On),
    AuditCommand(CommandCode::PutOption, AuditOption::On),
    AuditCommand(CommandCode::GetOption, AuditOption::On),
    AuditCommand(CommandCode::GetPseudoRandom, AuditOption::On),
    AuditCommand(CommandCode::PutHMACKey, AuditOption::On),
    AuditCommand(CommandCode::HMACData, AuditOption::On),
    AuditCommand(CommandCode::GetPubKey, AuditOption::On),
    AuditCommand(CommandCode::DeleteObject, AuditOption::On),
    AuditCommand(CommandCode::DecryptOAEP, AuditOption::On),
    AuditCommand(CommandCode::GenerateHMACKey, AuditOption::On),
    AuditCommand(CommandCode::GenerateWrapKey, AuditOption::On),
    AuditCommand(CommandCode::VerifyHMAC, AuditOption::On),
    AuditCommand(CommandCode::SSHCertify, AuditOption::On),
    AuditCommand(CommandCode::PutTemplate, AuditOption::On),
    AuditCommand(CommandCode::GetTemplate, AuditOption::On),
    AuditCommand(CommandCode::DecryptOTP, AuditOption::On),
    AuditCommand(CommandCode::CreateOTPAEAD, AuditOption::On),
    AuditCommand(CommandCode::RandomOTPAEAD, AuditOption::On),
    AuditCommand(CommandCode::RewrapOTPAEAD, AuditOption::On),
    AuditCommand(CommandCode::AttestAsymmetric, AuditOption::On),
    AuditCommand(CommandCode::PutOTPAEAD, AuditOption::On),
    AuditCommand(CommandCode::GenerateOTPAEAD, AuditOption::On),
    AuditCommand(CommandCode::WrapData, AuditOption::On),
    AuditCommand(CommandCode::UnwrapData, AuditOption::On),
    AuditCommand(CommandCode::SignDataEdDSA, AuditOption::On),
    AuditCommand(CommandCode::Blink, AuditOption::On),
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
