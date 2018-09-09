//! (Partial) support for audit logging within the MockHSM
//!
//! No logging is performed and these settings are not yet enforced

use std::collections::BTreeMap;

use audit::*;
use commands::CommandType;
use serializers;

/// Default per-command auditing options
pub const DEFAULT_COMMAND_AUDIT_OPTIONS: &[AuditCommand] = &[
    AuditCommand(CommandType::Echo, AuditOption::Off),
    AuditCommand(CommandType::CreateSession, AuditOption::On),
    AuditCommand(CommandType::AuthSession, AuditOption::On),
    AuditCommand(CommandType::SessionMessage, AuditOption::Off),
    AuditCommand(CommandType::DeviceInfo, AuditOption::Off),
    AuditCommand(CommandType::BSL, AuditOption::Off),
    AuditCommand(CommandType::Command9, AuditOption::Off),
    AuditCommand(CommandType::Reset, AuditOption::On),
    AuditCommand(CommandType::CloseSession, AuditOption::On),
    AuditCommand(CommandType::StorageStatus, AuditOption::On),
    AuditCommand(CommandType::PutOpaqueObject, AuditOption::On),
    AuditCommand(CommandType::GetOpaqueObject, AuditOption::On),
    AuditCommand(CommandType::PutAuthKey, AuditOption::On),
    AuditCommand(CommandType::PutAsymmetricKey, AuditOption::On),
    AuditCommand(CommandType::GenerateAsymmetricKey, AuditOption::On),
    AuditCommand(CommandType::SignDataPKCS1, AuditOption::On),
    AuditCommand(CommandType::SignDataPSS, AuditOption::On),
    AuditCommand(CommandType::SignDataECDSA, AuditOption::On),
    AuditCommand(CommandType::ListObjects, AuditOption::On),
    AuditCommand(CommandType::DecryptPKCS1, AuditOption::On),
    AuditCommand(CommandType::DecryptECDH, AuditOption::On),
    AuditCommand(CommandType::ExportWrapped, AuditOption::On),
    AuditCommand(CommandType::ImportWrapped, AuditOption::On),
    AuditCommand(CommandType::PutWrapKey, AuditOption::On),
    AuditCommand(CommandType::GetLogs, AuditOption::Off),
    AuditCommand(CommandType::SetLogIndex, AuditOption::On),
    AuditCommand(CommandType::GetObjectInfo, AuditOption::On),
    AuditCommand(CommandType::PutOption, AuditOption::On),
    AuditCommand(CommandType::GetOption, AuditOption::On),
    AuditCommand(CommandType::GetPseudoRandom, AuditOption::On),
    AuditCommand(CommandType::PutHMACKey, AuditOption::On),
    AuditCommand(CommandType::HMACData, AuditOption::On),
    AuditCommand(CommandType::GetPubKey, AuditOption::On),
    AuditCommand(CommandType::DeleteObject, AuditOption::On),
    AuditCommand(CommandType::DecryptOAEP, AuditOption::On),
    AuditCommand(CommandType::GenerateHMACKey, AuditOption::On),
    AuditCommand(CommandType::GenerateWrapKey, AuditOption::On),
    AuditCommand(CommandType::VerifyHMAC, AuditOption::On),
    AuditCommand(CommandType::SSHCertify, AuditOption::On),
    AuditCommand(CommandType::PutTemplate, AuditOption::On),
    AuditCommand(CommandType::GetTemplate, AuditOption::On),
    AuditCommand(CommandType::DecryptOTP, AuditOption::On),
    AuditCommand(CommandType::CreateOTPAEAD, AuditOption::On),
    AuditCommand(CommandType::RandomOTPAEAD, AuditOption::On),
    AuditCommand(CommandType::RewrapOTPAEAD, AuditOption::On),
    AuditCommand(CommandType::AttestAsymmetric, AuditOption::On),
    AuditCommand(CommandType::PutOTPAEAD, AuditOption::On),
    AuditCommand(CommandType::GenerateOTPAEAD, AuditOption::On),
    AuditCommand(CommandType::WrapData, AuditOption::On),
    AuditCommand(CommandType::UnwrapData, AuditOption::On),
    AuditCommand(CommandType::SignDataEdDSA, AuditOption::On),
    AuditCommand(CommandType::Blink, AuditOption::On),
];

/// Per-command auditing settings
#[derive(Debug)]
pub struct CommandAuditOptions(BTreeMap<CommandType, AuditOption>);

impl CommandAuditOptions {
    /// Serialize these audit options for use as a `GetObjects` response
    pub fn serialize(&self) -> Vec<u8> {
        let audit_commands: Vec<_> = self
            .0
            .iter()
            .map(|(cmd, opt)| AuditCommand(*cmd, *opt))
            .collect();

        serializers::serialize(&audit_commands).unwrap()
    }

    /// Change a setting for a particular command
    pub fn put(&mut self, command_type: CommandType, audit_option: AuditOption) {
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
