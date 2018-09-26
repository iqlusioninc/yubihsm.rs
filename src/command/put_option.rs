//! Put auditing options which have been configured on the device.
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Put_Option.html>

use super::{Command, Response};
use audit::*;
use client::{Client, ClientError};
use serialization::serialize;
use {Adapter, CommandType};

/// Configure the audit policy settings for a particular command, e.g. auditing
/// should be `On`, `Off`, or `Fix` (i.e. fixed permanently on)
pub fn put_command_audit_option<A>(
    session: &mut Client<A>,
    command: CommandType,
    audit_option: AuditOption,
) -> Result<(), ClientError>
where
    A: Adapter,
{
    session.send_command(PutOptionCommand {
        tag: AuditTag::Command,
        length: 2,
        value: serialize(&AuditCommand(command, audit_option))?,
    })?;

    Ok(())
}

/// Put the forced auditing global option: when enabled, the device will
/// refuse operations if the [log store] becomes full.
///
/// Options are `On`, `Off`, or `Fix` (i.e. fixed permanently on)
///
/// [log store]: https://developers.yubico.com/YubiHSM2/Concepts/Logs.html
pub fn put_force_audit_option<A: Adapter>(
    session: &mut Client<A>,
    option: AuditOption,
) -> Result<(), ClientError> {
    session.send_command(PutOptionCommand {
        tag: AuditTag::Force,
        length: 1,
        value: vec![option.to_u8()],
    })?;

    Ok(())
}

/// Request parameters for `command::put_option`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutOptionCommand {
    /// Tag byte for `Force` vs `Command` options
    pub tag: AuditTag,

    /// Length of the option-specific data
    pub length: u16,

    /// Option specific data
    pub value: Vec<u8>,
}

impl Command for PutOptionCommand {
    type ResponseType = PutOptionResponse;
}

/// Response from `command::put_option`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct PutOptionResponse {}

impl Response for PutOptionResponse {
    const COMMAND_TYPE: CommandType = CommandType::PutOption;
}
