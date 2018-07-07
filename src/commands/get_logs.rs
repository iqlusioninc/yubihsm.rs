//! Get audit logs from the `YubiHSM2` device
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Logs.html>

use std::fmt::{self, Debug};

use super::{Command, Response};
use securechannel::ResponseCode;
use {CommandType, Connector, ObjectId, Session, SessionError};

/// Get audit logs from the YubiHSM2 device
pub fn get_logs<C: Connector>(session: &mut Session<C>) -> Result<GetLogsResponse, SessionError> {
    session.send_encrypted_command(GetLogsCommand {})
}

/// Request parameters for `commands::get_logs`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetLogsCommand {}

impl Command for GetLogsCommand {
    type ResponseType = GetLogsResponse;
}

/// Response from `commands::get_logs`
#[derive(Serialize, Deserialize, Debug)]
pub struct GetLogsResponse {
    /// Number of boot events which weren't logged (if buffer is full and audit enforce is set)
    pub unlogged_boot_events: u16,

    /// Number of unlogged authentication events (if buffer is full and audit enforce is set)
    pub unlogged_auth_events: u16,

    /// Number of entries in the response
    pub num_entries: u8,

    /// Entries in the log
    pub entries: Vec<LogEntry>,
}

impl Response for GetLogsResponse {
    const COMMAND_TYPE: CommandType = CommandType::GetLogs;
}

/// Entry in the log response
#[derive(Serialize, Deserialize, Debug)]
pub struct LogEntry {
    /// Entry number
    pub item: u16,

    /// Command type
    pub cmd: CommandType,

    /// Command length
    pub length: u16,

    /// Session key ID
    pub session_key: ObjectId,

    /// Target key ID
    pub target_key: ObjectId,

    /// Second key affected
    pub second_key: ObjectId,

    /// Result of the operation
    pub result: ResponseCode,

    /// Tick count of the HSM's internal clock
    pub tick: u32,

    /// 16-byte truncated SHA-256 digest of this log entry and the digest of the previous entry
    pub digest: LogDigest,
}

/// Size of a truncated digest in the log
pub const LOG_DIGEST_SIZE: usize = 16;

/// Truncated SHA-256 digest of a log entry and the previous log digest
#[derive(Serialize, Deserialize)]
pub struct LogDigest(pub [u8; LOG_DIGEST_SIZE]);

impl AsRef<[u8]> for LogDigest {
    fn as_ref(&self) -> &[u8] {
        &self.0[..]
    }
}

impl Debug for LogDigest {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LogDigest(")?;
        for (i, byte) in self.0.iter().enumerate() {
            write!(f, "{:02x}", byte)?;
            write!(f, "{}", if i == LOG_DIGEST_SIZE - 1 { ")" } else { ":" })?;
        }
        Ok(())
    }
}
