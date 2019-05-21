//! Get audit logs from the `YubiHSM 2` device
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Log_Entries.html>

use crate::{
    command::{self, Command},
    object,
    response::{self, Response},
};
use serde::{Deserialize, Serialize};
use std::fmt::{self, Debug};

/// Request parameters for `command::get_log_entries`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetLogEntriesCommand {}

impl Command for GetLogEntriesCommand {
    type ResponseType = LogEntries;
}

/// Response from `command::get_log_entries`
#[derive(Serialize, Deserialize, Debug)]
pub struct LogEntries {
    /// Number of boot events which weren't logged (if buffer is full and audit enforce is set)
    pub unlogged_boot_events: u16,

    /// Number of unlogged authentication events (if buffer is full and audit enforce is set)
    pub unlogged_auth_events: u16,

    /// Number of entries in the response
    pub num_entries: u8,

    /// Entries in the log
    pub entries: Vec<LogEntry>,
}

impl Response for LogEntries {
    const COMMAND_CODE: command::Code = command::Code::GetLogEntries;
}

/// Entry in the log response
#[derive(Serialize, Deserialize, Debug)]
pub struct LogEntry {
    /// Entry number
    pub item: u16,

    /// Command type
    pub cmd: command::Code,

    /// Command length
    pub length: u16,

    /// Session key ID
    pub session_key: object::Id,

    /// Target key ID
    pub target_key: object::Id,

    /// Second key affected
    pub second_key: object::Id,

    /// Result of the operation
    pub result: response::Code,

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
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "LogDigest(")?;
        for (i, byte) in self.0.iter().enumerate() {
            write!(f, "{:02x}", byte)?;
            write!(f, "{}", if i == LOG_DIGEST_SIZE - 1 { ")" } else { ":" })?;
        }
        Ok(())
    }
}
