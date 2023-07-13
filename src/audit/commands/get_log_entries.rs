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
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
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
#[derive(Serialize, Deserialize, PartialEq, Eq)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialization::deserialize;

    static SAMPLE_ENTRY: &[u8] = &[
        0, 1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 237, 217, 180,
        224, 195, 140, 79, 126, 197, 15, 5, 112, 145, 241, 47, 206,
    ];

    #[test]
    fn test_get_log_entry() {
        let entry: LogEntry = deserialize(SAMPLE_ENTRY).expect("Parse log entry");
        assert_eq!(
            entry,
            LogEntry {
                item: 1,
                cmd: command::Code::HsmInitialization,
                length: 65535,
                session_key: 65535,
                target_key: 65535,
                second_key: 65535,
                result: response::Code::Success(command::Code::Error),
                tick: 4294967295,
                digest: LogDigest([
                    0xed, 0xd9, 0xb4, 0xe0, 0xc3, 0x8c, 0x4f, 0x7e, 0xc5, 0x0f, 0x05, 0x70, 0x91,
                    0xf1, 0x2f, 0xce
                ])
            }
        )
    }
}
