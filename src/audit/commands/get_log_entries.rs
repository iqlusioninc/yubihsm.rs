//! Get audit logs from the `YubiHSM 2` device
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Log_Entries.html>

use crate::{
    command::{self, Command},
    object,
    response::{self, Response},
    serialization::{self, serialize},
};
use serde::{ser, Deserialize, Serialize};
use sha2::Digest as _;
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
    pub result: AuditResponseCode,

    /// Tick count of the HSM's internal clock
    pub tick: u32,

    /// 16-byte truncated SHA-256 digest of this log entry and the digest of the previous entry
    pub digest: LogDigest,
}

impl LogEntry {
    /// The payload used to rebuild the hash of the log entry.
    pub fn digest_payload(&self) -> Result<Box<[u8]>, serialization::Error> {
        let mut out = serialize(self)?;

        // Strip out the digest
        out.resize(out.len() - LOG_DIGEST_SIZE, 0);
        Ok(out.into_boxed_slice())
    }
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
            write!(f, "{byte:02x}")?;
            write!(f, "{}", if i == LOG_DIGEST_SIZE - 1 { ")" } else { ":" })?;
        }
        Ok(())
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct AuditResponseCode(pub response::Code);

impl Serialize for AuditResponseCode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        let value = match self.0.to_u8() {
            v @ 0x80.. => v,
            //
            v @ 0x76.. => v,
            soft_err => 0x75 - soft_err,
        };

        serializer.serialize_u8(value)
    }
}

/// Verify log entries for consistency.
///
/// Checks if `entries_to_verify` are correctly derived from the `root` entry as described in [the documentation].
/// The root entry is usually the device initialization message but it is not strictly necessary.
///
/// Returns `Ok(true)` if the log entry is consistent, `Ok(false)` if not, and `Err(...)` on serialization errors.
///
/// [the documentation]: https://docs.yubico.com/hardware/yubihsm-2/hsm-2-user-guide/hsm2-cmd-reference.html#hsm2-cmd-get-log-entries-label
pub fn verify_log_entries(
    root: &LogEntry,
    entries_to_verify: &[LogEntry],
) -> Result<bool, serialization::Error> {
    let mut hasher = sha2::Sha256::new();
    let mut previous_digest = root.digest.0;
    for entry in entries_to_verify {
        hasher.update(entry.digest_payload()?);
        hasher.update(previous_digest);

        let trunc_digest = &hasher.finalize_reset()[..16];
        if trunc_digest != entry.digest.0 {
            return Ok(false);
        }
        previous_digest.copy_from_slice(trunc_digest);
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialization::deserialize;
    use hex_literal::hex;

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
                result: AuditResponseCode(response::Code::Success(command::Code::Error)),
                tick: 4294967295,
                digest: LogDigest([
                    0xed, 0xd9, 0xb4, 0xe0, 0xc3, 0x8c, 0x4f, 0x7e, 0xc5, 0x0f, 0x05, 0x70, 0x91,
                    0xf1, 0x2f, 0xce
                ])
            }
        );

        // Erroneous GetObjectInfo
        let payload = hex!("""
                00084e00030001000fffff0b00001578
                b59b4d9ce1aa4f618abcddb0d6f787c2
            """);
        let entry: LogEntry = deserialize(&payload).expect("Parse log entry");
        assert_eq!(
            entry,
            LogEntry {
                item: 8,
                cmd: command::Code::GetObjectInfo,
                length: 3,
                session_key: 1,
                target_key: 15,
                second_key: 65535,
                result: AuditResponseCode(response::Code::DeviceObjectNotFound),
                tick: 5496,
                digest: LogDigest(hex!("b59b4d9ce1aa4f618abcddb0d6f787c2"))
            }
        );

        assert_eq!(
            serialize(&entry).expect("serialize the entry back"),
            &payload
        );
    }

    #[test]
    fn serialize_device_boot_entry() {
        let device_boot_msg: &[u8] = &[
            0, 2, 0, 0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 237, 217, 180, 224, 195, 140, 79,
            126, 197, 15, 5, 112, 145, 241, 47, 206,
        ];
        let entry: LogEntry = deserialize(device_boot_msg).expect("Parse log entry");
        assert_eq!(
            entry,
            LogEntry {
                item: 2,
                cmd: command::Code::Unknown,
                length: 0,
                session_key: 65535,
                target_key: 0,
                second_key: 0,
                result: AuditResponseCode(response::Code::DeviceOk),
                tick: 0,
                digest: LogDigest([
                    0xed, 0xd9, 0xb4, 0xe0, 0xc3, 0x8c, 0x4f, 0x7e, 0xc5, 0x0f, 0x05, 0x70, 0x91,
                    0xf1, 0x2f, 0xce
                ])
            }
        );
    }

    #[test]
    fn verify_log() {
        let log: LogEntries = deserialize(&[
            0, 0, 0, 0, 5, 0, 1, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 16, 57, 193, 231, 53, 39, 161, 48, 106, 91, 222, 241, 111, 218, 230, 186, 0, 2, 0,
            0, 0, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0, 0, 77, 6, 54, 133, 12, 128, 156, 82, 145, 139,
            111, 177, 109, 100, 204, 5, 0, 3, 106, 0, 14, 0, 1, 0, 7, 255, 255, 234, 0, 0, 1, 6,
            202, 0, 137, 24, 52, 154, 17, 142, 18, 48, 153, 220, 202, 91, 172, 147, 0, 4, 106, 0,
            14, 0, 1, 0, 7, 255, 255, 234, 0, 0, 1, 10, 253, 255, 178, 231, 56, 29, 160, 88, 146,
            181, 192, 29, 142, 45, 44, 215, 0, 5, 106, 0, 14, 0, 1, 0, 7, 255, 255, 234, 0, 0, 1,
            13, 83, 130, 159, 15, 119, 58, 142, 25, 94, 111, 244, 153, 172, 98, 117, 239,
        ])
        .expect("log entries should be ok");

        let root = &log.entries[0];
        let entries_to_verify = &log.entries[1..];

        verify_log_entries(root, entries_to_verify).expect("verification to succeed");
    }
}
