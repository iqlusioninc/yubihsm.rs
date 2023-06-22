//! Get audit logs from the `YubiHSM 2` device
//!
//! <https://developers.yubico.com/YubiHSM2/Commands/Get_Log_Entries.html>

use crate::{audit::log::LogEntries, command::Command};
use serde::{Deserialize, Serialize};
use std::fmt::Debug;

/// Request parameters for `command::get_log_entries`
#[derive(Serialize, Deserialize, Debug)]
pub(crate) struct GetLogEntriesCommand {}

impl Command for GetLogEntriesCommand {
    type ResponseType = LogEntries;
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
