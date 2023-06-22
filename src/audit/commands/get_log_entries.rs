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
