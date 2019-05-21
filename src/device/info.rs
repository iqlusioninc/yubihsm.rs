//! Device info

use super::serial;
use crate::Algorithm;
use serde::{Deserialize, Serialize};

/// Information about an HSM device
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Info {
    /// Device major version
    pub major_version: u8,

    /// Device minor version
    pub minor_version: u8,

    /// Device build version (i.e. patchlevel)
    pub build_version: u8,

    /// Device serial number
    pub serial_number: serial::Number,

    /// Size of the log store (in lines/entries)
    pub log_store_capacity: u8,

    /// Number of log lines used
    pub log_store_used: u8,

    /// Supported algorithms
    pub algorithms: Vec<Algorithm>,
}
