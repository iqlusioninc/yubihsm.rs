//! USB device configuration

use crate::device::SerialNumber;
use serde::{Deserialize, Serialize};

/// Configuration for connecting to the YubiHSM via USB
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UsbConfig {
    /// Serial number of the YubiHSM to connect to
    pub serial: Option<SerialNumber>,

    /// Timeout for USB operations (default 1s)
    pub timeout_ms: u64,
}

impl UsbConfig {
    /// Default timeout for USB communication (30 seconds)
    pub const DEFAULT_TIMEOUT_MILLIS: u64 = 30_000;
}

impl Default for UsbConfig {
    fn default() -> UsbConfig {
        UsbConfig {
            serial: None,
            timeout_ms: Self::DEFAULT_TIMEOUT_MILLIS,
        }
    }
}
