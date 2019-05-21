//! USB device configuration

use crate::device::SerialNumber;
use serde::{Deserialize, Serialize};

/// Default timeouts for reading and writing (1 second)
pub const DEFAULT_TIMEOUT_MILLIS: u64 = 1000;

/// Configuration for connecting to the YubiHSM via USB
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct UsbConfig {
    /// Serial number of the YubiHSM to connect to
    pub serial: Option<SerialNumber>,

    /// Timeout for USB operations (default 1s)
    pub timeout_ms: u64,
}

impl Default for UsbConfig {
    fn default() -> UsbConfig {
        UsbConfig {
            serial: None,
            timeout_ms: DEFAULT_TIMEOUT_MILLIS,
        }
    }
}
