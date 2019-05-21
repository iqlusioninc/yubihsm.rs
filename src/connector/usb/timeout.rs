//! USB timeouts

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Number of seconds to wait when communicating with the YubiHSM 2
pub const DEFAULT_USB_TIMEOUT_SECS: u64 = 1; // 1 second

/// Timeouts when performing USB operations
#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct UsbTimeout(Duration);

impl UsbTimeout {
    /// Create a new timeout from the given duration
    pub fn new(duration: Duration) -> Self {
        UsbTimeout(duration)
    }

    /// Create a new timeout from the given number of secs
    pub fn from_secs(secs: u64) -> Self {
        Self::from(Duration::from_secs(secs))
    }

    /// Create a new timeout from the given number of milliseconds
    pub fn from_millis(millis: u64) -> Self {
        Self::from(Duration::from_millis(millis))
    }

    /// Get the duration value
    pub fn duration(&self) -> Duration {
        self.0
    }
}

/// Default timeout
impl Default for UsbTimeout {
    fn default() -> Self {
        Self::from_secs(DEFAULT_USB_TIMEOUT_SECS)
    }
}

impl From<Duration> for UsbTimeout {
    fn from(duration: Duration) -> Self {
        Self::new(duration)
    }
}
