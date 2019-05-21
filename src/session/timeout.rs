//! Session activity timeouts

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Sessions with the YubiHSM are stateful and expire after 30 seconds. See:
/// <https://developers.yubico.com/YubiHSM2/Concepts/Session.html>
pub const SESSION_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(30);

/// Session timeouts (i.e. YubiHSM's session inactivity timeout)
#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct Timeout(Duration);

impl Timeout {
    /// Create a new timeout from the given duration
    pub fn new(duration: Duration) -> Self {
        Timeout(duration)
    }

    /// Create a new timeout from the given number of secs
    pub fn from_secs(secs: u64) -> Self {
        Self::from(Duration::from_secs(secs))
    }

    /// Get the duration value
    pub fn duration(&self) -> Duration {
        self.0
    }
}

impl Default for Timeout {
    /// Default timeout: 30 seconds
    fn default() -> Self {
        Self::new(SESSION_INACTIVITY_TIMEOUT)
    }
}

impl From<Duration> for Timeout {
    fn from(duration: Duration) -> Self {
        Self::new(duration)
    }
}
