use std::time::Duration;

/// Sessions with the YubiHSM are stateful and expire after 30 seconds. See:
/// <https://developers.yubico.com/YubiHSM2/Concepts/Session.html>
pub const SESSION_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeouts when performing USB operations
#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct SessionTimeout(Duration);

impl SessionTimeout {
    /// Create a new timeout from the given duration
    pub fn new(duration: Duration) -> Self {
        SessionTimeout(duration)
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

/// Default timeout
impl Default for SessionTimeout {
    fn default() -> Self {
        Self::new(SESSION_INACTIVITY_TIMEOUT)
    }
}

impl From<Duration> for SessionTimeout {
    fn from(duration: Duration) -> Self {
        Self::new(duration)
    }
}
