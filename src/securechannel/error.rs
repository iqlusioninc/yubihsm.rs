//! Error types for Secure Channel communications

/// Secure Channel errors
#[derive(Debug, Fail)]
pub enum SecureChannelError {
    /// MAC or cryptogram verify failed
    #[fail(display = "verification failed: {}", description)]
    VerifyFailed {
        /// Description of the verification failure
        description: String,
    },

    /// Protocol error (i.e. parse error)
    #[fail(display = "error parsing value: {}", description)]
    ProtocolError {
        /// Description of the protocol error
        description: String,
    },

    /// Max commands per session exceeded and a new session should be created
    #[fail(display = "session limit reached: {}", description)]
    SessionLimitReached {
        /// Description of the protocol error
        description: String,
    },
}
