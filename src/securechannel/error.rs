//! Error types for Secure Channel problems

/// Secure Channel errors
#[derive(Debug, Fail)]
pub enum SecureChannelError {
    /// MAC or cryptogram verify failed
    #[cfg(feature = "mockhsm")]
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
}
