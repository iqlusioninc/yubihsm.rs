//! Errors that occur during sessions

/// Session-related errors
#[derive(Debug, Fail)]
pub enum SessionError {
    /// Couldn't create session
    #[fail(display = "couldn't create session: {}", description)]
    CreateFailed {
        /// Description of why we couldn't create the session
        description: String,
    },

    /// Couldn't authenticate session
    #[fail(display = "authentication failed: {}", description)]
    AuthFailed {
        /// Details about the authentication failure
        description: String,
    },

    /// Protocol error occurred
    #[fail(display = "protocol error: {}", description)]
    ProtocolError {
        /// Details about the protocol error
        description: String,
    },

    /// HSM returned an error response
    #[fail(display = "error response from HSM: {}", description)]
    ResponseError {
        /// Description of the bad response we received
        description: String,
    },
}
