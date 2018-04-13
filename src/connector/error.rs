//! Error types for yubihsm-connector

/// yubihsm-connector related errors
#[derive(Debug, Fail)]
pub enum ConnectorError {
    /// URL provided for yubihsm-connector is not valid
    #[fail(display = "invalid URL")]
    InvalidURL {
        /// Description of why the connection failed
        description: String,
    },

    /// Connection to yubihsm-connector failed
    #[fail(display = "connection failed: {}", description)]
    ConnectionFailed {
        /// Description of why the connection failed
        description: String,
    },

    /// Error making request
    #[fail(display = "invalid request: {}", description)]
    RequestError {
        /// Description of the error
        description: String,
    },

    /// yubihsm-connector sent bad response
    #[fail(display = "bad response from yubihsm-connector: {}", description)]
    ResponseError {
        /// Description of the bad response we received
        description: String,
    },
}
