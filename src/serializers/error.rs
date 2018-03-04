use std::error::Error as StdError;
use std::{fmt, io};

use serde;

/// Serialization errors
// TODO: use failure and the Fail trait (presently having trait bounds issues)
#[derive(Debug)]
pub enum SerializationError {
    /// Input/output errors
    Io { cause: io::Error },

    /// Errors that occurred during Serde parsing
    Parse {
        /// Description of the parse error
        description: String,
    },

    /// Unexpected end-of-file
    UnexpectedEof {
        /// Description of the error
        description: String,
    },
}

impl fmt::Display for SerializationError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            SerializationError::Io { ref cause } => write!(fmt, "{:?}", cause),
            SerializationError::Parse { ref description }
            | SerializationError::UnexpectedEof { ref description } => {
                write!(fmt, "{}", description)
            }
        }
    }
}

impl StdError for SerializationError {
    fn description(&self) -> &str {
        match *self {
            SerializationError::Io { .. } => "I/O error",
            SerializationError::Parse { .. } => "parse error",
            SerializationError::UnexpectedEof { .. } => "unexpected end-of-buffer",
        }
    }

    fn cause(&self) -> Option<&StdError> {
        None
    }
}

impl From<io::Error> for SerializationError {
    fn from(ioerror: io::Error) -> Self {
        SerializationError::Io { cause: ioerror }
    }
}

impl serde::ser::Error for SerializationError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        err!(SerializationError::Parse, msg.to_string())
    }
}

impl serde::de::Error for SerializationError {
    fn custom<T: fmt::Display>(msg: T) -> Self {
        err!(SerializationError::Parse, msg.to_string())
    }
}
