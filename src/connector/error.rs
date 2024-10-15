//! Error types for `yubihsm-connector`

use crate::error::{BoxError, Context};
use std::{fmt, io, num::ParseIntError, str::Utf8Error};
use thiserror::Error;

/// `yubihsm-connector` related errors
pub type Error = crate::Error<ErrorKind>;

/// `yubihsm-connector` related error kinds
#[derive(Copy, Clone, Debug, Eq, Error, PartialEq)]
pub enum ErrorKind {
    /// Address provided was not valid
    #[error("invalid address")]
    AddrInvalid,

    /// Access denied
    #[error("access denied")]
    AccessDenied,

    /// YubiHSM 2 is busy (in use by another client / process)
    #[error("device already in use")]
    DeviceBusyError,

    /// Couldn't connect to the YubiHSM 2
    #[error("connection failed")]
    ConnectionFailed,

    /// Input/output error
    #[error("I/O error")]
    IoError,

    /// Error making request
    #[error("request error")]
    RequestError,

    /// `yubihsm-connector` sent bad response
    #[error("bad response from connector")]
    ResponseError,

    /// USB operation failed
    #[cfg(feature = "usb")]
    #[error("USB error")]
    UsbError,
}

impl ErrorKind {
    /// Create an error context from this error
    pub fn context(self, source: impl Into<BoxError>) -> Context<ErrorKind> {
        Context::new(self, Some(source.into()))
    }
}

impl From<fmt::Error> for Error {
    fn from(err: fmt::Error) -> Self {
        ErrorKind::IoError.context(err).into()
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        ErrorKind::IoError.context(err).into()
    }
}

#[cfg(feature = "http")]
impl From<ureq::Error> for Error {
    fn from(err: ureq::Error) -> Error {
        let kind = match err.kind() {
            ureq::ErrorKind::Dns => ErrorKind::AddrInvalid,
            ureq::ErrorKind::Io => ErrorKind::IoError,
            ureq::ErrorKind::HTTP => ErrorKind::ResponseError,
            _ => ErrorKind::RequestError,
        };

        kind.context(err).into()
    }
}

#[cfg(feature = "usb")]
impl From<rusb::Error> for Error {
    fn from(err: rusb::Error) -> Error {
        match err {
            rusb::Error::Access => format_err!(ErrorKind::AccessDenied, "{}", err),
            rusb::Error::Io => format_err!(ErrorKind::IoError, "{}", err),
            rusb::Error::Pipe => format_err!(ErrorKind::UsbError, "lost connection to USB device"),
            _ => format_err!(ErrorKind::UsbError, "{}", err),
        }
            .into()
    }
}

impl From<ParseIntError> for Error {
    fn from(err: ParseIntError) -> Self {
        ErrorKind::ResponseError.context(err).into()
    }
}

impl From<Utf8Error> for Error {
    fn from(err: Utf8Error) -> Self {
        ErrorKind::ResponseError.context(err).into()
    }
}
