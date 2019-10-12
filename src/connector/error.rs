//! Error types for `yubihsm-connector`

use std::{fmt, io, num::ParseIntError, str::Utf8Error};

/// `yubihsm-connector` related errors
pub type Error = crate::Error<ErrorKind>;

/// `yubihsm-connector` related error kinds
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// Address provided was not valid
    AddrInvalid,

    /// Access denied
    AccessDenied,

    /// YubiHSM 2 is busy (in use by another client / process)
    DeviceBusyError,

    /// Couldn't connect to the YubiHSM 2
    ConnectionFailed,

    /// Input/output error
    IoError,

    /// Error making request
    RequestError,

    /// `yubihsm-connector` sent bad response
    ResponseError,

    /// USB operation failed
    #[cfg(feature = "usb")]
    UsbError,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ErrorKind::AddrInvalid => "invalid address",
            ErrorKind::AccessDenied => "access denied",
            ErrorKind::DeviceBusyError => "device already in use",
            ErrorKind::ConnectionFailed => "connection failed",
            ErrorKind::IoError => "I/O error",
            ErrorKind::RequestError => "invalid request",
            ErrorKind::ResponseError => "bad connector response",
            #[cfg(feature = "usb")]
            ErrorKind::UsbError => "USB error",
        })
    }
}

impl From<fmt::Error> for Error {
    fn from(err: fmt::Error) -> Self {
        format_err!(ErrorKind::IoError, err.to_string())
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        format_err!(ErrorKind::IoError, err.to_string())
    }
}

#[cfg(feature = "http")]
impl From<gaunt::Error> for Error {
    fn from(err: gaunt::Error) -> Error {
        let kind = match err.kind() {
            gaunt::ErrorKind::AddrInvalid => ErrorKind::AddrInvalid,
            gaunt::ErrorKind::IoError => ErrorKind::IoError,
            gaunt::ErrorKind::ParseError | gaunt::ErrorKind::ResponseError => {
                ErrorKind::ResponseError
            }
            gaunt::ErrorKind::RequestError => ErrorKind::RequestError,
        };

        format_err!(kind, err)
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
    }
}

impl From<ParseIntError> for Error {
    fn from(err: ParseIntError) -> Self {
        format_err!(ErrorKind::ResponseError, err.to_string())
    }
}

impl From<Utf8Error> for Error {
    fn from(err: Utf8Error) -> Self {
        format_err!(ErrorKind::ResponseError, err.to_string())
    }
}
