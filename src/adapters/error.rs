//! Error types for `yubihsm-connector`

#[cfg(feature = "usb")]
use libusb;
use std::num::ParseIntError;
use std::str::Utf8Error;
use std::{fmt, io};

use error::Error;

/// `yubihsm-connector` related errors
pub type AdapterError = Error<AdapterErrorKind>;

/// `yubihsm-connector` related error kinds
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum AdapterErrorKind {
    /// Address provided was not valid
    #[fail(display = "invalid address")]
    AddrInvalid,

    /// Access denied
    #[fail(display = "access denied")]
    AccessDenied,

    /// YubiHSM2 is busy (in use by another client / process)
    #[fail(display = "device already in use")]
    DeviceBusyError,

    /// Couldn't connect to the YubiHSM2
    #[fail(display = "connection failed")]
    ConnectionFailed,

    /// Input/output error
    #[fail(display = "I/O error")]
    IoError,

    /// Error making request
    #[fail(display = "invalid request")]
    RequestError,

    /// `yubihsm-connector` sent bad response
    #[fail(display = "bad connector response")]
    ResponseError,

    /// USB operation failed
    #[cfg(feature = "usb")]
    #[fail(display = "USB error")]
    UsbError,
}

/// Create a new connector error with a formatted message
macro_rules! adapter_err {
    ($kind:ident, $msg:expr) => {
        ::adapters::AdapterError::new(
            ::adapters::AdapterErrorKind::$kind,
            Some($msg.to_owned())
        )
    };
    ($kind:ident, $fmt:expr, $($arg:tt)+) => {
        ::adapters::AdapterError::new(
            ::adapters::AdapterErrorKind::$kind,
            Some(format!($fmt, $($arg)+))
        )
    };
}

/// Create and return an connector error with a formatted message
macro_rules! adapter_fail {
    ($kind:ident, $msg:expr) => {
        return Err(adapter_err!($kind, $msg).into());
    };
    ($kind:ident, $fmt:expr, $($arg:tt)+) => {
        return Err(adapter_err!($kind, $fmt, $($arg)+).into());
    };
}

impl From<fmt::Error> for AdapterError {
    fn from(err: fmt::Error) -> Self {
        adapter_err!(IoError, err.to_string())
    }
}

impl From<io::Error> for AdapterError {
    fn from(err: io::Error) -> Self {
        adapter_err!(IoError, err.to_string())
    }
}

#[cfg(feature = "usb")]
impl From<libusb::Error> for AdapterError {
    fn from(err: libusb::Error) -> AdapterError {
        match err {
            libusb::Error::Access => adapter_err!(AccessDenied, "{}", err),
            libusb::Error::Io => adapter_err!(IoError, "{}", err),
            _ => adapter_err!(UsbError, "{}", err),
        }
    }
}

impl From<ParseIntError> for AdapterError {
    fn from(err: ParseIntError) -> Self {
        adapter_err!(ResponseError, err.to_string())
    }
}

impl From<Utf8Error> for AdapterError {
    fn from(err: Utf8Error) -> Self {
        adapter_err!(ResponseError, err.to_string())
    }
}
