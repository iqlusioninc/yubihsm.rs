//! Error types for `yubihsm-connector`

use failure::Fail;
#[cfg(feature = "http")]
use gaunt;
#[cfg(feature = "usb")]
use libusb;
use std::{fmt, io, num::ParseIntError, str::Utf8Error};

/// `yubihsm-connector` related errors
pub type Error = crate::Error<ErrorKind>;

/// `yubihsm-connector` related error kinds
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum ErrorKind {
    /// Address provided was not valid
    #[fail(display = "invalid address")]
    AddrInvalid,

    /// Access denied
    #[fail(display = "access denied")]
    AccessDenied,

    /// YubiHSM 2 is busy (in use by another client / process)
    #[fail(display = "device already in use")]
    DeviceBusyError,

    /// Couldn't connect to the YubiHSM 2
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

impl From<fmt::Error> for Error {
    fn from(err: fmt::Error) -> Self {
        err!(ErrorKind::IoError, err.to_string())
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Self {
        err!(ErrorKind::IoError, err.to_string())
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

        err!(kind, err)
    }
}

#[cfg(feature = "usb")]
impl From<libusb::Error> for Error {
    fn from(err: libusb::Error) -> Error {
        match err {
            libusb::Error::Access => err!(ErrorKind::AccessDenied, "{}", err),
            libusb::Error::Io => err!(ErrorKind::IoError, "{}", err),
            libusb::Error::Pipe => err!(ErrorKind::UsbError, "lost connection to USB device"),
            _ => err!(ErrorKind::UsbError, "{}", err),
        }
    }
}

impl From<ParseIntError> for Error {
    fn from(err: ParseIntError) -> Self {
        err!(ErrorKind::ResponseError, err.to_string())
    }
}

impl From<Utf8Error> for Error {
    fn from(err: Utf8Error) -> Self {
        err!(ErrorKind::ResponseError, err.to_string())
    }
}
