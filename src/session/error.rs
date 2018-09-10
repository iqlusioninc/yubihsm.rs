//! Errors that occur during sessions

use adapters::AdapterError;
use error::Error;
use response::ResponseCode;
use securechannel::SecureChannelError;
use serializers::SerializationError;

/// Session errors
pub type SessionError = Error<SessionErrorKind>;

/// Session error kinds
#[derive(Copy, Clone, Eq, PartialEq, Debug, Fail)]
pub enum SessionErrorKind {
    /// Couldn't authenticate session
    #[fail(display = "authentication failed")]
    AuthFail,

    /// Session is closed
    #[fail(display = "session closed")]
    ClosedSessionError,

    /// Couldn't create session
    #[fail(display = "couldn't create session")]
    CreateFailed,

    /// Command not valid
    #[fail(display = "invalid command")]
    CommandInvalid,

    /// Data not valid
    #[fail(display = "invalid data")]
    DataInvalid,

    /// ID illegal
    #[fail(display = "ID illegal")]
    IDIllegal,

    /// HSM audit log is full; can't complete command
    #[fail(display = "HSM audit log full")]
    LogFull,

    /// The requested object was not found
    #[fail(display = "object not found")]
    ObjNotFound,

    /// One Time Password is invalid
    #[fail(display = "OTP invalid")]
    OTPInvalid,

    /// Incorrect permissions to complete operation
    #[fail(display = "access denied: invalid permissions")]
    PermissionInvalid,

    /// Protocol error occurred
    #[fail(display = "protocol error")]
    ProtocolError,

    /// Error response from HSM we can't further specify
    #[fail(display = "HSM error")]
    ResponseError,

    /// Session with HSM failed
    #[fail(display = "session failed")]
    SessionFailed,

    /// Session with HSM invalid
    #[fail(display = "invalid session")]
    SessionInvalid,

    /// HSM exceeded maximum number of sessions (16)
    #[fail(display = "HSM sessions full (max 16)")]
    SessionsFull,

    /// HSM storage failure
    #[fail(display = "HSM storage failure")]
    StorageFailed,

    /// Session with the YubiHSM2 timed out
    #[fail(display = "session timeout")]
    TimeoutError,

    /// Length incorrect for operation
    #[fail(display = "wrong length")]
    WrongLength,
}

impl From<AdapterError> for SessionError {
    fn from(err: AdapterError) -> Self {
        err!(SessionErrorKind::ProtocolError, err.to_string())
    }
}

impl From<SecureChannelError> for SessionError {
    fn from(err: SecureChannelError) -> Self {
        err!(SessionErrorKind::ProtocolError, err.to_string())
    }
}

impl From<SerializationError> for SessionError {
    fn from(err: SerializationError) -> Self {
        err!(SessionErrorKind::ProtocolError, err.to_string())
    }
}

impl From<ResponseCode> for SessionError {
    fn from(code: ResponseCode) -> Self {
        let kind = match code {
            ResponseCode::Success(cmd) => panic!("not an error: ResponseCode::Success({:?})", cmd),
            ResponseCode::DeviceOK => panic!("expected an error response, got DeviceOK"),
            ResponseCode::DeviceInvalidCommand => SessionErrorKind::CommandInvalid,
            ResponseCode::DeviceInvalidData => SessionErrorKind::DataInvalid,
            ResponseCode::DeviceInvalidSession => SessionErrorKind::SessionInvalid,
            ResponseCode::DeviceAuthFail => SessionErrorKind::AuthFail,
            ResponseCode::DeviceSessionsFull => SessionErrorKind::SessionsFull,
            ResponseCode::DeviceSessionFailed => SessionErrorKind::SessionFailed,
            ResponseCode::DeviceStorageFailed => SessionErrorKind::StorageFailed,
            ResponseCode::DeviceWrongLength => SessionErrorKind::WrongLength,
            ResponseCode::DeviceInvalidPermission => SessionErrorKind::PermissionInvalid,
            ResponseCode::DeviceLogFull => SessionErrorKind::LogFull,
            ResponseCode::DeviceObjNotFound => SessionErrorKind::ObjNotFound,
            ResponseCode::DeviceIDIllegal => SessionErrorKind::IDIllegal,
            ResponseCode::DeviceInvalidOTP => SessionErrorKind::OTPInvalid,
            _ => SessionErrorKind::ResponseError,
        };

        Error::new(kind, None)
    }
}
