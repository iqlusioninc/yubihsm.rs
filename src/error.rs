//! Error types

use std::{
    backtrace::Backtrace,
    fmt::{self, Debug, Display},
    ops::Deref,
};

/// Create a new error (of a given kind) with a formatted [`Message`]
/// as its source.
///
/// If additional parameters are given, the second is used as a format string,
/// e.g. `format_err!(kind, "something went wrong: {}", &wrongness)`.
macro_rules! format_err {
    ($kind:expr, $msg:expr) => {
        $kind.context($crate::error::Message::new($msg))
    };
    ($kind:expr, $fmt:expr, $($arg:tt)+) => {
        format_err!($kind, &format!($fmt, $($arg)+))
    };
}

/// Create and return an error with a formatted [`Message`].
macro_rules! fail {
    ($kind:expr, $msg:expr) => {
        return Err(format_err!($kind, $msg).into())
    };
    ($kind:expr, $fmt:expr, $($arg:tt)+) => {
        fail!($kind, &format!($fmt, $($arg)+))
    };
}

/// Ensure a condition holds, returning an error if it doesn't (ala `assert`)
macro_rules! ensure {
    ($cond:expr, $kind:expr, $msg:expr) => {
        if !($cond) {
            return Err(format_err!($kind, $msg).into())
        }
    };
    ($cond:expr, $kind:expr, $fmt:expr, $($arg:tt)+) => {
        ensure!($cond, $kind, format!($fmt, $($arg)+))
    };
}

/// Box containing a thread-safe + `'static` error suitable for use as a
/// as an `std::error::Error::source`.
pub type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Error context: stores an error source (as a [`BoxError`]) and backtrace
/// along with an error `Kind`.
#[derive(Debug)]
pub struct Context<Kind>
where
    Kind: Clone + Debug + Display + Into<BoxError>,
{
    /// Kind of error
    kind: Kind,

    /// Source of the error
    source: Option<BoxError>,

    /// Backtrace where error occurred
    backtrace: Option<Backtrace>,
}

impl<Kind> Context<Kind>
where
    Kind: Clone + Debug + Display + Into<BoxError>,
{
    /// Create a new error context
    pub fn new(kind: Kind, source: Option<BoxError>) -> Self {
        Context {
            kind,
            source,
            backtrace: Some(Backtrace::capture()),
        }
    }

    /// Get the kind of error
    pub fn kind(&self) -> &Kind {
        &self.kind
    }

    /// Get the backtrace associated with this error (if available)
    pub fn backtrace(&self) -> Option<&Backtrace> {
        self.backtrace.as_ref()
    }
}

impl<Kind> Display for Context<Kind>
where
    Kind: Clone + Debug + Display + Into<BoxError>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", &self.kind)?;

        if let Some(ref source) = self.source {
            write!(f, ": {source}")?;
        }

        Ok(())
    }
}

impl<Kind> From<Kind> for Context<Kind>
where
    Kind: Clone + Debug + Display + Into<BoxError>,
{
    fn from(kind: Kind) -> Context<Kind> {
        Self::new(kind, None)
    }
}

impl<Kind> std::error::Error for Context<Kind>
where
    Kind: Clone + Debug + Display + Into<BoxError>,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|source| source.as_ref() as &(dyn std::error::Error + 'static))
    }
}

/// Error message type: provide additional context with a string.
///
/// This is generally discouraged whenever possible as it will complicate
/// future I18n support. However, it can be useful for things with
/// language-independent string representations for error contexts.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Message(String);

impl Message {
    /// Create a new error message
    pub fn new(msg: impl ToString) -> Self {
        Message(msg.to_string())
    }
}

impl AsRef<str> for Message {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_ref())
    }
}

impl std::error::Error for Message {}

impl From<String> for Message {
    fn from(string: String) -> Message {
        Message(string)
    }
}

/// Error type
#[derive(Debug)]
pub struct Error<K>(Box<Context<K>>)
where
    K: Clone + Debug + Display + Eq + PartialEq + Into<BoxError>;

impl<K> Deref for Error<K>
where
    K: Clone + Debug + Display + Eq + PartialEq + Into<BoxError>,
{
    type Target = Context<K>;

    fn deref(&self) -> &Context<K> {
        &self.0
    }
}

impl<K> Display for Error<K>
where
    K: Clone + Debug + Display + Eq + PartialEq + Into<BoxError>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl<K> std::error::Error for Error<K>
where
    K: Clone + Debug + Display + Eq + PartialEq + Into<BoxError>,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

impl<K> From<K> for Error<K>
where
    K: Clone + Debug + Display + Eq + PartialEq + Into<BoxError>,
{
    fn from(kind: K) -> Self {
        Context::new(kind, None).into()
    }
}

impl<K> From<Context<K>> for Error<K>
where
    K: Clone + Debug + Display + Eq + PartialEq + Into<BoxError>,
{
    fn from(context: Context<K>) -> Self {
        Error(Box::new(context))
    }
}
