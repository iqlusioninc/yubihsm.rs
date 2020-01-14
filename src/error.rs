//! Error types

use anomaly::{BoxError, Context};
use std::{
    fmt::{self, Debug, Display},
    ops::Deref,
};

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
