//! Macros used by this crate

/// Create a new error (of a given enum variant) with a formatted message
macro_rules! err {
    ($errtype:ident::$variant:ident, $msg:expr) => {
        $errtype::$variant { description: $msg.to_owned() }
    };
    ($errtype:ident::$variant:ident, $fmt:expr, $($arg:tt)+) => {
        $errtype::$variant { description: format!($fmt, $($arg)+) }
    };
}

/// Create and return an error enum variant with a formatted message
macro_rules! fail {
    ($errtype:ident::$variant:ident, $msg:expr) => {
        return Err(err!($errtype::$variant, $msg).into());
    };
    ($errtype:ident::$variant:ident, $fmt:expr, $($arg:tt)+) => {
        return Err(err!($errtype::$variant, $fmt, $($arg)+).into());
    };
}
