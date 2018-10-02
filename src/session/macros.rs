/// Write consistent `debug!(...) lines for sessions
macro_rules! session_debug {
    ($session:expr, $msg:expr) => {
        debug!("session={} {}", $session.id().to_u8(), $msg);
    };
    ($session:expr, $fmt:expr, $($arg:tt)+) => {
        debug!(concat!("session={} ", $fmt), $session.id().to_u8(), $($arg)+);
    };
}

/// Write consistent `error!(...) lines for sessions
macro_rules! session_error {
    ($session:expr, $msg:expr) => {
        error!("session={} {}", $session.id().to_u8(), $msg);
    };
    ($session:expr, $fmt:expr, $($arg:tt)+) => {
        error!(concat!("session={} ", $fmt), $session.id().to_u8(), $($arg)+);
    };
}
