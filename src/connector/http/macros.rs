/// Write consistent `debug!(...) lines for connection
macro_rules! http_debug {
    ($connection:expr, $msg:expr) => {
        debug!("yubihsm-connector({}) {}", $connection.host, $msg);
    };
    ($connection:expr, $fmt:expr, $($arg:tt)+) => {
        debug!(concat!("yubihsm-connector({}) ", $fmt), $connection.host, $($arg)+);
    };
}
