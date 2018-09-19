/// Write consistent `debug!(...) lines for adapter
macro_rules! http_debug {
    ($adapter:expr, $msg:expr) => {
        debug!("yubihsm-connector({}) {}", $adapter.host, $msg);
    };
    ($adapter:expr, $fmt:expr, $($arg:tt)+) => {
        debug!(concat!("yubihsm-connector({}) ", $fmt), $adapter.host, $($arg)+);
    };
}
