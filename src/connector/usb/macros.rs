//! USB-related macros

/// Write consistent `debug!(...) lines for `UsbConnection`
macro_rules! usb_debug {
    ($device:expr, $msg:expr) => {
        debug!(
            concat!("USB(bus={},addr={}): ", $msg),
            $device.bus_number(),
            $device.address(),
        );
    };
    ($device:expr, $fmt:expr, $($arg:tt)+) => {
        debug!(
            concat!("USB(bus={},addr={}): ", $fmt),
            $device.bus_number(),
            $device.address(),
            $($arg)+
        );
    };
}

/// Create `UsbError`s that include bus and address information
macro_rules! usb_err {
    ($device:expr, $msg:expr) => {
        {
            use anomaly::format_err;
            format_err!(
                UsbError,
                "USB(bus={},addr={}): {}",
                $device.bus_number(),
                $device.address(),
                $msg
            )
        }
    };
    ($device:expr, $fmt:expr, $($arg:tt)+) => {
        {
            use anomaly::format_err;
            format_err!(
                UsbError,
                concat!("USB(bus={},addr={}): ", $fmt),
                $device.bus_number(),
                $device.address(),
                $($arg)+
            )
        }
    };
}
