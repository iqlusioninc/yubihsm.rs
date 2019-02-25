//! YubiHSM 2 device serial numbers

use failure::Error;
use std::{
    fmt::{self, Display},
    str::FromStr,
};

/// Length of a YubiHSM 2 serial number
pub const SERIAL_DIGITS: usize = 10;

/// YubiHSM serial numbers
#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize)]
pub struct SerialNumber(u32);

impl Display for SerialNumber {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:0width$}", self.0, width = SERIAL_DIGITS)
    }
}

impl FromStr for SerialNumber {
    type Err = Error;

    fn from_str(s: &str) -> Result<SerialNumber, Error> {
        if s.len() == SERIAL_DIGITS {
            Ok(SerialNumber(s.parse()?))
        } else {
            bail!(
                "invalid serial number length (expected {}, got {}): '{}'",
                SERIAL_DIGITS,
                s.len(),
                s
            );
        }
    }
}
