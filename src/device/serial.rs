//! YubiHSM 2 device serial numbers

use failure::Error;
use std::{
    fmt::{self, Display},
    str::FromStr,
};

/// Length of a YubiHSM 2 serial number in base 10 digits (i.e. characters)
const DIGITS: usize = 10;

/// YubiHSM serial numbers
#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize)]
pub struct Number(u32);

impl Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:0width$}", self.0, width = DIGITS)
    }
}

impl FromStr for Number {
    type Err = Error;

    fn from_str(s: &str) -> Result<Number, Error> {
        if s.len() == DIGITS {
            Ok(Number(s.parse()?))
        } else {
            bail!(
                "invalid serial number length (expected {}, got {}): '{}'",
                DIGITS,
                s.len(),
                s
            );
        }
    }
}
