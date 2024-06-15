//! YubiHSM 2 device serial numbers

use super::error::{Error, ErrorKind};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Display},
    str::FromStr,
};

/// Length of a YubiHSM 2 serial number in base 10 digits (i.e. characters)
const NUM_DIGITS: usize = 10;

/// YubiHSM serial numbers
#[derive(Copy, Clone, Debug, Deserialize, Eq, Hash, PartialEq, PartialOrd, Ord, Serialize)]
pub struct Number(pub(crate) u32);

impl Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:0width$}", self.0, width = NUM_DIGITS)
    }
}

impl FromStr for Number {
    type Err = Error;

    fn from_str(s: &str) -> Result<Number, Error> {
        if s.len() == NUM_DIGITS {
            let number = s.parse::<u32>().map_err(|_| {
                format_err!(ErrorKind::InvalidData, "error parsing serial number: {}", s)
            })?;

            Ok(Number(number))
        } else {
            fail!(
                ErrorKind::WrongLength,
                "invalid serial number length (expected {}, got {}): '{}'",
                NUM_DIGITS,
                s.len(),
                s
            );
        }
    }
}
