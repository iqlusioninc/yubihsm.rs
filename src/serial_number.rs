use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
use std::{
    fmt::{self, Debug, Display},
    str::{self, FromStr},
};

use connection::{ConnectionError, ConnectionErrorKind::AddrInvalid};

/// Length of a YubiHSM2 serial number
pub const SERIAL_SIZE: usize = 10;

/// YubiHSM serial numbers
#[derive(Copy, Clone, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct SerialNumber([u8; SERIAL_SIZE]);

impl SerialNumber {
    /// Borrow this serial as a string
    pub fn as_str(&self) -> &str {
        str::from_utf8(self.0.as_ref()).unwrap()
    }
}

impl AsRef<str> for SerialNumber {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Debug for SerialNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SerialNumber(\"{}\")", self.as_str())
    }
}

impl Display for SerialNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl FromStr for SerialNumber {
    type Err = ConnectionError;

    fn from_str(s: &str) -> Result<SerialNumber, ConnectionError> {
        if s.len() != SERIAL_SIZE {
            return Err(err!(
                AddrInvalid,
                "invalid serial number length ({}): {}",
                s.len(),
                s
            ));
        }

        for char in s.chars() {
            match char {
                '0'...'9' => (),
                _ => {
                    return Err(err!(
                        AddrInvalid,
                        "invalid character in serial number: {}",
                        s
                    ))
                }
            }
        }

        // We need to use a byte array in order for this to be a `Copy` type
        let mut bytes = [0u8; SERIAL_SIZE];
        bytes.copy_from_slice(s.as_bytes());

        Ok(SerialNumber(bytes))
    }
}

impl Serialize for SerialNumber {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SerialNumber {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::from_str(&String::deserialize(deserializer)?)
            .map_err(|e| D::Error::custom(format!("{}", e)))
    }
}
