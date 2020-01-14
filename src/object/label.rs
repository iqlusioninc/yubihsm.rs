//! Object labels: descriptions of objects

use super::{Error, ErrorKind};
use anomaly::fail;
use std::{
    fmt::{self, Debug, Display},
    ops::{Deref, DerefMut},
    str::{self, FromStr},
};

/// Number of bytes in a label on an object (fixed-size)
pub const LABEL_SIZE: usize = 40;

/// Placeholder text in event labels contain invalid UTF-8 characters
const INVALID_LABEL_STR_PLACEHOLDER: &str = "[INVALID UTF-8 CHARACTER IN LABEL]";

/// Labels attached to objects
pub struct Label(pub [u8; LABEL_SIZE]);

impl Label {
    /// Create a new label from a slice, returning an error if it's over 40-bytes
    pub fn from_bytes(label_slice: &[u8]) -> Result<Self, Error> {
        if label_slice.len() > LABEL_SIZE {
            fail!(
                ErrorKind::LabelInvalid,
                "label too long: {}-bytes (max {})",
                label_slice.len(),
                LABEL_SIZE
            );
        }

        let mut bytes = [0u8; LABEL_SIZE];
        bytes[..label_slice.len()].copy_from_slice(label_slice);
        Ok(Label(bytes))
    }

    /// Borrow this label as a string ref
    pub fn try_as_str(&self) -> Result<&str, Error> {
        str::from_utf8(match self.0.iter().position(|b| *b == b'\0') {
            Some(pos) => &self.0[..pos],
            None => self.0.as_ref(),
        })
        .map_err(|err| ErrorKind::LabelInvalid.context(err).into())
    }
}

impl AsRef<[u8]> for Label {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Clone for Label {
    fn clone(&self) -> Self {
        Self::from_bytes(self.as_ref()).unwrap()
    }
}

impl Default for Label {
    fn default() -> Self {
        Label([0u8; LABEL_SIZE])
    }
}

impl Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.try_as_str()
                .unwrap_or_else(|_| INVALID_LABEL_STR_PLACEHOLDER)
        )
    }
}

impl Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.try_as_str()
                .unwrap_or_else(|_| INVALID_LABEL_STR_PLACEHOLDER)
        )
    }
}

impl FromStr for Label {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Error> {
        Self::from_bytes(s.as_bytes())
    }
}

impl<'a> From<&'a str> for Label {
    fn from(s: &'a str) -> Self {
        Self::from_str(s).unwrap()
    }
}

impl PartialEq for Label {
    fn eq(&self, other: &Self) -> bool {
        self.0.as_ref() == other.0.as_ref()
    }
}

impl Deref for Label {
    type Target = [u8; LABEL_SIZE];

    fn deref(&self) -> &[u8; LABEL_SIZE] {
        &self.0
    }
}

impl DerefMut for Label {
    fn deref_mut(&mut self) -> &mut [u8; LABEL_SIZE] {
        &mut self.0
    }
}

impl_array_serializers!(Label, LABEL_SIZE);
