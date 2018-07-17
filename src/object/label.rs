use failure::Error;
use std::fmt;
use std::ops::{Deref, DerefMut};

/// Number of bytes in a label on an object (fixed-size)
pub const LABEL_SIZE: usize = 40;

/// Labels attached to objects
pub struct Label(pub [u8; LABEL_SIZE]);

impl Label {
    /// Create a new label from a slice, returning an error if it's over 40-bytes
    pub fn new(label_slice: &[u8]) -> Result<Self, Error> {
        if label_slice.len() > LABEL_SIZE {
            bail!(
                "label too long: {}-bytes (max {})",
                label_slice.len(),
                LABEL_SIZE
            );
        }

        let mut bytes = [0u8; LABEL_SIZE];
        bytes[..label_slice.len()].copy_from_slice(label_slice);
        Ok(Label(bytes))
    }

    /// Create a string representation of this label
    pub fn to_string(&self) -> Result<String, Error> {
        let slice = match self.0.iter().position(|b| *b == b'\0') {
            Some(pos) => &self.0.as_ref()[..pos],
            None => self.0.as_ref(),
        };

        Ok(String::from_utf8(slice.into())?)
    }
}

impl AsRef<[u8]> for Label {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Clone for Label {
    fn clone(&self) -> Self {
        Self::new(self.as_ref()).unwrap()
    }
}

impl fmt::Debug for Label {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let string = self
            .to_string()
            .unwrap_or_else(|_| "[INVALID UTF-8 CHARACTER IN LABEL]".to_owned());

        write!(f, "{:?}", string)
    }
}

impl<'a> From<&'a str> for Label {
    fn from(string: &'a str) -> Self {
        Self::new(string.as_bytes()).unwrap()
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
