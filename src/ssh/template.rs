/// SSH certificate template
// TODO(tarcieri): parse and validate these to provide better errors
#[derive(Clone, Debug)]
pub struct Template(Vec<u8>);

impl Template {
    /// Create an SSH certificate template from serialized bytes
    pub fn from_bytes<B>(bytes: B) -> Self
    where
        B: Into<Vec<u8>>,
    {
        Template(bytes.into())
    }

    /// Borrow this SSH certificate template as a byte slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8]> for Template {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}
