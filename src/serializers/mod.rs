use serde;
use std::io::Cursor;

#[macro_use]
mod error;

mod de;
mod ser;

pub use self::error::{SerializationError, SerializationErrorKind};

/// Serialize a message into a byte vector
pub fn serialize<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, SerializationError> {
    let mut result = vec![];
    serde::Serialize::serialize(value, &mut ser::Serializer::new(&mut result))?;
    Ok(result)
}

/// Deserialize a byte slice into an instance of `T`
pub fn deserialize<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, SerializationError> {
    let mut deserializer = de::Deserializer::new(Cursor::new(bytes));
    Ok(serde::Deserialize::deserialize(&mut deserializer)?)
}
