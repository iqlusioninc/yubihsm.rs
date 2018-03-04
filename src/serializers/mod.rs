//! Serde-powered serializers for the `YubiHSM2` wire format

use std::io::Cursor;

use failure::Error;
use serde;

mod de;
mod ser;
mod error;

pub use self::error::SerializationError;

/// Serialize a message into a byte vector
pub fn serialize<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, Error> {
    let mut result = vec![];
    serde::Serialize::serialize(value, &mut ser::Serializer::new(&mut result))?;
    Ok(result)
}

/// Deserialize a byte slice into an instance of `T`
pub fn deserialize<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, Error> {
    let mut deserializer = de::Deserializer::new(Cursor::new(bytes));
    Ok(serde::Deserialize::deserialize(&mut deserializer)?)
}
