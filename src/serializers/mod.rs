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

/// Implement serde serializers/deserializers for array newtypes
macro_rules! impl_array_serializers {
    ($ty:ident, $size:expr) => {
        impl ::serde::Serialize for $ty {
            fn serialize<S: ::serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                self.0.serialize(serializer)
            }
        }

        impl<'de> ::serde::Deserialize<'de> for $ty {
            fn deserialize<D: ::serde::Deserializer<'de>>(
                deserializer: D,
            ) -> Result<$ty, D::Error> {
                struct ArrayVisitor;

                impl<'de> ::serde::de::Visitor<'de> for ArrayVisitor {
                    type Value = $ty;

                    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                        write!(formatter, "{}-byte string of arbitrary bytes", $size)
                    }

                    fn visit_seq<S: ::serde::de::SeqAccess<'de>>(
                        self,
                        mut seq: S,
                    ) -> Result<$ty, S::Error> {
                        let mut result = [0; $size];

                        for elem in result.iter_mut().take($size) {
                            match seq.next_element()? {
                                Some(val) => *elem = val,
                                None => return Err(::serde::de::Error::custom("end of stream")),
                            };
                        }

                        Ok($ty(result))
                    }
                }

                deserializer.deserialize_seq(ArrayVisitor)
            }
        }
    };
}
